#define main cadical_fresh_multihorizon_embedded_main
#include "cadical_fresh_multihorizon.cpp"
#undef main

#include "cadical_tracer_v3.hpp"

#include <limits>
#include <unordered_map>
#include <unordered_set>

namespace {

constexpr int kMaximumLearnedClauseSize = 64;

struct IdentityLearner final : CaDiCaL::Learner {
  bool learning(int size) override {
    if (size < 0) throw std::runtime_error("negative learned clause size");
    ++offered;
    accepting = size <= kMaximumLearnedClauseSize;
    current.clear();
    expected_size = size;
    if (!accepting) ++rejected_large;
    return accepting;
  }

  void learn(int literal) override {
    if (!accepting)
      throw std::runtime_error("learn callback without accepted clause");
    if (literal) {
      current.push_back(literal);
      return;
    }
    if (static_cast<int>(current.size()) != expected_size)
      throw std::runtime_error("learned clause length differs from callback");
    std::sort(current.begin(), current.end(), [](int left, int right) {
      const int left_variable = std::abs(left);
      const int right_variable = std::abs(right);
      if (left_variable != right_variable) return left_variable < right_variable;
      return left < right;
    });
    if (std::adjacent_find(current.begin(), current.end()) != current.end())
      throw std::runtime_error("learned clause contains duplicate literals");
    for (std::size_t index = 1; index < current.size(); ++index)
      if (current[index] == -current[index - 1])
        throw std::runtime_error("learned clause is tautological");
    clauses.push_back(current);
    accepting = false;
    expected_size = -1;
  }

  std::vector<std::vector<int>> clauses;
  std::vector<int> current;
  int64_t offered = 0;
  int64_t rejected_large = 0;
  int expected_size = -1;
  bool accepting = false;
};

void print_clause_slice(const std::vector<std::vector<int>> &clauses,
                        std::size_t begin) {
  std::cout << '[';
  for (std::size_t index = begin; index < clauses.size(); ++index) {
    if (index != begin) std::cout << ',';
    print_array(clauses[index]);
  }
  std::cout << ']';
}

void print_size_slice(const std::vector<std::vector<int>> &clauses,
                      std::size_t begin) {
  std::cout << '[';
  for (std::size_t index = begin; index < clauses.size(); ++index) {
    if (index != begin) std::cout << ',';
    std::cout << clauses[index].size();
  }
  std::cout << ']';
}

int64_t literal_count(const std::vector<std::vector<int>> &clauses,
                      std::size_t begin) {
  int64_t result = 0;
  for (std::size_t index = begin; index < clauses.size(); ++index)
    result += static_cast<int64_t>(clauses[index].size());
  return result;
}

std::unique_ptr<CaDiCaL::Solver> build_identity_base_solver(
    const ParsedCnf &cnf, const Arguments &arguments) {
  auto solver = std::make_unique<CaDiCaL::Solver>();
  if (!solver->set("quiet", 1) || !solver->set("reverse", 1) ||
      !solver->set("factorcheck", 0) || !solver->set("factor", 0))
    throw std::runtime_error("required clause identity options are unavailable");
  solver->resize(cnf.variables);
  for (const int literal : cnf.literals) solver->add(literal);
  std::set<int> frozen;
  for (const int literal : arguments.assumption_one_literals)
    frozen.insert(std::abs(literal));
  for (const int literal : arguments.model_one_literals)
    frozen.insert(std::abs(literal));
  for (const int variable : frozen) {
    if (variable > cnf.variables)
      throw std::runtime_error("mapped variable exceeds CNF header");
    solver->freeze(variable);
  }
  return solver;
}

struct ProofNode {
  int depth = 0;
  int clause_size = 0;
  uint8_t assumption_ancestry_mask = 0;
  bool redundant = false;
};

constexpr uint64_t kFnvOffset = 1469598103934665603ULL;
constexpr uint64_t kFnvPrime = 1099511628211ULL;

uint64_t hash_word(uint64_t hash, uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8) {
    hash ^= (value >> shift) & 0xffU;
    hash *= kFnvPrime;
  }
  return hash;
}

uint64_t clause_hash(const std::vector<int> &clause) {
  uint64_t result = hash_word(kFnvOffset, clause.size());
  for (const int literal : clause)
    result = hash_word(result, static_cast<uint32_t>(literal));
  return result;
}

struct ProofMoment {
  uint64_t count = 0;
  long double sum = 0.0L;
  long double sum_squares = 0.0L;
  uint64_t maximum = 0;

  void add(uint64_t value) {
    ++count;
    sum += value;
    sum_squares += static_cast<long double>(value) * value;
    maximum = std::max(maximum, value);
  }
};

struct ProofAggregate {
  uint64_t events = 0;
  uint64_t witness_events = 0;
  uint64_t direct_assumption_touch_events = 0;
  uint64_t ancestry_assumption_touch_events = 0;
  uint64_t direct_assumption_same_literals = 0;
  uint64_t direct_assumption_opposite_literals = 0;
  uint64_t parent_assumption_ancestry_edges = 0;
  uint64_t recurrent_clause_events = 0;
  uint8_t direct_assumption_position_union = 0;
  uint8_t ancestry_assumption_position_union = 0;
  ProofMoment clause_size;
  ProofMoment antecedent_count;
  ProofMoment proof_depth;
  ProofMoment original_parent_count;
  ProofMoment derived_parent_count;
  ProofMoment missing_parent_count;
  ProofMoment parent_clause_size;
  ProofMoment parent_depth;
};

struct StageProofStats {
  ProofAggregate all;
  ProofAggregate redundant;
  ProofAggregate irredundant;
  std::unordered_map<int64_t, uint32_t> parent_use_all;
  std::unordered_map<int64_t, uint32_t> parent_use_redundant;
  uint64_t event_stream_hash = kFnvOffset;
};

void update_aggregate(ProofAggregate &aggregate, const std::vector<int> &clause,
                      const std::vector<int64_t> &antecedents, int depth,
                      int original_parents, int derived_parents,
                      int missing_parents, uint64_t parent_clause_size_sum,
                      uint64_t parent_clause_size_sum_squares,
                      uint64_t parent_clause_size_max, uint64_t parent_depth_sum,
                      uint64_t parent_depth_sum_squares, uint64_t parent_depth_max,
                      uint64_t parent_known_count,
                      uint8_t direct_mask, uint8_t ancestry_mask,
                      uint64_t same_literals, uint64_t opposite_literals,
                      uint64_t parent_ancestry_edges, bool witness,
                      bool recurrent) {
  ++aggregate.events;
  aggregate.clause_size.add(clause.size());
  aggregate.antecedent_count.add(antecedents.size());
  aggregate.proof_depth.add(depth);
  aggregate.original_parent_count.add(original_parents);
  aggregate.derived_parent_count.add(derived_parents);
  aggregate.missing_parent_count.add(missing_parents);
  if (parent_known_count) {
    aggregate.parent_clause_size.count += parent_known_count;
    aggregate.parent_clause_size.sum += parent_clause_size_sum;
    aggregate.parent_clause_size.sum_squares += parent_clause_size_sum_squares;
    aggregate.parent_clause_size.maximum = std::max(
        aggregate.parent_clause_size.maximum, parent_clause_size_max);
    aggregate.parent_depth.count += parent_known_count;
    aggregate.parent_depth.sum += parent_depth_sum;
    aggregate.parent_depth.sum_squares += parent_depth_sum_squares;
    aggregate.parent_depth.maximum = std::max(
        aggregate.parent_depth.maximum, parent_depth_max);
  }
  aggregate.witness_events += witness;
  aggregate.direct_assumption_touch_events += direct_mask != 0;
  aggregate.ancestry_assumption_touch_events += ancestry_mask != 0;
  aggregate.direct_assumption_same_literals += same_literals;
  aggregate.direct_assumption_opposite_literals += opposite_literals;
  aggregate.parent_assumption_ancestry_edges += parent_ancestry_edges;
  aggregate.recurrent_clause_events += recurrent;
  aggregate.direct_assumption_position_union |= direct_mask;
  aggregate.ancestry_assumption_position_union |= ancestry_mask;
}

struct AntecedentTracer final : CaDiCaL::Tracer {
  void start_stage(const std::vector<int> &candidate_assumptions) {
    if (stage_active || candidate_assumptions.size() != 8)
      throw std::runtime_error("invalid proof-stage start");
    stage = StageProofStats{};
    assumption_literal_by_variable.clear();
    assumption_position_by_variable.clear();
    for (std::size_t position = 0; position < candidate_assumptions.size(); ++position) {
      const int literal = candidate_assumptions[position];
      assumption_literal_by_variable.emplace(std::abs(literal), literal);
      assumption_position_by_variable.emplace(std::abs(literal), position);
    }
    if (assumption_literal_by_variable.size() != 8)
      throw std::runtime_error("proof-stage assumptions are not distinct");
    stage_active = true;
  }

  const StageProofStats &finish_stage() {
    if (!stage_active) throw std::runtime_error("proof stage is not active");
    stage_active = false;
    return stage;
  }

  void begin_proof(int64_t id) override {
    if (id <= 0) throw std::runtime_error("invalid first derived proof id");
    begin_ids.push_back(id);
  }

  void add_original_clause(int64_t id, bool, const std::vector<int> &,
                           bool restored) override {
    if (id <= 0) throw std::runtime_error("invalid original proof id");
    if (!original_ids.insert(id).second && !restored)
      throw std::runtime_error("duplicate non-restored original proof id");
    if (restored) ++restored_originals;
  }

  void add_derived_clause(int64_t id, bool redundant, int witness,
                          const std::vector<int> &clause,
                          const std::vector<int64_t> &antecedents) override {
    if (id <= 0 || derived_nodes.count(id))
      throw std::runtime_error("invalid or duplicate derived proof id");
    int maximum_parent_depth = -1;
    int original_parents = 0;
    int derived_parents = 0;
    int missing_parents = 0;
    uint64_t parent_clause_size_sum = 0;
    uint64_t parent_clause_size_sum_squares = 0;
    uint64_t parent_clause_size_max = 0;
    uint64_t parent_depth_sum = 0;
    uint64_t parent_depth_sum_squares = 0;
    uint64_t parent_depth_max = 0;
    uint64_t parent_known_count = 0;
    uint64_t parent_ancestry_edges = 0;
    uint8_t ancestry_mask = 0;
    for (const int64_t parent : antecedents) {
      if (parent <= 0)
        throw std::runtime_error("non-positive proof antecedent id");
      const auto derived = derived_nodes.find(parent);
      if (derived != derived_nodes.end()) {
        ++derived_parents;
        maximum_parent_depth = std::max(maximum_parent_depth, derived->second.depth);
        parent_clause_size_sum += derived->second.clause_size;
        parent_clause_size_sum_squares +=
            static_cast<uint64_t>(derived->second.clause_size) *
            derived->second.clause_size;
        parent_clause_size_max = std::max<uint64_t>(
            parent_clause_size_max, derived->second.clause_size);
        parent_depth_sum += derived->second.depth;
        parent_depth_sum_squares +=
            static_cast<uint64_t>(derived->second.depth) * derived->second.depth;
        parent_depth_max = std::max<uint64_t>(parent_depth_max,
                                              derived->second.depth);
        ++parent_known_count;
        ancestry_mask |= derived->second.assumption_ancestry_mask;
        parent_ancestry_edges += derived->second.assumption_ancestry_mask != 0;
      } else if (original_ids.count(parent)) {
        ++original_parents;
        maximum_parent_depth = std::max(maximum_parent_depth, 0);
        ++parent_known_count;
      } else {
        ++missing_parents;
      }
    }
    const int depth = maximum_parent_depth < 0 ? 1 : maximum_parent_depth + 1;
    uint8_t direct_mask = 0;
    uint64_t same_literals = 0;
    uint64_t opposite_literals = 0;
    for (const int literal : clause) {
      const auto position = assumption_position_by_variable.find(std::abs(literal));
      if (position == assumption_position_by_variable.end()) continue;
      direct_mask |= static_cast<uint8_t>(1U << position->second);
      if (assumption_literal_by_variable.at(std::abs(literal)) == literal)
        ++same_literals;
      else
        ++opposite_literals;
    }
    ancestry_mask |= direct_mask;
    const uint64_t fingerprint = clause_hash(clause);
    const bool recurrent = !seen_clause_hashes.insert(fingerprint).second;
    derived_nodes.emplace(
        id, ProofNode{depth, static_cast<int>(clause.size()), ancestry_mask, redundant});
    ++derived_count;
    antecedent_count += antecedents.size();
    missing_antecedent_count += missing_parents;
    if (stage_active) {
      update_aggregate(stage.all, clause, antecedents, depth, original_parents,
                       derived_parents, missing_parents, parent_clause_size_sum,
                       parent_clause_size_sum_squares, parent_clause_size_max,
                       parent_depth_sum, parent_depth_sum_squares,
                       parent_depth_max, parent_known_count, direct_mask,
                       ancestry_mask, same_literals, opposite_literals,
                       parent_ancestry_edges, witness != 0, recurrent);
      ProofAggregate &typed = redundant ? stage.redundant : stage.irredundant;
      update_aggregate(typed, clause, antecedents, depth, original_parents,
                       derived_parents, missing_parents, parent_clause_size_sum,
                       parent_clause_size_sum_squares, parent_clause_size_max,
                       parent_depth_sum, parent_depth_sum_squares,
                       parent_depth_max, parent_known_count, direct_mask,
                       ancestry_mask, same_literals, opposite_literals,
                       parent_ancestry_edges, witness != 0, recurrent);
      for (const int64_t parent : antecedents) {
        ++stage.parent_use_all[parent];
        if (redundant) ++stage.parent_use_redundant[parent];
      }
      stage.event_stream_hash = hash_word(stage.event_stream_hash, id);
      stage.event_stream_hash = hash_word(stage.event_stream_hash, redundant);
      stage.event_stream_hash = hash_word(stage.event_stream_hash,
                                          static_cast<uint32_t>(witness));
      stage.event_stream_hash = hash_word(stage.event_stream_hash, fingerprint);
      for (const int64_t parent : antecedents)
        stage.event_stream_hash = hash_word(stage.event_stream_hash, parent);
    }
  }

  void delete_clause(int64_t id, bool, const std::vector<int> &) override {
    if (id <= 0) throw std::runtime_error("invalid deleted proof id");
    ++deletions;
  }

  void demote_clause(uint64_t id, const std::vector<int> &) override {
    if (!id) throw std::runtime_error("invalid demoted proof id");
    ++demotions;
  }

  void weaken_minus(int64_t id, const std::vector<int> &) override {
    if (id <= 0) throw std::runtime_error("invalid weakened proof id");
    ++weakenings;
  }

  void strengthen(int64_t id) override {
    if (id <= 0) throw std::runtime_error("invalid strengthened proof id");
    ++strengthenings;
  }

  void report_status(int status, int64_t id) override {
    statuses.push_back({status, id});
  }

  void finalize_clause(int64_t id, const std::vector<int> &) override {
    if (id <= 0) throw std::runtime_error("invalid finalized proof id");
    ++finalizations;
  }

  void solve_query() override { ++solve_queries; }
  void add_assumption(int literal) override {
    if (!literal) throw std::runtime_error("zero proof assumption");
    assumptions.push_back(literal);
  }
  void add_constraint(const std::vector<int> &) override { ++constraints; }
  void reset_assumptions() override { ++assumption_resets; }

  void add_assumption_clause(
      int64_t id, const std::vector<int> &clause,
      const std::vector<int64_t> &antecedents) override {
    if (id <= 0) throw std::runtime_error("invalid assumption-clause id");
    assumption_clause_ids.push_back(id);
    assumption_clause_literal_counts.push_back(clause.size());
    assumption_clause_antecedent_counts.push_back(antecedents.size());
  }

  void conclude_unsat(CaDiCaL::ConclusionType,
                      const std::vector<int64_t> &) override {
    ++unsat_conclusions;
  }
  void conclude_sat(const std::vector<int> &) override { ++sat_conclusions; }
  void conclude_unknown(const std::vector<int> &) override {
    ++unknown_conclusions;
  }
  void notify_equivalence(int left, int right) override {
    if (!left || !right) throw std::runtime_error("zero proof equivalence");
    ++equivalences;
  }

  std::unordered_set<int64_t> original_ids;
  std::unordered_map<int64_t, ProofNode> derived_nodes;
  std::unordered_set<uint64_t> seen_clause_hashes;
  std::unordered_map<int, int> assumption_literal_by_variable;
  std::unordered_map<int, std::size_t> assumption_position_by_variable;
  StageProofStats stage;
  bool stage_active = false;
  uint64_t derived_count = 0;
  uint64_t antecedent_count = 0;
  uint64_t missing_antecedent_count = 0;
  std::vector<int64_t> begin_ids;
  std::vector<int> assumptions;
  std::vector<std::pair<int, int64_t>> statuses;
  std::vector<int64_t> assumption_clause_ids;
  std::vector<std::size_t> assumption_clause_literal_counts;
  std::vector<std::size_t> assumption_clause_antecedent_counts;
  int64_t restored_originals = 0;
  int64_t deletions = 0;
  int64_t demotions = 0;
  int64_t weakenings = 0;
  int64_t strengthenings = 0;
  int64_t finalizations = 0;
  int64_t solve_queries = 0;
  int64_t constraints = 0;
  int64_t assumption_resets = 0;
  int64_t unsat_conclusions = 0;
  int64_t sat_conclusions = 0;
  int64_t unknown_conclusions = 0;
  int64_t equivalences = 0;
};

void print_moment(const ProofMoment &moment) {
  std::cout << "{\"count\":" << moment.count
            << ",\"sum\":" << static_cast<double>(moment.sum)
            << ",\"sum_squares\":" << static_cast<double>(moment.sum_squares)
            << ",\"maximum\":" << moment.maximum << '}';
}

void print_aggregate(const ProofAggregate &aggregate) {
  std::cout << "{\"events\":" << aggregate.events
            << ",\"witness_events\":" << aggregate.witness_events
            << ",\"direct_assumption_touch_events\":"
            << aggregate.direct_assumption_touch_events
            << ",\"ancestry_assumption_touch_events\":"
            << aggregate.ancestry_assumption_touch_events
            << ",\"direct_assumption_same_literals\":"
            << aggregate.direct_assumption_same_literals
            << ",\"direct_assumption_opposite_literals\":"
            << aggregate.direct_assumption_opposite_literals
            << ",\"parent_assumption_ancestry_edges\":"
            << aggregate.parent_assumption_ancestry_edges
            << ",\"recurrent_clause_events\":"
            << aggregate.recurrent_clause_events
            << ",\"direct_assumption_position_union\":"
            << static_cast<unsigned>(aggregate.direct_assumption_position_union)
            << ",\"ancestry_assumption_position_union\":"
            << static_cast<unsigned>(aggregate.ancestry_assumption_position_union)
            << ",\"clause_size\":";
  print_moment(aggregate.clause_size);
  std::cout << ",\"antecedent_count\":";
  print_moment(aggregate.antecedent_count);
  std::cout << ",\"proof_depth\":";
  print_moment(aggregate.proof_depth);
  std::cout << ",\"original_parent_count\":";
  print_moment(aggregate.original_parent_count);
  std::cout << ",\"derived_parent_count\":";
  print_moment(aggregate.derived_parent_count);
  std::cout << ",\"missing_parent_count\":";
  print_moment(aggregate.missing_parent_count);
  std::cout << ",\"parent_clause_size\":";
  print_moment(aggregate.parent_clause_size);
  std::cout << ",\"parent_depth\":";
  print_moment(aggregate.parent_depth);
  std::cout << '}';
}

void print_parent_reuse(const std::unordered_map<int64_t, uint32_t> &use) {
  uint64_t references = 0;
  uint64_t maximum = 0;
  long double entropy = 0.0L;
  for (const auto &[id, count] : use) {
    (void) id;
    references += count;
    maximum = std::max<uint64_t>(maximum, count);
  }
  if (references)
    for (const auto &[id, count] : use) {
      (void) id;
      const long double probability =
          static_cast<long double>(count) / references;
      entropy -= probability * std::log2(probability);
    }
  const long double normalized =
      use.size() > 1 ? entropy / std::log2(static_cast<long double>(use.size()))
                     : 0.0L;
  std::cout << "{\"references\":" << references
            << ",\"unique_parents\":" << use.size()
            << ",\"reused_references\":" << references - use.size()
            << ",\"maximum_parent_use\":" << maximum
            << ",\"entropy_bits\":" << static_cast<double>(entropy)
            << ",\"normalized_entropy\":" << static_cast<double>(normalized)
            << '}';
}

void print_stage_proof_stats(const StageProofStats &stats) {
  std::cout << "{\"all\":";
  print_aggregate(stats.all);
  std::cout << ",\"redundant\":";
  print_aggregate(stats.redundant);
  std::cout << ",\"irredundant\":";
  print_aggregate(stats.irredundant);
  std::cout << ",\"parent_reuse_all\":";
  print_parent_reuse(stats.parent_use_all);
  std::cout << ",\"parent_reuse_redundant\":";
  print_parent_reuse(stats.parent_use_redundant);
  std::ostringstream digest;
  digest << std::hex << std::setw(16) << std::setfill('0')
         << stats.event_stream_hash;
  std::cout << ",\"event_stream_fnv1a64\":\"" << digest.str() << "\"}";
}

std::unique_ptr<CaDiCaL::Solver> copy_traced_solver(
    const CaDiCaL::Solver &base, AntecedentTracer &tracer) {
  auto solver = std::make_unique<CaDiCaL::Solver>();
  solver->connect_proof_tracer(&tracer, true, false);
  base.copy(*solver);
  return solver;
}

}  // namespace

int main(int argc, char **argv) {
  try {
    const Arguments arguments = parse_arguments(argc, argv);
    const ParsedCnf cnf = parse_dimacs(arguments.cnf);
    const std::unique_ptr<CaDiCaL::Solver> base =
        build_identity_base_solver(cnf, arguments);
    int sat_cells = 0;
    int unsat_cells = 0;
    int unknown_cells = 0;
    int stages_emitted = 0;
    int64_t derived_total = 0;
    int64_t antecedent_total = 0;
    int64_t missing_antecedent_total = 0;
    int64_t accepted_clauses_total = 0;
    int64_t offered_clauses_total = 0;
    int64_t rejected_large_total = 0;
    bool base_snapshot_identical = true;
    bool have_reference_snapshot = false;
    Snapshot reference_snapshot;

    for (std::size_t cell_index = 0;
         cell_index < arguments.cell_order.size(); ++cell_index) {
      const std::string &prefix8 = arguments.cell_order[cell_index];
      std::vector<int> assumptions;
      for (std::size_t bit = 0; bit < 8; ++bit) {
        const int one_literal = arguments.assumption_one_literals[bit];
        assumptions.push_back(prefix8[bit] == '1' ? one_literal : -one_literal);
      }

      AntecedentTracer tracer;
      std::unique_ptr<CaDiCaL::Solver> solver = copy_traced_solver(*base, tracer);
      const Snapshot cell_before = snapshot(*solver);
      if (!have_reference_snapshot) {
        reference_snapshot = cell_before;
        have_reference_snapshot = true;
      } else if (!(cell_before == reference_snapshot)) {
        base_snapshot_identical = false;
      }
      IdentityLearner learner;
      solver->connect_learner(&learner);

      int final_status = 0;
      int terminal_stage_index = -1;
      int stages_run = 0;
      for (std::size_t stage_index = 0;
           stage_index < arguments.conflict_horizons.size(); ++stage_index) {
        const int horizon = arguments.conflict_horizons[stage_index];
        const int previous_horizon =
            stage_index == 0 ? 0 : arguments.conflict_horizons[stage_index - 1];
        const int conflict_increment = horizon - previous_horizon;
        const Snapshot stage_before = snapshot(*solver);
        const std::size_t accepted_before = learner.clauses.size();
        const int64_t offered_before = learner.offered;
        const int64_t rejected_before = learner.rejected_large;
        const std::size_t assumptions_before = tracer.assumptions.size();
        const int64_t deletions_before = tracer.deletions;
        const int64_t demotions_before = tracer.demotions;
        const int64_t weakenings_before = tracer.weakenings;
        const int64_t strengthenings_before = tracer.strengthenings;
        const int64_t finalizations_before = tracer.finalizations;
        const int64_t resets_before = tracer.assumption_resets;
        const int64_t queries_before = tracer.solve_queries;
        tracer.start_stage(assumptions);
        for (const int literal : assumptions) solver->assume(literal);
        if (!solver->limit("conflicts", conflict_increment))
          throw std::runtime_error("CaDiCaL conflict limit is unavailable");
        DeadlineTerminator terminator(arguments.watchdog_seconds);
        solver->connect_terminator(&terminator);
        const auto started = Clock::now();
        const int status = solver->solve();
        const double elapsed =
            std::chrono::duration<double>(Clock::now() - started).count();
        solver->disconnect_terminator();
        if (terminator.fired) throw std::runtime_error("stage watchdog fired");
        const Snapshot stage_after = snapshot(*solver);
        const auto stage_delta = difference(stage_after.metrics, stage_before.metrics);
        const auto cell_delta = difference(stage_after.metrics, cell_before.metrics);
        const bool terminal = status == 10 || status == 20;
        const bool conflict_budget_exhausted =
            status == 0 && stage_delta[0] >= conflict_increment;
        std::vector<int> model_bits;
        if (status == 10)
          for (const int literal : arguments.model_one_literals)
            model_bits.push_back(
                literal_is_true_in_model(*solver, literal) ? 1 : 0);
        std::vector<int> failed_assumptions;
        if (status == 20)
          for (const int literal : assumptions)
            if (solver->failed(literal)) failed_assumptions.push_back(literal);

        const int64_t stage_accepted =
            static_cast<int64_t>(learner.clauses.size() - accepted_before);
        const int64_t stage_offered = learner.offered - offered_before;
        const int64_t stage_rejected = learner.rejected_large - rejected_before;
        if (stage_offered != stage_accepted + stage_rejected)
          throw std::runtime_error("learned clause accounting differs");
        const StageProofStats &proof = tracer.finish_stage();
        const uint64_t stage_antecedents =
            static_cast<uint64_t>(proof.all.antecedent_count.sum);
        const uint64_t stage_missing =
            static_cast<uint64_t>(proof.all.missing_parent_count.sum);

        std::cout << "FRESH_CA_STAGE {\"mode\":\"" << arguments.mode
                  << "\",\"prefix8\":\"" << prefix8
                  << "\",\"cell_index\":" << cell_index
                  << ",\"stage_index\":" << stage_index
                  << ",\"horizon\":" << horizon
                  << ",\"conflict_increment\":" << conflict_increment
                  << ",\"status\":\"" << status_name(status)
                  << "\",\"returncode\":" << status
                  << ",\"terminal\":" << (terminal ? "true" : "false")
                  << ",\"conflict_budget_exhausted\":"
                  << (conflict_budget_exhausted ? "true" : "false")
                  << ",\"watchdog_fired\":false,\"watchdog_seconds\":"
                  << std::setprecision(17) << arguments.watchdog_seconds
                  << ",\"elapsed_seconds\":" << elapsed
                  << ",\"assumptions\":";
        print_array(assumptions);
        std::cout << ",\"failed_assumptions\":";
        print_array(failed_assumptions);
        std::cout << ",\"model_bits_bit0_through_bit19\":";
        print_array(model_bits);
        std::cout << ",\"metric_names\":[\"conflicts\",\"decisions\",\"search_propagations\"]"
                  << ",\"metrics_stage_before\":";
        print_array(stage_before.metrics);
        std::cout << ",\"metrics_stage_after\":";
        print_array(stage_after.metrics);
        std::cout << ",\"metrics_stage_delta\":";
        print_array(stage_delta);
        std::cout << ",\"metrics_cell_before\":";
        print_array(cell_before.metrics);
        std::cout << ",\"metrics_cell_cumulative_delta\":";
        print_array(cell_delta);
        print_state_fields(stage_before, stage_after);
        std::cout << ",\"learned_clause_maximum_size\":"
                  << kMaximumLearnedClauseSize
                  << ",\"learned_clause_offered_stage\":" << stage_offered
                  << ",\"learned_clause_accepted_stage\":" << stage_accepted
                  << ",\"learned_clause_rejected_large_stage\":"
                  << stage_rejected
                  << ",\"learned_clause_accepted_cumulative\":"
                  << learner.clauses.size()
                  << ",\"learned_literal_count_stage\":"
                  << literal_count(learner.clauses, accepted_before)
                  << ",\"learned_clause_lengths_stage\":";
        print_size_slice(learner.clauses, accepted_before);
        std::cout << ",\"learned_clauses_stage\":";
        print_clause_slice(learner.clauses, accepted_before);
        std::cout << ",\"proof_original_clause_count\":"
                  << tracer.original_ids.size()
                  << ",\"proof_derived_count_stage\":"
                  << proof.all.events
                  << ",\"proof_derived_count_cumulative\":"
                  << tracer.derived_count
                  << ",\"proof_antecedent_count_stage\":"
                  << stage_antecedents
                  << ",\"proof_missing_antecedent_count_stage\":"
                  << stage_missing
                  << ",\"proof_assumptions_stage\":";
        std::vector<int> proof_assumptions(
            tracer.assumptions.begin() + assumptions_before,
            tracer.assumptions.end());
        print_array(proof_assumptions);
        std::cout << ",\"proof_solve_queries_stage\":"
                  << tracer.solve_queries - queries_before
                  << ",\"proof_assumption_resets_stage\":"
                  << tracer.assumption_resets - resets_before
                  << ",\"proof_deletions_stage\":"
                  << tracer.deletions - deletions_before
                  << ",\"proof_demotions_stage\":"
                  << tracer.demotions - demotions_before
                  << ",\"proof_weakenings_stage\":"
                  << tracer.weakenings - weakenings_before
                  << ",\"proof_strengthenings_stage\":"
                  << tracer.strengthenings - strengthenings_before
                  << ",\"proof_finalizations_stage\":"
                  << tracer.finalizations - finalizations_before
                  << ",\"proof_antecedent_statistics\":";
        print_stage_proof_stats(proof);
        std::cout << "}\n";

        derived_total += proof.all.events;
        antecedent_total += stage_antecedents;
        missing_antecedent_total += stage_missing;
        ++stages_run;
        ++stages_emitted;
        final_status = status;
        if (terminal) {
          terminal_stage_index = static_cast<int>(stage_index);
          break;
        }
      }
      solver->disconnect_learner();
      if (!solver->disconnect_proof_tracer(&tracer))
        throw std::runtime_error("proof tracer disconnect failed");

      const Snapshot cell_after = snapshot(*solver);
      const auto cell_delta = difference(cell_after.metrics, cell_before.metrics);
      if (final_status == 10)
        ++sat_cells;
      else if (final_status == 20)
        ++unsat_cells;
      else
        ++unknown_cells;
      accepted_clauses_total += static_cast<int64_t>(learner.clauses.size());
      offered_clauses_total += learner.offered;
      rejected_large_total += learner.rejected_large;
      std::cout << "FRESH_CA_CELL {\"mode\":\"" << arguments.mode
                << "\",\"prefix8\":\"" << prefix8
                << "\",\"cell_index\":" << cell_index
                << ",\"fresh_solver_instance\":true,\"assumptions\":";
      print_array(assumptions);
      std::cout << ",\"stages_run\":" << stages_run
                << ",\"final_status\":\"" << status_name(final_status)
                << "\",\"terminal_stage_index\":";
      if (terminal_stage_index < 0)
        std::cout << "null";
      else
        std::cout << terminal_stage_index;
      std::cout << ",\"metric_names\":[\"conflicts\",\"decisions\",\"search_propagations\"]"
                << ",\"metrics_before\":";
      print_array(cell_before.metrics);
      std::cout << ",\"metrics_after\":";
      print_array(cell_after.metrics);
      std::cout << ",\"metrics_delta\":";
      print_array(cell_delta);
      print_state_fields(cell_before, cell_after);
      std::cout << ",\"learned_clause_offered_total\":" << learner.offered
                << ",\"learned_clause_accepted_total\":"
                << learner.clauses.size()
                << ",\"learned_clause_rejected_large_total\":"
                << learner.rejected_large
                << ",\"proof_original_clause_count\":"
                << tracer.original_ids.size()
                << ",\"proof_restored_originals_total\":"
                << tracer.restored_originals
                << ",\"proof_derived_total\":" << tracer.derived_count
                << ",\"proof_begin_event_count\":" << tracer.begin_ids.size()
                << ",\"proof_status_event_count\":" << tracer.statuses.size()
                << ",\"proof_assumption_clause_count\":"
                << tracer.assumption_clause_ids.size()
                << ",\"proof_unsat_conclusions\":" << tracer.unsat_conclusions
                << ",\"proof_sat_conclusions\":" << tracer.sat_conclusions
                << ",\"proof_unknown_conclusions\":"
                << tracer.unknown_conclusions
                << ",\"proof_equivalences\":" << tracer.equivalences
                << "}\n";
    }

    if (!base_snapshot_identical)
      throw std::runtime_error("fresh solver base snapshots differ across cells");
    std::cout << "FRESH_CA_SUMMARY {\"signature\":\""
              << CaDiCaL::Solver::signature() << "\",\"version\":\""
              << CaDiCaL::Solver::version() << "\",\"mode\":\""
              << arguments.mode << "\",\"variables\":" << cnf.variables
              << ",\"clauses\":" << cnf.declared_clauses
              << ",\"literal_stream_items\":" << cnf.literals.size()
              << ",\"cells\":256,\"fresh_solver_instances\":256"
              << ",\"base_copy_source_solved\":false"
              << ",\"base_copy_method\":\"cadical_copy_irredundant_units_options_with_preconnected_LRAT_antecedent_tracer\""
              << ",\"base_snapshot_identical\":true,\"conflict_horizons\":";
    print_array(arguments.conflict_horizons);
    std::cout << ",\"configured_stages_per_nonterminal_cell\":"
              << arguments.conflict_horizons.size()
              << ",\"stages_emitted\":" << stages_emitted
              << ",\"sat_cells\":" << sat_cells
              << ",\"unsat_cells\":" << unsat_cells
              << ",\"unknown_cells\":" << unknown_cells
              << ",\"watchdog_seconds\":" << std::setprecision(17)
              << arguments.watchdog_seconds
              << ",\"metric_names\":[\"conflicts\",\"decisions\",\"search_propagations\"]"
              << ",\"proof_antecedents_enabled\":true"
              << ",\"proof_derived_total\":" << derived_total
              << ",\"proof_antecedent_total\":" << antecedent_total
              << ",\"proof_missing_antecedent_total\":"
              << missing_antecedent_total
              << ",\"learned_clause_maximum_size\":"
              << kMaximumLearnedClauseSize
              << ",\"bounded_variable_addition_enabled\":false"
              << ",\"learned_clause_offered_total\":"
              << offered_clauses_total
              << ",\"learned_clause_accepted_total\":"
              << accepted_clauses_total
              << ",\"learned_clause_rejected_large_total\":"
              << rejected_large_total << "}\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "FRESH_CA_ERROR " << error.what() << '\n';
    return 2;
  }
}

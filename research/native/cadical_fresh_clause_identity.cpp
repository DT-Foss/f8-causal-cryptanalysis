#define main cadical_fresh_multihorizon_embedded_main
#include "cadical_fresh_multihorizon.cpp"
#undef main

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

      std::unique_ptr<CaDiCaL::Solver> solver = copy_fresh_solver(*base);
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

        std::cout << "FRESH_CI_STAGE {\"mode\":\"" << arguments.mode
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
        std::cout << "}\n";

        ++stages_run;
        ++stages_emitted;
        final_status = status;
        if (terminal) {
          terminal_stage_index = static_cast<int>(stage_index);
          break;
        }
      }
      solver->disconnect_learner();

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
      std::cout << "FRESH_CI_CELL {\"mode\":\"" << arguments.mode
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
                << learner.rejected_large << "}\n";
    }

    if (!base_snapshot_identical)
      throw std::runtime_error("fresh solver base snapshots differ across cells");
    std::cout << "FRESH_CI_SUMMARY {\"signature\":\""
              << CaDiCaL::Solver::signature() << "\",\"version\":\""
              << CaDiCaL::Solver::version() << "\",\"mode\":\""
              << arguments.mode << "\",\"variables\":" << cnf.variables
              << ",\"clauses\":" << cnf.declared_clauses
              << ",\"literal_stream_items\":" << cnf.literals.size()
              << ",\"cells\":256,\"fresh_solver_instances\":256"
              << ",\"base_copy_source_solved\":false"
              << ",\"base_copy_method\":\"cadical_copy_irredundant_units_options\""
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
              << ",\"learned_clause_maximum_size\":"
              << kMaximumLearnedClauseSize
              << ",\"bounded_variable_addition_enabled\":false"
              << ",\"learned_clause_offered_total\":" << offered_clauses_total
              << ",\"learned_clause_accepted_total\":"
              << accepted_clauses_total
              << ",\"learned_clause_rejected_large_total\":"
              << rejected_large_total << "}\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "FRESH_CI_ERROR " << error.what() << '\n';
    return 2;
  }
}

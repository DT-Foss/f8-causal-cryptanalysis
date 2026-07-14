#include <cadical.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

constexpr std::array<const char *, 3> kMetricNames = {
    "conflicts", "decisions", "propagations"};

struct DeadlineTerminator final : CaDiCaL::Terminator {
  explicit DeadlineTerminator(double seconds)
      : deadline(Clock::now() + std::chrono::duration_cast<Clock::duration>(
                                    std::chrono::duration<double>(seconds))) {}

  bool terminate() override {
    if (Clock::now() < deadline) return false;
    fired = true;
    return true;
  }

  Clock::time_point deadline;
  bool fired = false;
};

struct Arguments {
  std::string cnf;
  std::string mode;
  std::vector<int> assumption_one_literals;
  std::vector<int> model_one_literals;
  std::vector<std::string> cell_order;
  std::vector<int> conflict_horizons;
  double watchdog_seconds = 0.0;
};

struct ParsedCnf {
  int variables = 0;
  int declared_clauses = 0;
  std::vector<int> literals;
};

struct Snapshot {
  std::array<int64_t, 3> metrics{};
  int64_t active = 0;
  int64_t irredundant = 0;
  int64_t redundant = 0;

  bool operator==(const Snapshot &other) const {
    return metrics == other.metrics && active == other.active &&
           irredundant == other.irredundant && redundant == other.redundant;
  }
};

std::vector<std::string> split(const std::string &raw, char delimiter,
                               const char *label) {
  if (raw.empty() || raw.front() == delimiter || raw.back() == delimiter)
    throw std::runtime_error(std::string(label) + " has an empty item");
  std::vector<std::string> result;
  std::stringstream stream(raw);
  std::string item;
  while (std::getline(stream, item, delimiter)) {
    if (item.empty())
      throw std::runtime_error(std::string(label) + " has an empty item");
    result.push_back(item);
  }
  return result;
}

int parse_positive_int(const std::string &raw, const char *label) {
  std::size_t consumed = 0;
  const long value = std::stol(raw, &consumed);
  if (consumed != raw.size() || value <= 0 || value > INT32_MAX)
    throw std::runtime_error(std::string(label) + " must be a positive integer");
  return static_cast<int>(value);
}

double parse_positive_double(const std::string &raw, const char *label) {
  std::size_t consumed = 0;
  const double value = std::stod(raw, &consumed);
  if (consumed != raw.size() || !std::isfinite(value) || value <= 0.0)
    throw std::runtime_error(std::string(label) + " must be finite and positive");
  return value;
}

std::vector<int> parse_signed_literals(const std::string &raw,
                                       const char *label) {
  std::vector<int> result;
  for (const std::string &item : split(raw, ',', label)) {
    std::size_t consumed = 0;
    const long value = std::stol(item, &consumed);
    if (consumed != item.size() || value == 0 || value < -INT32_MAX ||
        value > INT32_MAX)
      throw std::runtime_error(std::string(label) +
                               " contains an invalid signed literal");
    result.push_back(static_cast<int>(value));
  }
  return result;
}

std::vector<int> parse_horizons(const std::string &raw) {
  std::vector<int> result;
  for (const std::string &item : split(raw, ',', "conflict-horizons"))
    result.push_back(parse_positive_int(item, "conflict horizon"));
  if (!std::is_sorted(result.begin(), result.end()) ||
      std::adjacent_find(result.begin(), result.end()) != result.end())
    throw std::runtime_error(
        "conflict-horizons must be a strictly increasing list");
  return result;
}

bool is_binary_width(const std::string &value, std::size_t width) {
  return value.size() == width &&
         std::all_of(value.begin(), value.end(),
                     [](char bit) { return bit == '0' || bit == '1'; });
}

bool is_safe_mode(const std::string &value) {
  return !value.empty() &&
         std::all_of(value.begin(), value.end(), [](unsigned char character) {
           return std::isalnum(character) || character == '_' ||
                  character == '-' || character == '.';
         });
}

Arguments parse_arguments(int argc, char **argv) {
  Arguments result;
  std::set<std::string> observed_options;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 >= argc) throw std::runtime_error("option without value");
    const std::string option = argv[index];
    const std::string value = argv[index + 1];
    if (!observed_options.insert(option).second)
      throw std::runtime_error("duplicate option: " + option);
    if (option == "--cnf")
      result.cnf = value;
    else if (option == "--mode")
      result.mode = value;
    else if (option == "--assumption-one-literals")
      result.assumption_one_literals =
          parse_signed_literals(value, "assumption-one-literals");
    else if (option == "--model-one-literals")
      result.model_one_literals =
          parse_signed_literals(value, "model-one-literals");
    else if (option == "--cell-order")
      result.cell_order = split(value, ',', "cell-order");
    else if (option == "--conflict-horizons")
      result.conflict_horizons = parse_horizons(value);
    else if (option == "--watchdog-seconds")
      result.watchdog_seconds =
          parse_positive_double(value, "watchdog-seconds");
    else
      throw std::runtime_error("unknown option: " + option);
  }
  if (result.cnf.empty()) throw std::runtime_error("cnf is required");
  if (!is_safe_mode(result.mode))
    throw std::runtime_error(
        "mode must contain only alphanumeric, dot, dash, or underscore");
  if (result.assumption_one_literals.size() != 8)
    throw std::runtime_error(
        "exactly eight assumption-one-literals are required");
  if (result.model_one_literals.size() != 20)
    throw std::runtime_error("exactly twenty model-one-literals are required");
  std::set<int> assumption_variables;
  for (const int literal : result.assumption_one_literals)
    assumption_variables.insert(std::abs(literal));
  std::set<int> model_variables;
  for (const int literal : result.model_one_literals)
    model_variables.insert(std::abs(literal));
  if (assumption_variables.size() != 8)
    throw std::runtime_error("assumption variables must be distinct");
  if (model_variables.size() != 20)
    throw std::runtime_error("model variables must be distinct");
  if (result.cell_order.size() != 256)
    throw std::runtime_error("cell order must contain 256 entries");
  std::set<std::string> observed_cells;
  for (const std::string &cell : result.cell_order) {
    if (!is_binary_width(cell, 8))
      throw std::runtime_error("cell order entries must be eight-bit binary");
    observed_cells.insert(cell);
  }
  if (observed_cells.size() != 256)
    throw std::runtime_error(
        "cell order must cover every eight-bit value exactly once");
  if (result.conflict_horizons.empty())
    throw std::runtime_error("conflict-horizons is required");
  if (result.watchdog_seconds <= 0.0)
    throw std::runtime_error("watchdog-seconds is required");
  return result;
}

ParsedCnf parse_dimacs(const std::string &path) {
  std::ifstream input(path);
  if (!input) throw std::runtime_error("cannot open DIMACS file");
  ParsedCnf result;
  bool header_seen = false;
  int observed_clauses = 0;
  std::string line;
  while (std::getline(input, line)) {
    const std::size_t first = line.find_first_not_of(" \t\r");
    if (first == std::string::npos || line[first] == 'c') continue;
    if (line[first] == 'p') {
      if (header_seen) throw std::runtime_error("duplicate DIMACS header");
      std::istringstream stream(line.substr(first));
      std::string p;
      std::string format;
      std::string trailing;
      if (!(stream >> p >> format >> result.variables >>
            result.declared_clauses) ||
          p != "p" || format != "cnf" || result.variables <= 0 ||
          result.declared_clauses < 0 || (stream >> trailing))
        throw std::runtime_error("invalid DIMACS header");
      header_seen = true;
      continue;
    }
    if (!header_seen)
      throw std::runtime_error("DIMACS clause appears before header");
    std::istringstream stream(line.substr(first));
    long raw = 0;
    while (stream >> raw) {
      if (raw < -result.variables || raw > result.variables)
        throw std::runtime_error("DIMACS literal exceeds declared variables");
      result.literals.push_back(static_cast<int>(raw));
      if (raw == 0) ++observed_clauses;
    }
    if (!stream.eof()) throw std::runtime_error("invalid DIMACS token");
  }
  if (!header_seen) throw std::runtime_error("DIMACS header is missing");
  if (!result.literals.empty() && result.literals.back() != 0)
    throw std::runtime_error("DIMACS final clause is unterminated");
  if (observed_clauses != result.declared_clauses)
    throw std::runtime_error("DIMACS clause count differs from header");
  return result;
}

int64_t statistic(CaDiCaL::Solver &solver, const char *name) {
  const int64_t value = solver.get_statistic_value(name);
  if (value < 0)
    throw std::runtime_error(std::string("unsupported statistic: ") + name);
  return value;
}

Snapshot snapshot(CaDiCaL::Solver &solver) {
  Snapshot result;
  for (std::size_t index = 0; index < kMetricNames.size(); ++index)
    result.metrics[index] = statistic(solver, kMetricNames[index]);
  result.active = solver.active();
  result.irredundant = solver.irredundant();
  result.redundant = solver.redundant();
  return result;
}

std::string status_name(int status) {
  if (status == 0) return "unknown";
  if (status == 10) return "sat";
  if (status == 20) return "unsat";
  throw std::runtime_error("unexpected CaDiCaL status");
}

template <typename T>
void print_array(const std::vector<T> &values) {
  std::cout << '[';
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index) std::cout << ',';
    std::cout << values[index];
  }
  std::cout << ']';
}

void print_array(const std::array<int64_t, 3> &values) {
  std::cout << '[' << values[0] << ',' << values[1] << ',' << values[2]
            << ']';
}

std::array<int64_t, 3> difference(const std::array<int64_t, 3> &after,
                                  const std::array<int64_t, 3> &before) {
  return {after[0] - before[0], after[1] - before[1],
          after[2] - before[2]};
}

bool literal_is_true_in_model(CaDiCaL::Solver &solver, int literal) {
  const int value = solver.val(std::abs(literal));
  if (value == 0)
    throw std::runtime_error("model variable has no Boolean value");
  return (value > 0) == (literal > 0);
}

void print_state_fields(const Snapshot &before, const Snapshot &after) {
  const struct {
    const char *name;
    int64_t Snapshot::*member;
  } fields[] = {{"active_variables", &Snapshot::active},
                {"irredundant_clauses", &Snapshot::irredundant},
                {"redundant_clauses", &Snapshot::redundant}};
  for (const auto &field : fields) {
    const int64_t left = before.*(field.member);
    const int64_t right = after.*(field.member);
    std::cout << ",\"" << field.name << "_before\":" << left << ",\""
              << field.name << "_after\":" << right << ",\""
              << field.name << "_delta\":" << right - left;
  }
}

std::unique_ptr<CaDiCaL::Solver> build_base_solver(
    const ParsedCnf &cnf, const Arguments &arguments) {
  auto solver = std::make_unique<CaDiCaL::Solver>();
  if (!solver->set("quiet", 1) || !solver->set("reverse", 1) ||
      !solver->set("factorcheck", 0))
    throw std::runtime_error("required CaDiCaL options are unavailable");
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

std::unique_ptr<CaDiCaL::Solver> copy_fresh_solver(
    const CaDiCaL::Solver &base) {
  auto solver = std::make_unique<CaDiCaL::Solver>();
  base.copy(*solver);
  return solver;
}

}  // namespace

int main(int argc, char **argv) {
  try {
    const Arguments arguments = parse_arguments(argc, argv);
    const ParsedCnf cnf = parse_dimacs(arguments.cnf);
    const std::unique_ptr<CaDiCaL::Solver> base =
        build_base_solver(cnf, arguments);
    int sat_cells = 0;
    int unsat_cells = 0;
    int unknown_cells = 0;
    int stages_emitted = 0;
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
        if (terminator.fired)
          throw std::runtime_error("stage watchdog fired");
        const Snapshot stage_after = snapshot(*solver);
        const auto stage_delta =
            difference(stage_after.metrics, stage_before.metrics);
        const auto cell_delta =
            difference(stage_after.metrics, cell_before.metrics);
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

        std::cout << "FRESH_MH_STAGE {\"mode\":\"" << arguments.mode
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
        std::cout << "}\n";

        ++stages_run;
        ++stages_emitted;
        final_status = status;
        if (terminal) {
          terminal_stage_index = static_cast<int>(stage_index);
          break;
        }
      }

      const Snapshot cell_after = snapshot(*solver);
      const auto cell_delta = difference(cell_after.metrics, cell_before.metrics);
      if (final_status == 10)
        ++sat_cells;
      else if (final_status == 20)
        ++unsat_cells;
      else
        ++unknown_cells;
      std::cout << "FRESH_MH_CELL {\"mode\":\"" << arguments.mode
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
      std::cout << "}\n";
    }

    if (!base_snapshot_identical)
      throw std::runtime_error("fresh solver base snapshots differ across cells");
    std::cout << "FRESH_MH_SUMMARY {\"signature\":\""
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
              << ",\"metric_names\":[\"conflicts\",\"decisions\",\"search_propagations\"]}\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "FRESH_MH_ERROR " << error.what() << '\n';
    return 2;
  }
}

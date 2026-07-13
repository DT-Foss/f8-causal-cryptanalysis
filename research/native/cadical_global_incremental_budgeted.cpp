#include <cadical.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

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
  int conflicts = 0;
  double seconds = 0.0;
  double watchdog_seconds = 0.0;
  bool load_only = false;
};

std::vector<std::string> split(const std::string &raw, char delimiter) {
  std::vector<std::string> result;
  std::stringstream stream(raw);
  std::string item;
  while (std::getline(stream, item, delimiter)) result.push_back(item);
  return result;
}

std::vector<int> parse_signed_literals(const std::string &raw,
                                       const char *label) {
  std::vector<int> result;
  for (const std::string &item : split(raw, ',')) {
    if (item.empty())
      throw std::runtime_error(std::string(label) + " has an empty item");
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
  if (consumed != raw.size() || value <= 0.0)
    throw std::runtime_error(std::string(label) + " must be positive");
  return value;
}

bool is_binary_width(const std::string &value, std::size_t width) {
  return value.size() == width &&
         std::all_of(value.begin(), value.end(),
                     [](char bit) { return bit == '0' || bit == '1'; });
}

Arguments parse_arguments(int argc, char **argv) {
  Arguments result;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 >= argc) throw std::runtime_error("option without value");
    const std::string option = argv[index];
    const std::string value = argv[index + 1];
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
      result.cell_order = split(value, ',');
    else if (option == "--conflicts")
      result.conflicts = parse_positive_int(value, "conflicts");
    else if (option == "--seconds")
      result.seconds = parse_positive_double(value, "seconds");
    else if (option == "--watchdog-seconds")
      result.watchdog_seconds =
          parse_positive_double(value, "watchdog-seconds");
    else if (option == "--load-only") {
      if (value != "0" && value != "1")
        throw std::runtime_error("load-only must be 0 or 1");
      result.load_only = value == "1";
    } else {
      throw std::runtime_error("unknown option: " + option);
    }
  }
  if (result.cnf.empty() || result.mode.empty())
    throw std::runtime_error("cnf and mode are required");
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
  if (result.load_only) {
    if (!result.cell_order.empty() || result.conflicts || result.seconds ||
        result.watchdog_seconds)
      throw std::runtime_error(
          "load-only forbids cell-order and solve budgets");
    return result;
  }
  if ((result.conflicts > 0) == (result.seconds > 0.0))
    throw std::runtime_error(
        "exactly one of conflicts or seconds is required");
  if (result.seconds > 0.0 && result.watchdog_seconds > 0.0)
    throw std::runtime_error(
        "seconds mode cannot also specify watchdog-seconds");
  if (result.cell_order.size() != 256)
    throw std::runtime_error("cell order must contain 256 entries");
  std::set<std::string> observed;
  for (const std::string &cell : result.cell_order) {
    if (!is_binary_width(cell, 8))
      throw std::runtime_error("cell order entries must be eight-bit binary");
    observed.insert(cell);
  }
  if (observed.size() != 256)
    throw std::runtime_error(
        "cell order must cover every eight-bit value exactly once");
  return result;
}

int64_t statistic(CaDiCaL::Solver &solver, const char *name) {
  const int64_t value = solver.get_statistic_value(name);
  if (value < 0)
    throw std::runtime_error(std::string("unsupported statistic: ") + name);
  return value;
}

std::string status_name(int status) {
  if (status == 0) return "unknown";
  if (status == 10) return "sat";
  if (status == 20) return "unsat";
  throw std::runtime_error("unexpected CaDiCaL status");
}

void print_integer_array(const std::vector<int> &values) {
  std::cout << '[';
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index) std::cout << ',';
    std::cout << values[index];
  }
  std::cout << ']';
}

void print_int64_array(const std::vector<int64_t> &values) {
  std::cout << '[';
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index) std::cout << ',';
    std::cout << values[index];
  }
  std::cout << ']';
}

bool literal_is_true_in_model(CaDiCaL::Solver &solver, int literal) {
  const int value = solver.val(std::abs(literal));
  if (value == 0)
    throw std::runtime_error("model variable has no Boolean value");
  return (value > 0) == (literal > 0);
}

}  // namespace

int main(int argc, char **argv) {
  try {
    const Arguments arguments = parse_arguments(argc, argv);
    CaDiCaL::Solver solver;
    if (!solver.set("quiet", 1) || !solver.set("reverse", 1))
      throw std::runtime_error("required CaDiCaL options are unavailable");
    int variables = 0;
    if (const char *error =
            solver.read_dimacs(arguments.cnf.c_str(), variables, 1))
      throw std::runtime_error(std::string("DIMACS read failed: ") + error);
    std::set<int> frozen;
    for (const int literal : arguments.assumption_one_literals)
      frozen.insert(std::abs(literal));
    for (const int literal : arguments.model_one_literals)
      frozen.insert(std::abs(literal));
    for (const int variable : frozen) {
      if (variable > variables)
        throw std::runtime_error("mapped variable exceeds CNF header");
      solver.freeze(variable);
    }

    if (arguments.load_only) {
      std::cout << "R20_BUDGET_LOAD {\"signature\":\""
                << CaDiCaL::Solver::signature() << "\",\"version\":\""
                << CaDiCaL::Solver::version() << "\",\"mode\":\""
                << arguments.mode << "\",\"variables\":" << variables
                << ",\"active_variables\":" << solver.active()
                << ",\"irredundant_clauses\":" << solver.irredundant()
                << ",\"redundant_clauses\":" << solver.redundant()
                << "}\n";
      return 0;
    }

    const char *metric_names[] = {"conflicts", "decisions", "propagations"};
    const std::string budget_kind =
        arguments.conflicts > 0 ? "conflicts" : "seconds";
    int sat = 0, unsat = 0, unknown = 0, seconds_budget_fires = 0,
        watchdog_fires = 0;
    for (std::size_t cell_index = 0;
         cell_index < arguments.cell_order.size(); ++cell_index) {
      const std::string &prefix8 = arguments.cell_order[cell_index];
      std::vector<int> assumptions;
      for (std::size_t bit = 0; bit < 8; ++bit) {
        const int one_literal = arguments.assumption_one_literals[bit];
        assumptions.push_back(prefix8[bit] == '1' ? one_literal : -one_literal);
      }
      std::vector<int64_t> before;
      for (const char *metric : metric_names)
        before.push_back(statistic(solver, metric));
      const int active_before = solver.active();
      const int64_t irredundant_before = solver.irredundant();
      const int64_t redundant_before = solver.redundant();
      for (const int literal : assumptions) solver.assume(literal);

      DeadlineTerminator terminator(
          arguments.seconds > 0.0 ? arguments.seconds
                                  : arguments.watchdog_seconds);
      const bool use_terminator =
          arguments.seconds > 0.0 || arguments.watchdog_seconds > 0.0;
      if (arguments.conflicts > 0 &&
          !solver.limit("conflicts", arguments.conflicts))
        throw std::runtime_error("CaDiCaL conflict limit is unavailable");
      if (use_terminator) solver.connect_terminator(&terminator);
      const auto started = Clock::now();
      const int status = solver.solve();
      const double elapsed =
          std::chrono::duration<double>(Clock::now() - started).count();
      if (use_terminator) solver.disconnect_terminator();
      const bool seconds_budget_fired =
          arguments.seconds > 0.0 && terminator.fired;
      const bool watchdog_fired =
          arguments.conflicts > 0 && arguments.watchdog_seconds > 0.0 &&
          terminator.fired;
      if (seconds_budget_fired) ++seconds_budget_fires;
      if (watchdog_fired) ++watchdog_fires;

      std::vector<int64_t> after;
      std::vector<int64_t> delta;
      for (std::size_t metric = 0; metric < 3; ++metric) {
        after.push_back(statistic(solver, metric_names[metric]));
        delta.push_back(after.back() - before[metric]);
      }
      const int active_after = solver.active();
      const int64_t irredundant_after = solver.irredundant();
      const int64_t redundant_after = solver.redundant();
      const bool budget_exhausted =
          status == 0 &&
          ((arguments.conflicts > 0 && delta[0] >= arguments.conflicts) ||
           seconds_budget_fired);

      std::vector<int> model_bits;
      if (status == 10) {
        ++sat;
        for (const int literal : arguments.model_one_literals)
          model_bits.push_back(literal_is_true_in_model(solver, literal) ? 1 : 0);
      } else if (status == 20) {
        ++unsat;
      } else {
        ++unknown;
      }
      std::vector<int> failed_assumptions;
      if (status == 20)
        for (const int literal : assumptions)
          if (solver.failed(literal)) failed_assumptions.push_back(literal);

      std::cout << "R20_BUDGET_RESULT {\"mode\":\"" << arguments.mode
                << "\",\"prefix8\":\"" << prefix8
                << "\",\"cell_index\":" << cell_index << ",\"status\":\""
                << status_name(status) << "\",\"returncode\":" << status
                << ",\"budget_kind\":\"" << budget_kind
                << "\",\"budget_value\":" << std::setprecision(17)
                << (arguments.conflicts > 0
                        ? static_cast<double>(arguments.conflicts)
                        : arguments.seconds)
                << ",\"budget_exhausted\":"
                << (budget_exhausted ? "true" : "false")
                << ",\"elapsed_seconds\":" << std::setprecision(17) << elapsed
                << ",\"seconds_budget_fired\":"
                << (seconds_budget_fired ? "true" : "false")
                << ",\"watchdog_fired\":"
                << (watchdog_fired ? "true" : "false")
                << ",\"assumptions\":";
      print_integer_array(assumptions);
      std::cout << ",\"failed_assumptions\":";
      print_integer_array(failed_assumptions);
      std::cout << ",\"model_bits_bit0_through_bit19\":";
      print_integer_array(model_bits);
      std::cout << ",\"metric_names\":[\"conflicts\",\"decisions\",\"search_propagations\"]";
      std::cout << ",\"metrics_before\":";
      print_int64_array(before);
      std::cout << ",\"metrics_after\":";
      print_int64_array(after);
      std::cout << ",\"metrics_delta\":";
      print_int64_array(delta);
      std::cout << ",\"active_variables_before\":" << active_before
                << ",\"active_variables_after\":" << active_after
                << ",\"active_variables_delta\":"
                << active_after - active_before
                << ",\"irredundant_clauses_before\":" << irredundant_before
                << ",\"irredundant_clauses_after\":" << irredundant_after
                << ",\"irredundant_clauses_delta\":"
                << irredundant_after - irredundant_before
                << ",\"redundant_clauses_before\":" << redundant_before
                << ",\"redundant_clauses_after\":" << redundant_after
                << ",\"redundant_clauses_delta\":"
                << redundant_after - redundant_before << "}\n";
    }
    std::cout << "R20_BUDGET_SUMMARY {\"signature\":\""
              << CaDiCaL::Solver::signature() << "\",\"version\":\""
              << CaDiCaL::Solver::version() << "\",\"mode\":\""
              << arguments.mode << "\",\"variables\":" << variables
              << ",\"cells\":256,\"sat\":" << sat << ",\"unsat\":"
              << unsat << ",\"unknown\":" << unknown
              << ",\"seconds_budget_fires\":" << seconds_budget_fires
              << ",\"watchdog_fires\":" << watchdog_fires
              << ",\"budget_kind\":\"" << budget_kind
              << "\",\"budget_value\":"
              << (arguments.conflicts > 0
                      ? static_cast<double>(arguments.conflicts)
                      : arguments.seconds)
              << ",\"metric_names\":[\"conflicts\",\"decisions\",\"search_propagations\"]}\n";
    return watchdog_fires ? 3 : 0;
  } catch (const std::exception &error) {
    std::cerr << "R20_BUDGET_ERROR " << error.what() << '\n';
    return 2;
  }
}

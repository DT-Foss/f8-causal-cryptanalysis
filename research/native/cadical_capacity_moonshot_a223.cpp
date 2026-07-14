#include <cadical.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
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
  std::string arm;
  std::string model_spool;
  std::vector<int> assumption_one_literals;
  std::vector<int> model_one_literals;
  std::vector<std::string> cell_order;
  double seconds = 0.0;
  bool load_only = false;
};

struct ModelRecord {
  std::size_t cell_index;
  std::string prefix8;
  std::vector<int> bits;
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
    else if (option == "--arm")
      result.arm = value;
    else if (option == "--assumption-one-literals")
      result.assumption_one_literals =
          parse_signed_literals(value, "assumption-one-literals");
    else if (option == "--model-one-literals")
      result.model_one_literals =
          parse_signed_literals(value, "model-one-literals");
    else if (option == "--model-spool")
      result.model_spool = value;
    else if (option == "--cell-order")
      result.cell_order = split(value, ',');
    else if (option == "--seconds") {
      std::size_t consumed = 0;
      result.seconds = std::stod(value, &consumed);
      if (consumed != value.size() || result.seconds <= 0.0)
        throw std::runtime_error("seconds must be positive");
    } else if (option == "--load-only") {
      if (value != "0" && value != "1")
        throw std::runtime_error("load-only must be 0 or 1");
      result.load_only = value == "1";
    } else {
      throw std::runtime_error("unknown option: " + option);
    }
  }
  if (result.cnf.empty() || result.arm.empty())
    throw std::runtime_error("cnf and arm are required");
  if (result.assumption_one_literals.size() != 8)
    throw std::runtime_error(
        "exactly eight assumption-one-literals are required");
  if (result.model_one_literals.empty() || result.model_one_literals.size() > 256)
    throw std::runtime_error("between one and 256 model-one-literals are required");

  std::set<int> assumption_variables;
  for (const int literal : result.assumption_one_literals)
    assumption_variables.insert(std::abs(literal));
  std::set<int> model_variables;
  for (const int literal : result.model_one_literals)
    model_variables.insert(std::abs(literal));
  if (assumption_variables.size() != 8)
    throw std::runtime_error("assumption variables must be distinct");
  if (model_variables.size() != result.model_one_literals.size())
    throw std::runtime_error("model variables must be distinct");
  if (!std::includes(model_variables.begin(), model_variables.end(),
                     assumption_variables.begin(), assumption_variables.end()))
    throw std::runtime_error("assumption variables must be model variables");

  if (result.load_only) {
    if (!result.cell_order.empty() || result.seconds != 0.0 ||
        !result.model_spool.empty())
      throw std::runtime_error(
          "load-only forbids cell-order, solve seconds, and model-spool");
    return result;
  }
  if (result.seconds <= 0.0 || result.model_spool.empty())
    throw std::runtime_error(
        "seconds and model-spool are required outside load-only mode");
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

void print_integer_array(std::ostream &stream, const std::vector<int> &values) {
  stream << '[';
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index) stream << ',';
    stream << values[index];
  }
  stream << ']';
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

void write_model_spool(const Arguments &arguments,
                       const std::vector<ModelRecord> &records) {
  std::ofstream spool(arguments.model_spool,
                      std::ios::out | std::ios::trunc | std::ios::binary);
  if (!spool) throw std::runtime_error("cannot open model-spool");
  for (const ModelRecord &record : records) {
    spool << "A223_MODEL {\"arm\":\"" << arguments.arm
          << "\",\"cell_index\":" << record.cell_index
          << ",\"prefix8\":\"" << record.prefix8
          << "\",\"model_width\":" << record.bits.size()
          << ",\"model_bits_bit0_upward\":";
    print_integer_array(spool, record.bits);
    spool << "}\n";
  }
  spool.flush();
  if (!spool) throw std::runtime_error("cannot finalize model-spool");
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
    for (const int literal : arguments.assumption_one_literals) {
      if (std::abs(literal) > variables)
        throw std::runtime_error("assumption variable exceeds CNF header");
      solver.freeze(std::abs(literal));
    }
    for (const int literal : arguments.model_one_literals)
      if (std::abs(literal) > variables)
        throw std::runtime_error("model variable exceeds CNF header");

    if (arguments.load_only) {
      std::cout << "A223_LOAD {\"signature\":\""
                << CaDiCaL::Solver::signature() << "\",\"version\":\""
                << CaDiCaL::Solver::version() << "\",\"arm\":\""
                << arguments.arm << "\",\"variables\":" << variables
                << ",\"model_width\":" << arguments.model_one_literals.size()
                << ",\"active_variables\":" << solver.active()
                << ",\"irredundant_clauses\":" << solver.irredundant()
                << ",\"redundant_clauses\":" << solver.redundant()
                << "}\n";
      return 0;
    }

    const char *metric_names[] = {"conflicts", "decisions", "propagations"};
    int sat = 0, unsat = 0, unknown = 0;
    std::vector<ModelRecord> model_records;
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
      for (const int literal : assumptions) solver.assume(literal);
      DeadlineTerminator terminator(arguments.seconds);
      solver.connect_terminator(&terminator);
      const auto started = Clock::now();
      const int status = solver.solve();
      const double elapsed =
          std::chrono::duration<double>(Clock::now() - started).count();
      solver.disconnect_terminator();

      std::vector<int64_t> after;
      std::vector<int64_t> delta;
      for (std::size_t metric = 0; metric < 3; ++metric) {
        after.push_back(statistic(solver, metric_names[metric]));
        delta.push_back(after.back() - before[metric]);
      }
      bool model_buffered_for_post_arm_spool = false;
      if (status == 10) {
        ++sat;
        ModelRecord record{cell_index, prefix8, {}};
        for (const int literal : arguments.model_one_literals)
          record.bits.push_back(
              literal_is_true_in_model(solver, literal) ? 1 : 0);
        model_records.push_back(std::move(record));
        model_buffered_for_post_arm_spool = true;
      } else if (status == 20) {
        ++unsat;
      } else if (status == 0) {
        ++unknown;
      }
      std::vector<int> failed_assumptions;
      if (status == 20)
        for (const int literal : assumptions)
          if (solver.failed(literal)) failed_assumptions.push_back(literal);

      std::cout << "A223_RESULT {\"arm\":\"" << arguments.arm
                << "\",\"prefix8\":\"" << prefix8
                << "\",\"cell_index\":" << cell_index << ",\"status\":\""
                << status_name(status) << "\",\"returncode\":" << status
                << ",\"elapsed_seconds\":" << std::setprecision(17) << elapsed
                << ",\"terminator_fired\":"
                << (terminator.fired ? "true" : "false")
                << ",\"assumptions\":";
      print_integer_array(std::cout, assumptions);
      std::cout << ",\"failed_assumptions\":";
      print_integer_array(std::cout, failed_assumptions);
      std::cout << ",\"model_buffered_for_post_arm_spool\":"
                << (model_buffered_for_post_arm_spool ? "true" : "false")
                << ",\"metric_names\":[\"conflicts\",\"decisions\",\"search_propagations\"]"
                << ",\"metrics_before\":";
      print_int64_array(before);
      std::cout << ",\"metrics_after\":";
      print_int64_array(after);
      std::cout << ",\"metrics_delta\":";
      print_int64_array(delta);
      std::cout << ",\"active_variables\":" << solver.active()
                << ",\"irredundant_clauses\":" << solver.irredundant()
                << ",\"redundant_clauses\":" << solver.redundant()
                << "}\n";
    }
    write_model_spool(arguments, model_records);
    std::cout << "A223_SUMMARY {\"signature\":\""
              << CaDiCaL::Solver::signature() << "\",\"version\":\""
              << CaDiCaL::Solver::version() << "\",\"arm\":\""
              << arguments.arm << "\",\"variables\":" << variables
              << ",\"model_width\":" << arguments.model_one_literals.size()
              << ",\"cells\":256,\"sat\":" << sat
              << ",\"unsat\":" << unsat << ",\"unknown\":" << unknown
              << ",\"model_records_spooled_after_complete_arm\":"
              << model_records.size()
              << ",\"metric_names\":[\"conflicts\",\"decisions\",\"search_propagations\"]}\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "A223_ERROR " << error.what() << '\n';
    return 2;
  }
}

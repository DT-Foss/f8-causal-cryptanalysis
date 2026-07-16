#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr std::uint32_t kAxisCells = 1u << 12;
constexpr std::uint32_t kPairCells = 1u << 24;
constexpr std::size_t kComponents = 3;
constexpr std::array<unsigned char, 16> kMagic = {
    'A', '4', '5', '6', 'R', 'A', 'N', 'K', 'V', '1', 0, 0, 0, 0, 0, 0};
constexpr std::array<char, kComponents> kSymbols = {'H', 'B', 'O'};

struct ComponentOrder {
  std::array<std::uint16_t, kAxisCells> prefix_inverse{};
  std::array<std::uint16_t, kAxisCells> off_axis_inverse{};
};

struct Pattern {
  std::string text;
  std::array<std::vector<std::uint32_t>, kComponents> occurrence_slots;
};

struct Job {
  std::uint64_t first_key;
  std::uint32_t canonical_id;
};

std::uint16_t read_u16be(std::istream& input) {
  unsigned char bytes[2]{};
  input.read(reinterpret_cast<char*>(bytes), 2);
  if (!input) {
    throw std::runtime_error("A456 component input ended early");
  }
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8) |
                                    static_cast<std::uint16_t>(bytes[1]));
}

void write_u32be(std::ostream& output, std::uint32_t value) {
  const std::array<unsigned char, 4> bytes = {
      static_cast<unsigned char>((value >> 24) & 0xffu),
      static_cast<unsigned char>((value >> 16) & 0xffu),
      static_cast<unsigned char>((value >> 8) & 0xffu),
      static_cast<unsigned char>(value & 0xffu),
  };
  output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::array<std::uint16_t, kAxisCells> read_inverse_permutation(
    std::istream& input) {
  std::array<std::uint16_t, kAxisCells> inverse{};
  std::array<bool, kAxisCells> seen{};
  for (std::uint32_t position = 0; position < kAxisCells; ++position) {
    const std::uint16_t value = read_u16be(input);
    if (value >= kAxisCells || seen[value]) {
      throw std::runtime_error("A456 component order is not a permutation");
    }
    seen[value] = true;
    inverse[value] = static_cast<std::uint16_t>(position);
  }
  if (!std::all_of(seen.begin(), seen.end(), [](bool value) { return value; })) {
    throw std::runtime_error("A456 component order cover is incomplete");
  }
  return inverse;
}

std::array<ComponentOrder, kComponents> read_components(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("A456 cannot open component input");
  }
  std::array<unsigned char, 16> magic{};
  input.read(reinterpret_cast<char*>(magic.data()), magic.size());
  if (!input || magic != kMagic) {
    throw std::runtime_error("A456 component input magic differs");
  }
  std::array<ComponentOrder, kComponents> components{};
  for (auto& component : components) {
    component.prefix_inverse = read_inverse_permutation(input);
    component.off_axis_inverse = read_inverse_permutation(input);
  }
  if (input.peek() != std::char_traits<char>::eof()) {
    throw std::runtime_error("A456 component input has trailing bytes");
  }
  return components;
}

std::uint32_t square_rank(const ComponentOrder& component,
                          std::uint32_t canonical_id) {
  const std::uint32_t prefix = canonical_id >> 12;
  const std::uint32_t off_axis = canonical_id & (kAxisCells - 1u);
  const std::uint32_t left = component.prefix_inverse[prefix];
  const std::uint32_t right = component.off_axis_inverse[off_axis];
  const std::uint32_t shell = std::max(left, right);
  const std::uint32_t zero_based =
      left == shell ? shell * shell + right
                    : shell * shell + shell + 1u + left;
  if (zero_based >= kPairCells) {
    throw std::runtime_error("A456 component rank is outside the pair domain");
  }
  return zero_based + 1u;
}

std::size_t component_index(char symbol) {
  const auto found = std::find(kSymbols.begin(), kSymbols.end(), symbol);
  if (found == kSymbols.end()) {
    throw std::runtime_error("A456 pattern contains an unknown symbol");
  }
  return static_cast<std::size_t>(found - kSymbols.begin());
}

Pattern parse_pattern(const std::string& text) {
  if (text.size() < 3u || text.size() > 31u) {
    throw std::runtime_error("A456 pattern period must be in [3,31]");
  }
  Pattern pattern{.text = text, .occurrence_slots = {}};
  for (std::uint32_t slot = 0; slot < text.size(); ++slot) {
    pattern.occurrence_slots[component_index(text[slot])].push_back(slot);
  }
  if (std::any_of(pattern.occurrence_slots.begin(),
                  pattern.occurrence_slots.end(),
                  [](const auto& slots) { return slots.empty(); })) {
    throw std::runtime_error("A456 pattern must contain H, B, and O");
  }
  return pattern;
}

std::uint64_t proposal_key(const Pattern& pattern, std::size_t component,
                           std::uint32_t one_based_rank) {
  if (one_based_rank == 0u) {
    throw std::runtime_error("A456 proposal rank must be one based");
  }
  const auto& slots = pattern.occurrence_slots[component];
  const std::uint64_t zero_based_rank = one_based_rank - 1u;
  const std::uint64_t cycle = zero_based_rank / slots.size();
  const std::size_t occurrence =
      static_cast<std::size_t>(zero_based_rank % slots.size());
  return cycle * pattern.text.size() + slots[occurrence];
}

std::vector<Job> build_jobs(
    const std::array<ComponentOrder, kComponents>& components,
    const Pattern& pattern) {
  std::vector<Job> jobs;
  jobs.reserve(kPairCells);
  for (std::uint32_t canonical_id = 0; canonical_id < kPairCells;
       ++canonical_id) {
    std::uint64_t first_key = std::numeric_limits<std::uint64_t>::max();
    for (std::size_t component = 0; component < kComponents; ++component) {
      first_key = std::min(
          first_key,
          proposal_key(pattern, component,
                       square_rank(components[component], canonical_id)));
    }
    jobs.push_back(Job{.first_key = first_key, .canonical_id = canonical_id});
  }
  return jobs;
}

bool earlier(const Job& left, const Job& right) {
  if (left.first_key != right.first_key) {
    return left.first_key < right.first_key;
  }
  return left.canonical_id < right.canonical_id;
}

void write_schedule(const std::string& path, const std::vector<Job>& jobs) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    throw std::runtime_error("A456 cannot open output artifact");
  }
  std::uint64_t previous_key = 0;
  bool first = true;
  for (const Job& job : jobs) {
    if (!first && job.first_key <= previous_key) {
      throw std::runtime_error("A456 first-encounter keys are not unique");
    }
    first = false;
    previous_key = job.first_key;
    const std::uint32_t prefix = job.canonical_id >> 12;
    const std::uint32_t off_axis = job.canonical_id & (kAxisCells - 1u);
    write_u32be(output, (prefix << 16) | off_axis);
  }
  output.flush();
  if (!output) {
    throw std::runtime_error("A456 output artifact write failed");
  }
}

void exhaustive_small_semantics_test() {
  constexpr std::size_t kSmallCells = 3;
  using Order = std::array<std::uint32_t, kSmallCells>;
  std::array<char, 3> symbols = {'B', 'H', 'O'};
  do {
    const Pattern pattern = parse_pattern(std::string(symbols.begin(), symbols.end()));
    Order first = {0u, 1u, 2u};
    do {
      Order second = {0u, 1u, 2u};
      do {
        Order third = {0u, 1u, 2u};
        do {
          const std::array<Order, kComponents> orders = {first, second, third};
          std::array<Order, kComponents> inverse{};
          for (std::size_t component = 0; component < kComponents; ++component) {
            for (std::size_t rank = 0; rank < kSmallCells; ++rank) {
              inverse[component][orders[component][rank]] =
                  static_cast<std::uint32_t>(rank + 1u);
            }
          }
          std::array<Job, kSmallCells> calculated{};
          for (std::uint32_t cell = 0; cell < kSmallCells; ++cell) {
            std::uint64_t key = std::numeric_limits<std::uint64_t>::max();
            for (std::size_t component = 0; component < kComponents; ++component) {
              key = std::min(
                  key,
                  proposal_key(pattern, component, inverse[component][cell]));
            }
            calculated[cell] = Job{.first_key = key, .canonical_id = cell};
          }
          std::sort(calculated.begin(), calculated.end(), earlier);
          std::array<std::size_t, kComponents> cursors{};
          std::array<bool, kSmallCells> seen{};
          std::array<std::uint32_t, kSmallCells> simulated{};
          std::size_t discovered = 0;
          for (std::size_t slot = 0; discovered < kSmallCells; ++slot) {
            const std::size_t component =
                component_index(pattern.text[slot % pattern.text.size()]);
            if (cursors[component] >= kSmallCells) {
              continue;
            }
            const std::uint32_t cell = orders[component][cursors[component]++];
            if (!seen[cell]) {
              seen[cell] = true;
              simulated[discovered++] = cell;
            }
          }
          for (std::size_t rank = 0; rank < kSmallCells; ++rank) {
            if (calculated[rank].canonical_id != simulated[rank]) {
              throw std::runtime_error(
                  "A456 exhaustive small first-encounter semantics failed");
            }
          }
        } while (std::next_permutation(third.begin(), third.end()));
      } while (std::next_permutation(second.begin(), second.end()));
    } while (std::next_permutation(first.begin(), first.end()));
  } while (std::next_permutation(symbols.begin(), symbols.end()));
}

void self_test() {
  const Pattern pattern = parse_pattern("BOOOHHH");
  if (proposal_key(pattern, 0u, 1u) != 4u ||
      proposal_key(pattern, 0u, 2u) != 5u ||
      proposal_key(pattern, 0u, 3u) != 6u ||
      proposal_key(pattern, 0u, 4u) != 11u ||
      proposal_key(pattern, 1u, 1u) != 0u ||
      proposal_key(pattern, 1u, 2u) != 7u ||
      proposal_key(pattern, 2u, 1u) != 1u ||
      proposal_key(pattern, 2u, 4u) != 8u) {
    throw std::runtime_error("A456 frequency-ray proposal-key self-test failed");
  }
  ComponentOrder identity{};
  for (std::uint32_t index = 0; index < kAxisCells; ++index) {
    identity.prefix_inverse[index] = static_cast<std::uint16_t>(index);
    identity.off_axis_inverse[index] = static_cast<std::uint16_t>(index);
  }
  if (square_rank(identity, 0u) != 1u ||
      square_rank(identity, (1u << 12)) != 2u ||
      square_rank(identity, (1u << 12) | 1u) != 3u ||
      square_rank(identity, 1u) != 4u) {
    throw std::runtime_error("A456 square-rank self-test failed");
  }
  const Job first{.first_key = 2u, .canonical_id = 9u};
  const Job second{.first_key = 3u, .canonical_id = 0u};
  if (!earlier(first, second) || earlier(second, first)) {
    throw std::runtime_error("A456 ordering self-test failed");
  }
  exhaustive_small_semantics_test();
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string(argv[1]) == "--self-test") {
      self_test();
      std::cout << "A456 frequency-ray compiler self-test passed\n";
      return 0;
    }
    if (argc != 4) {
      std::cerr << "usage: " << argv[0]
                << " COMPONENT_INPUT OUTPUT_PAIR_STREAM PATTERN\n";
      return 2;
    }
    const Pattern pattern = parse_pattern(argv[3]);
    const auto components = read_components(argv[1]);
    std::cerr << "A456 building frequency-ray keys for pattern "
              << pattern.text << '\n';
    auto jobs = build_jobs(components, pattern);
    std::cerr << "A456 sorting " << jobs.size() << " cells\n";
    std::sort(jobs.begin(), jobs.end(), earlier);
    std::cerr << "A456 writing complete pair permutation\n";
    write_schedule(argv[2], jobs);
    std::cerr << "A456 complete\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}

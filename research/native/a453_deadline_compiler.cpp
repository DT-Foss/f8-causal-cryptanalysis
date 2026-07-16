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
    'A', '4', '5', '3', 'R', 'A', 'N', 'K', 'V', '1', 0, 0, 0, 0, 0, 0};

struct ComponentOrder {
  std::array<std::uint16_t, kAxisCells> prefix_inverse{};
  std::array<std::uint16_t, kAxisCells> off_axis_inverse{};
};

struct Job {
  std::uint32_t median_rank;
  std::uint32_t maximum_rank;
  std::uint32_t minimum_rank;
  std::uint32_t canonical_id;
  std::uint32_t deadline;
};

std::uint16_t read_u16be(std::istream& input) {
  unsigned char bytes[2]{};
  input.read(reinterpret_cast<char*>(bytes), 2);
  if (!input) {
    throw std::runtime_error("A453 component input ended early");
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
      throw std::runtime_error("A453 component order is not a permutation");
    }
    seen[value] = true;
    inverse[value] = static_cast<std::uint16_t>(position);
  }
  if (!std::all_of(seen.begin(), seen.end(), [](bool value) { return value; })) {
    throw std::runtime_error("A453 component order cover is incomplete");
  }
  return inverse;
}

std::array<ComponentOrder, kComponents> read_components(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("A453 cannot open component input");
  }
  std::array<unsigned char, 16> magic{};
  input.read(reinterpret_cast<char*>(magic.data()), magic.size());
  if (!input || magic != kMagic) {
    throw std::runtime_error("A453 component input magic differs");
  }
  std::array<ComponentOrder, kComponents> components{};
  for (auto& component : components) {
    component.prefix_inverse = read_inverse_permutation(input);
    component.off_axis_inverse = read_inverse_permutation(input);
  }
  if (input.peek() != std::char_traits<char>::eof()) {
    throw std::runtime_error("A453 component input has trailing bytes");
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
    throw std::runtime_error("A453 component rank is outside the pair domain");
  }
  return zero_based + 1u;
}

class PredecessorSet {
 public:
  explicit PredecessorSet(std::uint32_t cells) : parent_(cells + 1u) {
    for (std::uint32_t index = 0; index <= cells; ++index) {
      parent_[index] = index;
    }
  }

  std::uint32_t find(std::uint32_t value) {
    std::uint32_t root = value;
    while (parent_[root] != root) {
      root = parent_[root];
    }
    while (parent_[value] != value) {
      const std::uint32_t next = parent_[value];
      parent_[value] = root;
      value = next;
    }
    return root;
  }

  void occupy(std::uint32_t value) { parent_[value] = find(value - 1u); }

 private:
  std::vector<std::uint32_t> parent_;
};

bool worse_priority(const Job& left, const Job& right) {
  if (left.median_rank != right.median_rank) {
    return left.median_rank > right.median_rank;
  }
  if (left.maximum_rank != right.maximum_rank) {
    return left.maximum_rank > right.maximum_rank;
  }
  if (left.minimum_rank != right.minimum_rank) {
    return left.minimum_rank > right.minimum_rank;
  }
  return left.canonical_id > right.canonical_id;
}

std::vector<Job> build_jobs(
    const std::array<ComponentOrder, kComponents>& components) {
  std::vector<Job> jobs;
  jobs.reserve(kPairCells);
  for (std::uint32_t canonical_id = 0; canonical_id < kPairCells;
       ++canonical_id) {
    std::array<std::uint32_t, kComponents> ranks{};
    for (std::size_t component = 0; component < kComponents; ++component) {
      ranks[component] = square_rank(components[component], canonical_id);
    }
    std::sort(ranks.begin(), ranks.end());
    const std::uint64_t unbounded_deadline =
        static_cast<std::uint64_t>(kComponents) * ranks[0];
    jobs.push_back(Job{
        .median_rank = ranks[1],
        .maximum_rank = ranks[2],
        .minimum_rank = ranks[0],
        .canonical_id = canonical_id,
        .deadline = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(kPairCells, unbounded_deadline)),
    });
  }
  return jobs;
}

std::vector<std::uint32_t> compile_schedule(std::vector<Job>& jobs) {
  std::cerr << "A453 sorting " << jobs.size()
            << " cells by descending majority-consensus priority\n";
  std::sort(jobs.begin(), jobs.end(), worse_priority);
  std::cerr << "A453 assigning latest feasible deadline slots\n";
  PredecessorSet free_slots(kPairCells);
  std::vector<std::uint32_t> order(kPairCells,
                                   std::numeric_limits<std::uint32_t>::max());
  for (const Job& job : jobs) {
    const std::uint32_t slot = free_slots.find(job.deadline);
    if (slot == 0u) {
      throw std::runtime_error("A453 deadline compiler found no feasible slot");
    }
    order[slot - 1u] = job.canonical_id;
    free_slots.occupy(slot);
  }
  if (free_slots.find(kPairCells) != 0u) {
    throw std::runtime_error("A453 deadline compiler left a free slot");
  }
  return order;
}

void write_schedule(const std::string& path,
                    const std::vector<std::uint32_t>& order) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    throw std::runtime_error("A453 cannot open output artifact");
  }
  for (const std::uint32_t canonical_id : order) {
    if (canonical_id >= kPairCells) {
      throw std::runtime_error("A453 output order contains an invalid cell");
    }
    const std::uint32_t prefix = canonical_id >> 12;
    const std::uint32_t off_axis = canonical_id & (kAxisCells - 1u);
    write_u32be(output, (prefix << 16) | off_axis);
  }
  output.flush();
  if (!output) {
    throw std::runtime_error("A453 output artifact write failed");
  }
}

void self_test() {
  ComponentOrder identity{};
  for (std::uint32_t index = 0; index < kAxisCells; ++index) {
    identity.prefix_inverse[index] = static_cast<std::uint16_t>(index);
    identity.off_axis_inverse[index] = static_cast<std::uint16_t>(index);
  }
  if (square_rank(identity, 0u) != 1u ||
      square_rank(identity, (1u << 12)) != 2u ||
      square_rank(identity, (1u << 12) | 1u) != 3u ||
      square_rank(identity, 1u) != 4u) {
    throw std::runtime_error("A453 square-rank self-test failed");
  }
  const Job better{.median_rank = 2u,
                   .maximum_rank = 9u,
                   .minimum_rank = 1u,
                   .canonical_id = 0u,
                   .deadline = 3u};
  const Job worse{.median_rank = 3u,
                  .maximum_rank = 4u,
                  .minimum_rank = 1u,
                  .canonical_id = 1u,
                  .deadline = 3u};
  if (worse_priority(better, worse) || !worse_priority(worse, better)) {
    throw std::runtime_error("A453 priority self-test failed");
  }
  PredecessorSet slots(4u);
  if (slots.find(4u) != 4u) {
    throw std::runtime_error("A453 predecessor initialization failed");
  }
  slots.occupy(4u);
  slots.occupy(2u);
  slots.occupy(3u);
  slots.occupy(1u);
  if (slots.find(4u) != 0u) {
    throw std::runtime_error("A453 predecessor cover self-test failed");
  }
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string(argv[1]) == "--self-test") {
      self_test();
      std::cout << "A453 deadline compiler self-test passed\n";
      return 0;
    }
    if (argc != 3) {
      std::cerr << "usage: " << argv[0]
                << " COMPONENT_INPUT OUTPUT_PAIR_STREAM\n";
      return 2;
    }
    const auto components = read_components(argv[1]);
    std::cerr << "A453 building exact rank deadlines\n";
    auto jobs = build_jobs(components);
    const auto order = compile_schedule(jobs);
    jobs.clear();
    jobs.shrink_to_fit();
    std::cerr << "A453 writing complete pair permutation\n";
    write_schedule(argv[2], order);
    std::cerr << "A453 complete\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}

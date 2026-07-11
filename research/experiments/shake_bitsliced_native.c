/*
 * Native candidate-axis bit-sliced Keccak-f[1600].
 *
 * The implementation is deliberately self-contained C11/POSIX: one uint64_t
 * carries the same bit coordinate for 64 candidate states.  It exposes both a
 * 64-state permutation gate and a threaded exact rate-filter kernel so the
 * Python experiment can cross-check semantics before using the fast path.
 */
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define KECCAK_LANES 25
#define LANE_BITS 64
#define KECCAK_ROUNDS 24

static const uint64_t ROUND_CONSTANTS[KECCAK_ROUNDS] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};

/* Indexed as [x][y], matching FIPS 202 and the independent NumPy core. */
static const unsigned ROTATION_OFFSETS[5][5] = {
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14},
};

static const uint64_t LOW_CANDIDATE_PATTERNS[6] = {
    UINT64_C(0xaaaaaaaaaaaaaaaa),
    UINT64_C(0xcccccccccccccccc),
    UINT64_C(0xf0f0f0f0f0f0f0f0),
    UINT64_C(0xff00ff00ff00ff00),
    UINT64_C(0xffff0000ffff0000),
    UINT64_C(0xffffffff00000000),
};

/* a[lane][bit] contains one bit from each of 64 candidate states. */
static void keccak_f1600_bitsliced(uint64_t a[KECCAK_LANES][LANE_BITS]) {
    uint64_t b[KECCAK_LANES][LANE_BITS];
    uint64_t c[5][LANE_BITS];

    for (unsigned round = 0; round < KECCAK_ROUNDS; ++round) {
        /* Theta. */
        for (unsigned x = 0; x < 5; ++x) {
            for (unsigned bit = 0; bit < LANE_BITS; ++bit) {
                c[x][bit] = a[x][bit] ^ a[x + 5][bit] ^ a[x + 10][bit]
                    ^ a[x + 15][bit] ^ a[x + 20][bit];
            }
        }
        for (unsigned x = 0; x < 5; ++x) {
            const unsigned xm1 = (x + 4) % 5;
            const unsigned xp1 = (x + 1) % 5;
            for (unsigned bit = 0; bit < LANE_BITS; ++bit) {
                const uint64_t d = c[xm1][bit] ^ c[xp1][(bit + 63) & 63];
                a[x][bit] ^= d;
                a[x + 5][bit] ^= d;
                a[x + 10][bit] ^= d;
                a[x + 15][bit] ^= d;
                a[x + 20][bit] ^= d;
            }
        }

        /* Rho and Pi. */
        for (unsigned x = 0; x < 5; ++x) {
            for (unsigned y = 0; y < 5; ++y) {
                const unsigned source = x + 5 * y;
                const unsigned destination = y + 5 * ((2 * x + 3 * y) % 5);
                const unsigned rotation = ROTATION_OFFSETS[x][y];
                for (unsigned bit = 0; bit < LANE_BITS; ++bit) {
                    b[destination][bit] =
                        a[source][(bit + LANE_BITS - rotation) & 63];
                }
            }
        }

        /* Chi. */
        for (unsigned y = 0; y < 5; ++y) {
            for (unsigned x = 0; x < 5; ++x) {
                const unsigned lane = x + 5 * y;
                const unsigned next = ((x + 1) % 5) + 5 * y;
                const unsigned next2 = ((x + 2) % 5) + 5 * y;
                for (unsigned bit = 0; bit < LANE_BITS; ++bit) {
                    a[lane][bit] = b[lane][bit]
                        ^ ((~b[next][bit]) & b[next2][bit]);
                }
            }
        }

        /* Iota: an RC bit is applied identically to all 64 candidates. */
        const uint64_t rc = ROUND_CONSTANTS[round];
        for (unsigned bit = 0; bit < LANE_BITS; ++bit) {
            if ((rc >> bit) & UINT64_C(1)) {
                a[0][bit] ^= UINT64_MAX;
            }
        }
    }
}

int shake_bitslice_permute64(const uint64_t *input, uint64_t *output) {
    if (input == NULL || output == NULL) {
        return 1;
    }
    uint64_t state[KECCAK_LANES][LANE_BITS] = {{0}};
    for (unsigned candidate = 0; candidate < 64; ++candidate) {
        for (unsigned lane = 0; lane < KECCAK_LANES; ++lane) {
            const uint64_t value = input[candidate * KECCAK_LANES + lane];
            for (unsigned bit = 0; bit < LANE_BITS; ++bit) {
                state[lane][bit] |= ((value >> bit) & UINT64_C(1)) << candidate;
            }
        }
    }
    keccak_f1600_bitsliced(state);
    memset(output, 0, 64 * KECCAK_LANES * sizeof(uint64_t));
    for (unsigned candidate = 0; candidate < 64; ++candidate) {
        for (unsigned lane = 0; lane < KECCAK_LANES; ++lane) {
            uint64_t value = 0;
            for (unsigned bit = 0; bit < LANE_BITS; ++bit) {
                value |= ((state[lane][bit] >> candidate) & UINT64_C(1)) << bit;
            }
            output[candidate * KECCAK_LANES + lane] = value;
        }
    }
    return 0;
}

typedef struct {
    const uint64_t *template_state;
    unsigned rate_lanes;
    const uint16_t *positions;
    unsigned window_bits;
    uint64_t first_pack;
    uint64_t begin;
    uint64_t end;
    const uint64_t *target;
    const uint64_t *wrong_target;
    unsigned filter_lanes;
    uint64_t *factual_masks;
    uint64_t *wrong_masks;
} filter_job;

static void initialize_candidate_pack(
    uint64_t state[KECCAK_LANES][LANE_BITS],
    const filter_job *job,
    uint64_t pack_index
) {
    for (unsigned lane = 0; lane < KECCAK_LANES; ++lane) {
        const uint64_t value = job->template_state[lane];
        for (unsigned bit = 0; bit < LANE_BITS; ++bit) {
            state[lane][bit] = ((value >> bit) & UINT64_C(1))
                ? UINT64_MAX : UINT64_C(0);
        }
    }
    for (unsigned candidate_bit = 0; candidate_bit < job->window_bits;
         ++candidate_bit) {
        const unsigned position = job->positions[candidate_bit];
        const unsigned lane = job->rate_lanes + position / LANE_BITS;
        const unsigned bit = position % LANE_BITS;
        state[lane][bit] = candidate_bit < 6
            ? LOW_CANDIDATE_PATTERNS[candidate_bit]
            : (((pack_index >> (candidate_bit - 6)) & UINT64_C(1))
                ? UINT64_MAX : UINT64_C(0));
    }
}

static void *filter_worker(void *opaque) {
    filter_job *job = (filter_job *)opaque;
    uint64_t state[KECCAK_LANES][LANE_BITS];
    for (uint64_t local = job->begin; local < job->end; ++local) {
        const uint64_t pack_index = job->first_pack + local;
        initialize_candidate_pack(state, job, pack_index);
        keccak_f1600_bitsliced(state);
        uint64_t factual = UINT64_MAX;
        uint64_t wrong = UINT64_MAX;
        for (unsigned lane = 0; lane < job->filter_lanes; ++lane) {
            const uint64_t target_lane = job->target[lane];
            const uint64_t wrong_lane = job->wrong_target[lane];
            for (unsigned bit = 0; bit < LANE_BITS; ++bit) {
                const uint64_t plane = state[lane][bit];
                factual &= ((target_lane >> bit) & UINT64_C(1)) ? plane : ~plane;
                wrong &= ((wrong_lane >> bit) & UINT64_C(1)) ? plane : ~plane;
            }
        }
        job->factual_masks[local] = factual;
        job->wrong_masks[local] = wrong;
    }
    return NULL;
}

int shake_bitslice_filter(
    const uint64_t *template_state,
    unsigned rate_lanes,
    const uint16_t *positions,
    unsigned window_bits,
    uint64_t first_pack,
    uint64_t pack_count,
    const uint64_t *target,
    const uint64_t *wrong_target,
    unsigned filter_lanes,
    unsigned thread_count,
    uint64_t *factual_masks,
    uint64_t *wrong_masks
) {
    if (template_state == NULL || positions == NULL || target == NULL
        || wrong_target == NULL || factual_masks == NULL || wrong_masks == NULL
        || rate_lanes > KECCAK_LANES || window_bits == 0 || window_bits > 63
        || filter_lanes == 0 || filter_lanes > rate_lanes || thread_count == 0) {
        return 1;
    }
    for (unsigned bit = 0; bit < window_bits; ++bit) {
        if (positions[bit] >= (KECCAK_LANES - rate_lanes) * LANE_BITS) {
            return 1;
        }
    }
    if (UINT64_MAX - first_pack < pack_count) {
        return 1;
    }
    if (pack_count == 0) {
        return 0;
    }
    if (thread_count > pack_count) {
        thread_count = (unsigned)pack_count;
    }
    pthread_t *threads = calloc(thread_count, sizeof(*threads));
    filter_job *jobs = calloc(thread_count, sizeof(*jobs));
    if (threads == NULL || jobs == NULL) {
        free(threads);
        free(jobs);
        return 2;
    }

    unsigned launched = 0;
    for (unsigned index = 0; index < thread_count; ++index) {
        const uint64_t begin = (pack_count * index) / thread_count;
        const uint64_t end = (pack_count * (index + 1)) / thread_count;
        jobs[index] = (filter_job){
            .template_state = template_state,
            .rate_lanes = rate_lanes,
            .positions = positions,
            .window_bits = window_bits,
            .first_pack = first_pack,
            .begin = begin,
            .end = end,
            .target = target,
            .wrong_target = wrong_target,
            .filter_lanes = filter_lanes,
            .factual_masks = factual_masks,
            .wrong_masks = wrong_masks,
        };
        if (pthread_create(&threads[index], NULL, filter_worker, &jobs[index]) != 0) {
            for (unsigned prior = 0; prior < launched; ++prior) {
                pthread_join(threads[prior], NULL);
            }
            free(threads);
            free(jobs);
            return 3;
        }
        ++launched;
    }
    for (unsigned index = 0; index < launched; ++index) {
        pthread_join(threads[index], NULL);
    }
    free(threads);
    free(jobs);
    return 0;
}

const char *shake_bitslice_native_version(void) {
    return "shake-bitslice-native-v1";
}

/* Native candidate-axis bit-sliced ChaCha20 partial-key search kernel. */

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHACHA_WORDS 16U
#define WORD_BITS 32U
#define CANDIDATES_PER_PACK 64U

static const uint64_t LOW_CANDIDATE_PATTERNS[6] = {
    UINT64_C(0xAAAAAAAAAAAAAAAA),
    UINT64_C(0xCCCCCCCCCCCCCCCC),
    UINT64_C(0xF0F0F0F0F0F0F0F0),
    UINT64_C(0xFF00FF00FF00FF00),
    UINT64_C(0xFFFF0000FFFF0000),
    UINT64_C(0xFFFFFFFF00000000),
};

static void add_word(
    uint64_t out[WORD_BITS],
    const uint64_t left[WORD_BITS],
    const uint64_t right[WORD_BITS]
) {
    uint64_t result[WORD_BITS];
    uint64_t carry = UINT64_C(0);
    for (unsigned bit = 0; bit < WORD_BITS; ++bit) {
        const uint64_t pair_xor = left[bit] ^ right[bit];
        result[bit] = pair_xor ^ carry;
        carry = (left[bit] & right[bit]) | (carry & pair_xor);
    }
    memcpy(out, result, sizeof(result));
}

static void xor_word(
    uint64_t out[WORD_BITS],
    const uint64_t left[WORD_BITS],
    const uint64_t right[WORD_BITS]
) {
    for (unsigned bit = 0; bit < WORD_BITS; ++bit) {
        out[bit] = left[bit] ^ right[bit];
    }
}

static void rotl_word(uint64_t word[WORD_BITS], unsigned shift) {
    uint64_t rotated[WORD_BITS];
    for (unsigned bit = 0; bit < WORD_BITS; ++bit) {
        rotated[(bit + shift) & 31U] = word[bit];
    }
    memcpy(word, rotated, sizeof(rotated));
}

static void quarter_round(
    uint64_t state[CHACHA_WORDS][WORD_BITS],
    unsigned a,
    unsigned b,
    unsigned c,
    unsigned d
) {
    add_word(state[a], state[a], state[b]);
    xor_word(state[d], state[d], state[a]);
    rotl_word(state[d], 16U);
    add_word(state[c], state[c], state[d]);
    xor_word(state[b], state[b], state[c]);
    rotl_word(state[b], 12U);
    add_word(state[a], state[a], state[b]);
    xor_word(state[d], state[d], state[a]);
    rotl_word(state[d], 8U);
    add_word(state[c], state[c], state[d]);
    xor_word(state[b], state[b], state[c]);
    rotl_word(state[b], 7U);
}

static void chacha20_block_planes(
    uint64_t state[CHACHA_WORDS][WORD_BITS]
) {
    uint64_t initial[CHACHA_WORDS][WORD_BITS];
    memcpy(initial, state, sizeof(initial));
    for (unsigned double_round = 0; double_round < 10U; ++double_round) {
        quarter_round(state, 0U, 4U, 8U, 12U);
        quarter_round(state, 1U, 5U, 9U, 13U);
        quarter_round(state, 2U, 6U, 10U, 14U);
        quarter_round(state, 3U, 7U, 11U, 15U);
        quarter_round(state, 0U, 5U, 10U, 15U);
        quarter_round(state, 1U, 6U, 11U, 12U);
        quarter_round(state, 2U, 7U, 8U, 13U);
        quarter_round(state, 3U, 4U, 9U, 14U);
    }
    for (unsigned word = 0; word < CHACHA_WORDS; ++word) {
        add_word(state[word], state[word], initial[word]);
    }
}

static void scalar_to_planes(
    const uint32_t input[CANDIDATES_PER_PACK][CHACHA_WORDS],
    uint64_t state[CHACHA_WORDS][WORD_BITS]
) {
    memset(state, 0, sizeof(uint64_t) * CHACHA_WORDS * WORD_BITS);
    for (unsigned candidate = 0; candidate < CANDIDATES_PER_PACK; ++candidate) {
        for (unsigned word = 0; word < CHACHA_WORDS; ++word) {
            const uint32_t value = input[candidate][word];
            for (unsigned bit = 0; bit < WORD_BITS; ++bit) {
                state[word][bit] |=
                    ((uint64_t)((value >> bit) & UINT32_C(1))) << candidate;
            }
        }
    }
}

static void planes_to_scalar(
    const uint64_t state[CHACHA_WORDS][WORD_BITS],
    uint32_t output[CANDIDATES_PER_PACK][CHACHA_WORDS]
) {
    for (unsigned candidate = 0; candidate < CANDIDATES_PER_PACK; ++candidate) {
        for (unsigned word = 0; word < CHACHA_WORDS; ++word) {
            uint32_t value = UINT32_C(0);
            for (unsigned bit = 0; bit < WORD_BITS; ++bit) {
                value |= (uint32_t)((state[word][bit] >> candidate) & UINT64_C(1))
                    << bit;
            }
            output[candidate][word] = value;
        }
    }
}

int chacha20_bitslice_blocks64(
    const uint32_t *input_flat,
    uint32_t *output_flat
) {
    if (input_flat == NULL || output_flat == NULL) {
        return 1;
    }
    const uint32_t (*input)[CHACHA_WORDS] =
        (const uint32_t (*)[CHACHA_WORDS])input_flat;
    uint32_t (*output)[CHACHA_WORDS] =
        (uint32_t (*)[CHACHA_WORDS])output_flat;
    uint64_t state[CHACHA_WORDS][WORD_BITS];
    scalar_to_planes(input, state);
    chacha20_block_planes(state);
    planes_to_scalar(state, output);
    return 0;
}

typedef struct {
    const uint32_t *initial;
    unsigned unknown_word;
    uint64_t first_pack;
    uint64_t begin;
    uint64_t end;
    const uint32_t *target;
    const uint32_t *control;
    unsigned filter_words;
    uint64_t *factual_masks;
    uint64_t *control_masks;
} filter_job;

static void initialize_candidate_pack(
    uint64_t state[CHACHA_WORDS][WORD_BITS],
    const filter_job *job,
    uint64_t pack_index
) {
    for (unsigned word = 0; word < CHACHA_WORDS; ++word) {
        const uint32_t value = job->initial[word];
        for (unsigned bit = 0; bit < WORD_BITS; ++bit) {
            state[word][bit] = ((value >> bit) & UINT32_C(1))
                ? UINT64_MAX
                : UINT64_C(0);
        }
    }
    for (unsigned bit = 0; bit < WORD_BITS; ++bit) {
        state[job->unknown_word][bit] = bit < 6U
            ? LOW_CANDIDATE_PATTERNS[bit]
            : (((pack_index >> (bit - 6U)) & UINT64_C(1))
                ? UINT64_MAX
                : UINT64_C(0));
    }
}

static uint64_t target_mask(
    const uint64_t state[CHACHA_WORDS][WORD_BITS],
    const uint32_t target[CHACHA_WORDS],
    unsigned filter_words
) {
    uint64_t mask = UINT64_MAX;
    for (unsigned word = 0; word < filter_words; ++word) {
        const uint32_t expected = target[word];
        for (unsigned bit = 0; bit < WORD_BITS; ++bit) {
            mask &= ((expected >> bit) & UINT32_C(1))
                ? state[word][bit]
                : ~state[word][bit];
        }
    }
    return mask;
}

static void *filter_worker(void *opaque) {
    filter_job *job = (filter_job *)opaque;
    uint64_t state[CHACHA_WORDS][WORD_BITS];
    for (uint64_t local = job->begin; local < job->end; ++local) {
        const uint64_t pack_index = job->first_pack + local;
        initialize_candidate_pack(state, job, pack_index);
        chacha20_block_planes(state);
        job->factual_masks[local] =
            target_mask(state, job->target, job->filter_words);
        job->control_masks[local] =
            target_mask(state, job->control, job->filter_words);
    }
    return NULL;
}

int chacha20_bitslice_filter(
    const uint32_t *initial,
    unsigned unknown_word,
    uint64_t first_pack,
    uint64_t pack_count,
    const uint32_t *target,
    const uint32_t *control,
    unsigned filter_words,
    unsigned thread_count,
    uint64_t *factual_masks,
    uint64_t *control_masks
) {
    if (
        initial == NULL || target == NULL || control == NULL
        || factual_masks == NULL || control_masks == NULL
        || unknown_word < 4U || unknown_word > 11U
        || filter_words == 0U || filter_words > CHACHA_WORDS
        || thread_count == 0U
    ) {
        return 1;
    }
    if (UINT64_MAX - first_pack < pack_count) {
        return 2;
    }
    if (pack_count == 0U) {
        return 0;
    }
    if ((uint64_t)thread_count > pack_count) {
        thread_count = (unsigned)pack_count;
    }
    pthread_t *threads = calloc(thread_count, sizeof(*threads));
    filter_job *jobs = calloc(thread_count, sizeof(*jobs));
    if (threads == NULL || jobs == NULL) {
        free(threads);
        free(jobs);
        return 3;
    }
    unsigned started = 0U;
    for (unsigned index = 0; index < thread_count; ++index) {
        const uint64_t begin = (pack_count * index) / thread_count;
        const uint64_t end = (pack_count * (index + 1U)) / thread_count;
        jobs[index] = (filter_job){
            .initial = initial,
            .unknown_word = unknown_word,
            .first_pack = first_pack,
            .begin = begin,
            .end = end,
            .target = target,
            .control = control,
            .filter_words = filter_words,
            .factual_masks = factual_masks,
            .control_masks = control_masks,
        };
        if (pthread_create(&threads[index], NULL, filter_worker, &jobs[index]) != 0) {
            break;
        }
        ++started;
    }
    int status = started == thread_count ? 0 : 4;
    for (unsigned index = 0; index < started; ++index) {
        if (pthread_join(threads[index], NULL) != 0) {
            status = 5;
        }
    }
    free(threads);
    free(jobs);
    return status;
}

const char *chacha20_bitslice_native_version(void) {
    return "chacha20-bitslice-native-v1";
}

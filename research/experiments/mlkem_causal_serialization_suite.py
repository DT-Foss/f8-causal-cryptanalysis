#!/usr/bin/env python3
"""Causal serialization interventions on real ML-KEM compressed coefficients.

Unlike a 16-bit re-encoding with random padding, every intervention here is a
bijection of exactly the same compressed coefficient bits and has exactly the
same byte length:

* standard FIPS bit packing;
* bit-plane packing (all bit-0 values, then all bit-1 values, ...);
* coefficient-order routing through a balanced global permutation.

Thus any score change is representation/locality sensitivity of the statistic,
not information removal by ``Compress_d``. Uniform compressed coefficients are
processed through the same interventions as a negative control.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import itertools
import json
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from scipy import stats

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder
from arx_carry_leak.f8 import _chi_square
from arx_carry_leak.live_casi_v091.core import compute_amplified_score, compute_casi_score


@dataclass(frozen=True)
class Variant:
    name: str
    module: str
    u_bytes: int
    coefficient_bits: int
    coefficient_count: int


VARIANTS = (
    Variant("mlkem512", "pqcrypto.kem.ml_kem_512", 640, 10, 512),
    Variant("mlkem768", "pqcrypto.kem.ml_kem_768", 960, 10, 768),
    Variant("mlkem1024", "pqcrypto.kem.ml_kem_1024", 1408, 11, 1024),
)
Q = 3329


def _decode(data: bytes, width: int, count: int) -> np.ndarray:
    accumulator = bits = 0
    values = []
    mask = (1 << width) - 1
    for byte in data:
        accumulator |= byte << bits
        bits += 8
        while bits >= width and len(values) < count:
            values.append(accumulator & mask)
            accumulator >>= width
            bits -= width
    if len(values) != count:
        raise ValueError(f"decoded {len(values)} coefficients, expected {count}")
    return np.asarray(values, dtype=np.uint16)


def _encode(values: np.ndarray, width: int) -> bytes:
    accumulator = bits = 0
    output = bytearray()
    mask = (1 << width) - 1
    for value in values:
        accumulator |= (int(value) & mask) << bits
        bits += width
        while bits >= 8:
            output.append(accumulator & 0xFF)
            accumulator >>= 8
            bits -= 8
    if bits:
        output.append(accumulator & 0xFF)
    return bytes(output)


def _bitplane_encode(values: np.ndarray, width: int) -> bytes:
    bits = ((values[:, None] >> np.arange(width, dtype=np.uint16)) & 1).astype(np.uint8)
    return np.packbits(bits.T.reshape(-1), bitorder="little").tobytes()


def _compress_field(values: np.ndarray, width: int) -> np.ndarray:
    """FIPS-203 Compress_d on canonical representatives in Z_q."""
    wide = values.astype(np.int64)
    return ((((wide << width) + Q // 2) // Q) & ((1 << width) - 1)).astype(np.uint16)


def _compression_probabilities(width: int) -> np.ndarray:
    compressed = _compress_field(np.arange(Q, dtype=np.uint16), width)
    return np.bincount(compressed.astype(np.int64), minlength=1 << width) / Q


def _rows(stream: bytes) -> np.ndarray:
    usable = len(stream) - len(stream) % 32
    return np.frombuffer(stream[:usable], dtype=np.uint8).reshape(-1, 32).copy()


def _f8_output(rows: np.ndarray, shift: int = 5) -> float:
    first, second = rows[:-1], rows[1:]
    n_bins = 2 ** (8 - shift)
    source = first >> shift
    delta = (first ^ second) >> shift
    significant = tested = 0
    for i in range(32):
        for j in range(32):
            flat = source[:, i].astype(np.int64) * n_bins + delta[:, j]
            table = np.bincount(flat, minlength=n_bins * n_bins).reshape(n_bins, n_bins)
            result = _chi_square(table.astype(float), len(first))
            if result is None:
                continue
            tested += 1
            significant += result[1] < 0.05
    return significant / max(tested, 1)


def _measure(stream: bytes, baseline_seed: int) -> dict[str, float | int]:
    rows = _rows(stream)
    standard = compute_casi_score(rows, baseline_seed=baseline_seed)
    amplified = compute_amplified_score(rows, baseline_seed=baseline_seed)
    return {
        "bytes": len(stream),
        "rows": len(rows),
        "casi": float(max(standard["casi"], amplified["casi"])),
        "f8_output_rate": _f8_output(rows),
    }


def _entropy(values: np.ndarray, alphabet: int) -> float:
    counts = np.bincount(values.astype(np.int64), minlength=alphabet)
    probabilities = counts[counts > 0] / len(values)
    return float(-np.sum(probabilities * np.log2(probabilities)))


def _distribution_fit(values: np.ndarray, width: int) -> dict[str, Any]:
    alphabet = 1 << width
    counts = np.bincount(values.astype(np.int64), minlength=alphabet)
    expected_probabilities = _compression_probabilities(width)
    expected = len(values) * expected_probabilities
    chi_square = float(np.sum((counts - expected) ** 2 / expected))
    degrees_of_freedom = alphabet - 1
    observed_probabilities = counts / len(values)
    uniform = np.full(alphabet, 1.0 / alphabet)
    occupancy_values, occupancy_counts = np.unique(
        np.bincount(
            _compress_field(np.arange(Q, dtype=np.uint16), width).astype(np.int64),
            minlength=alphabet,
        ),
        return_counts=True,
    )
    return {
        "samples": len(values),
        "chi_square_vs_uniform_field_through_compress": chi_square,
        "degrees_of_freedom": degrees_of_freedom,
        "reduced_chi_square": chi_square / degrees_of_freedom,
        "p_value": float(stats.chi2.sf(chi_square, degrees_of_freedom)),
        "tv_observed_to_uniform_field_compress": float(
            0.5 * np.sum(np.abs(observed_probabilities - expected_probabilities))
        ),
        "tv_observed_to_uniform_output_alphabet": float(
            0.5 * np.sum(np.abs(observed_probabilities - uniform))
        ),
        "tv_theoretical_compress_to_uniform_output_alphabet": float(
            0.5 * np.sum(np.abs(expected_probabilities - uniform))
        ),
        "preimages_per_output_symbol": {
            str(int(value)): int(count)
            for value, count in zip(occupancy_values, occupancy_counts, strict=True)
        },
    }


def _paired_test(first: list[float], second: list[float]) -> dict[str, float | int]:
    differences = np.asarray(first) - np.asarray(second)
    observed = float(np.mean(differences))
    null = np.asarray(
        [np.mean(differences * signs) for signs in itertools.product((-1.0, 1.0), repeat=len(differences))]
    )
    upper = float(np.mean(null >= observed))
    lower = float(np.mean(null <= observed))
    return {
        "mean_difference": observed,
        "seed_pairs": len(differences),
        "exact_assignments": len(null),
        "upper_tail_p": upper,
        "lower_tail_p": lower,
        "two_sided_p": min(1.0, 2.0 * min(upper, lower)),
    }


def _summary(records: list[dict[str, Any]], stream: str, metric: str) -> dict[str, Any]:
    values = [float(record["measurements"][stream][metric]) for record in records]
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
    }


def _seed_run(variant: Variant, operations: int, seed: int) -> dict[str, Any]:
    module = importlib.import_module(variant.module)
    rng = np.random.default_rng(seed)
    route = route_ensemble(variant.coefficient_count, 1, 0xB17B1A + seed)[0]
    route_check = verify_routes([route])
    real_standard = []
    real_planes = []
    real_routed = []
    uniform_standard = []
    uniform_planes = []
    uniform_field_compressed_standard = []
    exact_repacks = roundtrips = bitcount_identities = 0
    all_real_values = []
    all_field_compressed_values = []
    for _ in range(operations):
        public_key, secret_key = module.generate_keypair()
        ciphertext, shared_secret = module.encrypt(public_key)
        roundtrips += module.decrypt(secret_key, ciphertext) == shared_secret
        packed = ciphertext[: variant.u_bytes]
        values = _decode(packed, variant.coefficient_bits, variant.coefficient_count)
        all_real_values.append(values)
        repacked = _encode(values, variant.coefficient_bits)
        planes = _bitplane_encode(values, variant.coefficient_bits)
        routed = _encode(values[route], variant.coefficient_bits)
        exact_repacks += repacked == packed
        bitcount_identities += (
            sum(byte.bit_count() for byte in packed)
            == sum(byte.bit_count() for byte in planes)
            == sum(byte.bit_count() for byte in routed)
        )
        real_standard.append(packed)
        real_planes.append(planes)
        real_routed.append(routed)
        uniform = rng.integers(
            0,
            1 << variant.coefficient_bits,
            size=variant.coefficient_count,
            dtype=np.uint16,
        )
        uniform_standard.append(_encode(uniform, variant.coefficient_bits))
        uniform_planes.append(_bitplane_encode(uniform, variant.coefficient_bits))
        uniform_field = rng.integers(0, Q, size=variant.coefficient_count, dtype=np.uint16)
        field_compressed = _compress_field(uniform_field, variant.coefficient_bits)
        all_field_compressed_values.append(field_compressed)
        uniform_field_compressed_standard.append(
            _encode(field_compressed, variant.coefficient_bits)
        )
    values = np.concatenate(all_real_values)
    field_values = np.concatenate(all_field_compressed_values)
    streams = {
        "real_standard": b"".join(real_standard),
        "real_bitplane": b"".join(real_planes),
        "real_coefficient_routed": b"".join(real_routed),
        "uniform_standard": b"".join(uniform_standard),
        "uniform_bitplane": b"".join(uniform_planes),
        "uniform_field_through_compress_standard": b"".join(
            uniform_field_compressed_standard
        ),
    }
    baseline_seed = 0xC451 + seed
    bit_biases = np.mean(
        ((values[:, None] >> np.arange(variant.coefficient_bits, dtype=np.uint16)) & 1), axis=0
    )
    return {
        "seed": seed,
        "successful_decapsulations": int(roundtrips),
        "exact_standard_repacks": int(exact_repacks),
        "bitcount_identity_operations": int(bitcount_identities),
        "route_check": route_check,
        "coefficient_entropy_bits": _entropy(values, 1 << variant.coefficient_bits),
        "maximum_coefficient_entropy_bits": float(variant.coefficient_bits),
        "real_distribution_fit": _distribution_fit(values, variant.coefficient_bits),
        "uniform_field_control_fit": _distribution_fit(
            field_values, variant.coefficient_bits
        ),
        "bitplane_one_frequencies": [float(value) for value in bit_biases],
        "measurements": {name: _measure(stream, baseline_seed) for name, stream in streams.items()},
    }


def _variant_run(variant: Variant, operations: int, seeds: int) -> dict[str, Any]:
    records = [_seed_run(variant, operations, 42 + 7919 * index) for index in range(seeds)]
    stream_names = list(records[0]["measurements"])
    summaries = {
        stream: {metric: _summary(records, stream, metric) for metric in ("casi", "f8_output_rate")}
        for stream in stream_names
    }
    effects = {}
    for metric in ("casi", "f8_output_rate"):
        effects[f"real_standard_minus_bitplane_{metric}"] = _paired_test(
            summaries["real_standard"][metric]["values"],
            summaries["real_bitplane"][metric]["values"],
        )
        effects[f"real_standard_minus_routed_{metric}"] = _paired_test(
            summaries["real_standard"][metric]["values"],
            summaries["real_coefficient_routed"][metric]["values"],
        )
        effects[f"uniform_standard_minus_bitplane_{metric}"] = _paired_test(
            summaries["uniform_standard"][metric]["values"],
            summaries["uniform_bitplane"][metric]["values"],
        )
        effects[f"real_minus_uniform_field_compress_{metric}"] = _paired_test(
            summaries["real_standard"][metric]["values"],
            summaries["uniform_field_through_compress_standard"][metric]["values"],
        )
    return {
        "variant": variant.name,
        "coefficient_bits": variant.coefficient_bits,
        "coefficients_per_operation": variant.coefficient_count,
        "records": records,
        "summaries": summaries,
        "paired_intervention_tests": effects,
        "all_functional_gates_passed": all(
            record["successful_decapsulations"] == operations for record in records
        ),
        "all_repack_gates_passed": all(record["exact_standard_repacks"] == operations for record in records),
        "all_bitcount_identity_gates_passed": all(
            record["bitcount_identity_operations"] == operations for record in records
        ),
    }


def _graph(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="mlkem_causal_serialization_suite", parameters=parameters)
    for result in results:
        variant = result["variant"]
        builder.add_triplet(
            edge_id=f"{variant}-bit-bijection",
            trigger=f"{variant}:compressed_coefficient_vector",
            mechanism="bijective_bitplane_serialization",
            outcome="same_bits_same_length",
            confidence=1.0,
            evidence_kind="exact_identity_verified_all_operations",
            source=source,
            attrs={
                "all_repacks_exact": result["all_repack_gates_passed"],
                "all_bitcounts_equal": result["all_bitcount_identity_gates_passed"],
            },
        )
        fits = [record["real_distribution_fit"] for record in result["records"]]
        mean_tv = float(
            np.mean([fit["tv_observed_to_uniform_field_compress"] for fit in fits])
        )
        builder.add_triplet(
            edge_id=f"{variant}-quantizer-occupancy",
            trigger="uniform_field_element_in_Zq",
            mechanism=f"Compress_{result['coefficient_bits']}_unequal_preimage_counts",
            outcome=f"{variant}:observed_compressed_symbol_distribution",
            confidence=max(0.0, 1.0 - mean_tv),
            evidence_kind="algebraic_quantizer_model_and_empirical_fit",
            source=source,
            attrs={
                "mean_tv_observed_to_theory": mean_tv,
                "mean_reduced_chi_square": float(
                    np.mean([fit["reduced_chi_square"] for fit in fits])
                ),
                "theoretical_tv_to_uniform_output": fits[0][
                    "tv_theoretical_compress_to_uniform_output_alphabet"
                ],
                "preimages_per_output_symbol": fits[0]["preimages_per_output_symbol"],
            },
        )
        for metric in ("casi", "f8_output_rate"):
            test = result["paired_intervention_tests"][f"real_standard_minus_bitplane_{metric}"]
            builder.add_triplet(
                edge_id=f"{variant}-serialization-{metric}",
                trigger=f"{variant}:same_compressed_coefficients",
                mechanism="change_only_bit_locality",
                outcome=f"{metric}_change",
                confidence=1.0 - float(test["two_sided_p"]),
                evidence_kind="paired_representation_intervention",
                source=source,
                attrs=test,
            )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--operations", type=int, default=500)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--variants", nargs="*", default=[variant.name for variant in VARIANTS])
    args = parser.parse_args()
    if args.operations < 32 or args.seeds < 2:
        raise ValueError("operations >= 32 and seeds >= 2 required")
    known = {variant.name: variant for variant in VARIANTS}
    unknown = sorted(set(args.variants) - set(known))
    if unknown:
        raise ValueError(f"unknown variants: {', '.join(unknown)}")
    parameters = {"operations": args.operations, "seeds": args.seeds, "variants": args.variants}
    results = []
    for name in args.variants:
        print(f"ML-KEM causal serialization: {name}", flush=True)
        results.append(_variant_run(known[name], args.operations, args.seeds))
    payload = {
        "schema_version": 1,
        "experiment": "mlkem_causal_serialization_suite",
        "parameters": parameters,
        "environment": {"python": sys.version.split()[0], "numpy": np.__version__, "platform": platform.platform()},
        "formulae": {
            "standard": "concatenate coefficient bits little-endian at width d",
            "bitplane": "concatenate all bit j values before bit j+1; a permutation of the same bits",
            "causal_identification": "same values + same bits + same length; only serialization locality changes",
        },
        "results": results,
        "scope_note": (
            "This isolates sensitivity of CASI/F8-O to bijective serialization. It does not observe pre-compression "
            "ML-KEM coefficients and makes no IND-CPA/IND-CCA or key-recovery claim."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    source = "sha256:" + hashlib.sha256(args.output.read_bytes()).hexdigest()
    stats = _graph(results, parameters, source, args.causal_output)
    print(f"wrote {args.output}")
    print(f"wrote {args.causal_output} ({stats['triplets']} triplets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

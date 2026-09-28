"""Deterministic Value-of-Information-Like (VIL) scoring for shadow intake.

VIL ranks already-safe candidate evidence.  It does not grant authority and it
does not decide whether an action may run.
"""
from __future__ import annotations

import math
from typing import Mapping


class VILError(ValueError):
    pass


DEFAULT_SIGNAL_WEIGHTS = {
    "relevance": 0.35,
    "source_quality": 0.25,
    "freshness": 0.20,
    "actionability": 0.20,
}

DEFAULT_VERIFIABILITY_WEIGHTS = {
    "traceability": 0.45,
    "completeness": 0.35,
    "corroboration": 0.20,
}

DEFAULT_THRESHOLDS = {"retain": 0.75, "queue": 0.45}


def _validated_scores(values: Mapping[str, float], expected: set[str]) -> dict[str, float]:
    if set(values) != expected:
        raise VILError("score dimensions do not match the configured model")
    result: dict[str, float] = {}
    for name, value in values.items():
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
            raise VILError(f"{name} must be a finite number from 0 to 1")
        result[name] = float(value)
    return result


def _validated_weights(weights: Mapping[str, float], expected: set[str]) -> dict[str, float]:
    checked = _validated_scores(weights, expected)
    if not math.isclose(sum(checked.values()), 1.0, rel_tol=0, abs_tol=1e-9):
        raise VILError("weights must sum to 1")
    return checked


def assess(
    signal: Mapping[str, float],
    verifiability: Mapping[str, float],
    *,
    signal_weights: Mapping[str, float] = DEFAULT_SIGNAL_WEIGHTS,
    verifiability_weights: Mapping[str, float] = DEFAULT_VERIFIABILITY_WEIGHTS,
    thresholds: Mapping[str, float] = DEFAULT_THRESHOLDS,
) -> dict:
    """Return the explicit component scores, limiting score, and intake route."""
    signal_values = _validated_scores(signal, set(DEFAULT_SIGNAL_WEIGHTS))
    verification_values = _validated_scores(verifiability, set(DEFAULT_VERIFIABILITY_WEIGHTS))
    sw = _validated_weights(signal_weights, set(DEFAULT_SIGNAL_WEIGHTS))
    vw = _validated_weights(verifiability_weights, set(DEFAULT_VERIFIABILITY_WEIGHTS))
    if set(thresholds) != {"retain", "queue"}:
        raise VILError("thresholds must define retain and queue")
    retain = thresholds["retain"]
    queue = thresholds["queue"]
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in (retain, queue)):
        raise VILError("thresholds must be finite numbers")
    if not 0 <= queue <= retain <= 1:
        raise VILError("thresholds must satisfy 0 <= queue <= retain <= 1")

    weighted_signal = round(sum(signal_values[k] * sw[k] for k in sw), 6)
    weighted_verifiability = round(sum(verification_values[k] * vw[k] for k in vw), 6)
    final = round(min(weighted_signal, weighted_verifiability), 6)
    route = "retained" if final >= retain else "pending" if final >= queue else "rejected"
    return {
        "model": "vil-v0.2-shadow-intake-profile",
        "signal": signal_values,
        "signal_weights": sw,
        "weighted_signal": weighted_signal,
        "verifiability": verification_values,
        "verifiability_weights": vw,
        "weighted_verifiability": weighted_verifiability,
        "final": final,
        "limiting_dimension": "signal" if weighted_signal <= weighted_verifiability else "verifiability",
        "thresholds": {"retain": float(retain), "queue": float(queue)},
        "route": route,
    }

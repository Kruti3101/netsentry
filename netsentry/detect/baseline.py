"""EWMA mean/variance baselines with z-scoring.

Each (service, metric) pair keeps an exponentially weighted mean and variance
(West/Finch incremental form). Windows judged anomalous are *not* folded into
the baseline, so an ongoing attack cannot teach the model that the attack is
normal. If the shift persists for ``max_freeze_windows`` the baseline resumes
learning, which lets genuine regime changes (new release, migration) settle.
"""
from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class EWMA:
    alpha: float
    mean: float = 0.0
    var: float = 0.0
    n: int = 0

    def update(self, x: float) -> None:
        if self.n == 0:
            self.mean, self.var = x, 0.0
        else:
            diff = x - self.mean
            incr = self.alpha * diff
            self.mean += incr
            self.var = (1 - self.alpha) * (self.var + diff * incr)
        self.n += 1

    def std(self, rel_floor: float, abs_floor: float = 1.0) -> float:
        return max(math.sqrt(max(self.var, 0.0)), rel_floor * abs(self.mean), abs_floor)

    def zscore(self, x: float, rel_floor: float, abs_floor: float = 1.0) -> float:
        return (x - self.mean) / self.std(rel_floor, abs_floor)


class ServiceBaseline:
    """Baselines for every tracked metric of one service."""

    def __init__(self, metrics: list[str], alpha: float, warmup: int, rel_floor: float, max_freeze: int):
        self.models = {m: EWMA(alpha) for m in metrics}
        self.warmup = warmup
        self.rel_floor = rel_floor
        self.max_freeze = max_freeze
        self.frozen_for = 0

    @property
    def ready(self) -> bool:
        return next(iter(self.models.values())).n >= self.warmup

    def score(self, vec: dict[str, float]) -> dict[str, float] | None:
        if not self.ready:
            return None
        return {m: self.models[m].zscore(vec[m], self.rel_floor) for m in self.models}

    def observe(self, vec: dict[str, float], anomalous: bool) -> None:
        if anomalous and self.ready:
            self.frozen_for += 1
            if self.frozen_for <= self.max_freeze:
                return
        else:
            self.frozen_for = 0
        for m, model in self.models.items():
            model.update(vec[m])

    def snapshot(self) -> dict[str, dict[str, float]]:
        return {
            m: {"mean": round(e.mean, 3), "std": round(e.std(self.rel_floor), 3), "n": e.n}
            for m, e in self.models.items()
        }

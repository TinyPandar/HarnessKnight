"""Rule-detector metrics on public injection data; not Agent ASR.

Default: committed sample. ``--full`` scores every cached full set
(run eval/fetch_public_injection.py first).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "eval"))

from uuid import uuid4

from public_injection_sources import BY_ID

from security_harness.agentguard.detection_v2 import DETECTOR_VERSION, detect_indirect


def new_id(): return uuid4().hex

SAMPLE = ROOT / "eval/agentguard/cases/public_injection_sample_v1.json"
CACHE = ROOT / "eval/.cache/public_injection"


def _metrics(c: dict) -> dict:
    tp, fn, fp, tn = c["tp"], c["fn"], c["fp"], c["tn"]
    return {
        "confusion": c,
        "n": tp + fn + fp + tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "fpr": fp / (fp + tn) if fp + tn else None,
    }


def score(cases) -> dict:
    per: dict[str, dict] = {}
    total = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    misses = []
    for item in cases:
        try:
            _, finding = detect_indirect(
                item["text"],
                new_id(),
                new_id(),
                attack_source=item.get("attack_source", "INDIRECT"),
            )
            detected = finding is not None
        except Exception:  # scan limit etc. -> treated as flagged (fail closed)
            detected = True
        key = ("tp" if detected else "fn") if item["attack"] else ("fp" if detected else "tn")
        for bucket in (per.setdefault(item["source"], dict.fromkeys(total, 0)), total):
            bucket[key] += 1
        if key in {"fn", "fp"} and len(misses) < 200:
            misses.append({"id": item["id"], "outcome": key.upper()})
    return {
        "detector_version": DETECTOR_VERSION,
        "evaluation_scope": "rule_detector_only_not_agent_asr",
        "overall": _metrics(total),
        "per_source": {k: _metrics(v) for k, v in sorted(per.items())},
        "errors_sample": misses,
    }


def evaluate_sample() -> dict:
    raw = SAMPLE.read_bytes()
    data = json.loads(raw)
    ids = [c["id"] for c in data["cases"]]
    if len(ids) != len(set(ids)):
        raise ValueError("DUPLICATE_CASE_ID")
    report = score(data["cases"])
    report.update(dataset_id=data["dataset_id"], dataset_sha256=hashlib.sha256(raw).hexdigest())
    return report


def evaluate_full(split: str = "heldout") -> dict:
    cases = []
    base = CACHE / "tune" if split == "tune" else CACHE
    for path in sorted(base.glob("*.jsonl")):
        sid = path.stem
        for i, line in enumerate(path.read_text("utf-8").split("\n")):
            if not line:
                continue
            row = json.loads(line)
            cases.append(
                {
                    "id": f"{sid}:{i}",
                    "source": sid,
                    "attack_source": BY_ID[sid].attack_source,
                    **row,
                }
            )
    report = score(cases)
    report["dataset_id"] = f"public-injection-full-{split}"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--split", choices=("heldout", "tune"), default="heldout")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    report = evaluate_full(args.split) if args.full else evaluate_sample()
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, "utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

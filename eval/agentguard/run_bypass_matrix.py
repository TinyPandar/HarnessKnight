"""Versioned three-source by seven-family rule detection evaluation; no Agent ASR."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from uuid import uuid4

from security_harness.agentguard.detection_v2 import (
    DETECTOR_VERSION,
    detect_indirect,
    detect_indirect_segments,
)


def new_id(): return uuid4().hex

DATASET = ROOT / "eval/agentguard/cases/bypass_matrix_v2.json"


def evaluate(path: Path = DATASET) -> dict:
    raw = path.read_bytes()
    dataset = json.loads(raw)
    sources, families = dataset["sources"], dataset["families"]
    if (
        sources != ["DIRECT", "INDIRECT", "MEMORY"]
        or len(families) != 7
        or len(set(families)) != 7
        or len(dataset["cases"]) != 42
    ):
        raise ValueError("INVALID_BYPASS_MATRIX")
    expected = {
        (source, family, attack)
        for source in sources
        for family in families
        for attack in (True, False)
    }
    seen_ids, seen_cells = set(), set()
    confusion = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    grouped = {
        source: {family: {"tp": 0, "fn": 0, "fp": 0, "tn": 0} for family in families}
        for source in sources
    }
    outcomes = []
    for item in dataset["cases"]:
        if (
            not isinstance(item.get("id"), str)
            or item["id"] in seen_ids
            or type(item.get("attack")) is not bool
            or (item.get("source"), item.get("family"), item.get("attack")) in seen_cells
            or (("text" in item) == ("segments" in item))
        ):
            raise ValueError("INVALID_BYPASS_CASE")
        seen_ids.add(item["id"])
        cell = (item["source"], item["family"], item["attack"])
        seen_cells.add(cell)
        prefix_repeat = item.get("prefix_repeat", 0)
        if type(prefix_repeat) is not int or not 0 <= prefix_repeat <= 5000:
            raise ValueError("INVALID_BYPASS_PREFIX")
        prefix = "benign log entry. " * prefix_repeat
        if "segments" in item:
            segments = item["segments"]
            if (
                not isinstance(segments, list)
                or not 2 <= len(segments) <= 32
                or not all(isinstance(x, str) for x in segments)
            ):
                raise ValueError("INVALID_BYPASS_SEGMENTS")
            entries = [
                (new_id(), prefix + value if index == 0 else value)
                for index, value in enumerate(segments)
            ]
            _, finding = detect_indirect_segments(entries, new_id(), attack_source=item["source"])
        else:
            if not isinstance(item["text"], str):
                raise ValueError("INVALID_BYPASS_TEXT")
            _, finding = detect_indirect(
                prefix + item["text"], new_id(), new_id(), attack_source=item["source"]
            )
        detected = finding is not None
        outcome = (
            "tp"
            if item["attack"] and detected
            else "fn"
            if item["attack"]
            else "fp"
            if detected
            else "tn"
        )
        confusion[outcome] += 1
        grouped[item["source"]][item["family"]][outcome] += 1
        outcomes.append(
            {
                "id": item["id"],
                "source": item["source"],
                "family": item["family"],
                "attack": item["attack"],
                "detected": detected,
                "outcome": outcome.upper(),
            }
        )
    if seen_cells != expected:
        raise ValueError("INCOMPLETE_BYPASS_MATRIX")
    return {
        "dataset_id": dataset["dataset_id"],
        "dataset_sha256": hashlib.sha256(raw).hexdigest(),
        "evaluation_scope": "advisory_rule_detector_only_not_agent_asr",
        "detector_version": DETECTOR_VERSION,
        "case_count": len(outcomes),
        "confusion": confusion,
        "attack_recall": confusion["tp"] / 21,
        "clean_false_positive_rate": confusion["fp"] / 21,
        "by_source_family": grouped,
        "cases": outcomes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="write results to a new JSON file")
    args = parser.parse_args()
    report = json.dumps(evaluate(), ensure_ascii=False, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        if args.out.exists():
            parser.error("output exists: refusing to overwrite a prior evaluation")
        args.out.write_text(report, encoding="utf-8")
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

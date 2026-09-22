from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
import unicodedata
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPO_URL = (
    "https://huggingface.co/datasets/rogue-security/"
    "prompt-injections-benchmark/resolve/main/test.csv?download=true"
)
ALLOWED_LABELS = {"jailbreak", "benign"}


def read_token(env_path: Path) -> str:
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or not line.startswith("HF_TOKEN"):
            continue
        key, sep, value = line.partition("=")
        if sep and key.strip() == "HF_TOKEN":
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if value:
                return value
    raise RuntimeError(".env 中未找到非空 HF_TOKEN")


def normalize(value: str) -> str:
    value = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"\s+", " ", value).strip()


def download(token: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = Request(REPO_URL, headers={"Authorization": f"Bearer {token}"})
    try:
        with urlopen(request, timeout=60) as response:
            destination.write_bytes(response.read())
    except HTTPError as exc:
        if exc.code in {401, 403}:
            raise RuntimeError(
                f"Hugging Face 返回 HTTP {exc.code}：Token 无效，或尚未接受该数据集访问条件"
            ) from exc
        raise RuntimeError(f"Hugging Face 下载失败：HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"Hugging Face 网络访问失败：{exc.reason}") from exc


def prepare(source: Path, output: Path, report_path: Path) -> dict[str, object]:
    raw = source.read_bytes()
    source_sha256 = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8-sig")
    reader = csv.DictReader(text.splitlines())
    fields = reader.fieldnames or []
    required = {"text", "label"}
    missing = sorted(required - set(fields))
    if missing:
        raise RuntimeError(f"源 CSV 缺少必需列：{', '.join(missing)}；实际列：{fields}")

    rows: list[tuple[str, str]] = []
    total = empty_text = invalid_label = malformed = 0
    groups: dict[str, set[str]] = {}
    for row in reader:
        total += 1
        value = row.get("text")
        label = (row.get("label") or "").strip().casefold()
        if value is None:
            malformed += 1
            continue
        value = value.strip()
        if not value:
            empty_text += 1
            continue
        if label not in ALLOWED_LABELS:
            invalid_label += 1
            continue
        normalized = normalize(value)
        if not normalized:
            empty_text += 1
            continue
        groups.setdefault(normalized, set()).add(label)
        rows.append((value, label))

    conflicts = {key for key, labels in groups.items() if len(labels) > 1}
    unique: dict[tuple[str, str], str] = {}
    duplicate_count = 0
    for value, label in rows:
        key = (normalize(value), label)
        if key in unique:
            duplicate_count += 1
        else:
            unique[key] = value

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["text", "label"])
        for (normalized, label), value in sorted(unique.items(), key=lambda item: item[0]):
            if normalized not in conflicts:
                writer.writerow([value, label])

    report = {
        "source": "rogue-security/prompt-injections-benchmark",
        "source_file": "test.csv",
        "source_sha256": source_sha256,
        "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "normalization": "normalize-v1: NFKC, casefold, whitespace collapse, trim",
        "source_columns": fields,
        "output_columns": ["text", "label"],
        "total_rows": total,
        "valid_rows": len(rows),
        "output_rows": sum(1 for key in unique if key[0] not in conflicts),
        "empty_text_rows": empty_text,
        "invalid_label_rows": invalid_label,
        "malformed_rows": malformed,
        "duplicate_rows": duplicate_count,
        "label_conflict_groups": len(conflicts),
        "jailbreak_unique": sum(1 for (key, label) in unique if label == "jailbreak" and key not in conflicts),
        "benign_unique": sum(1 for (key, label) in unique if label == "benign" and key not in conflicts),
        "license": "CC BY-NC 4.0",
    }
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    data_dir = root / "data" / "datasets" / "rogue-security" / "prompt-injections-benchmark"
    source = data_dir / "source_test.csv"
    output = data_dir / "prompt-injections-benchmark.csv"
    report_path = data_dir / "load_report.json"
    token = read_token(root / ".env")
    download(token, source)
    report = prepare(source, output, report_path)
    print(json.dumps({k: v for k, v in report.items() if k != "source_sha256"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)

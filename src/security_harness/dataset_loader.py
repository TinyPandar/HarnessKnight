from __future__ import annotations

import csv
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .prompt_matcher import normalize


class DatasetLoadError(ValueError):
    pass


@dataclass(frozen=True)
class DatasetLoadReport:
    path: str
    file_sha256: str
    total_rows: int
    valid_rows: int
    empty_texts: int
    invalid_labels: int
    overlong_texts: int
    duplicate_rows: int
    label_conflicts: int
    jailbreak_index_size: int
    benign_unique: int
    columns: tuple[str, ...]
    normalization_version: str = "normalize-v1"

    def to_dict(self) -> dict:
        return {"path": self.path, **self.__dict__, "columns": list(self.columns)}


@dataclass(frozen=True)
class DatasetIndex:
    jailbreak: frozenset[str]
    benign: frozenset[str]
    report: DatasetLoadReport


def load_dataset(path: str | Path, *, strict: bool = True, max_text_length: int = 32_768, max_bad_rows: int = 100) -> DatasetIndex:
    file_path = Path(path)
    if not file_path.is_file():
        raise DatasetLoadError(f"dataset file does not exist: {file_path}")
    raw = file_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise DatasetLoadError("dataset must be UTF-8 or UTF-8-BOM CSV") from exc
    try:
        reader = csv.DictReader(text.splitlines())
        columns = tuple(reader.fieldnames or ())
    except csv.Error as exc:
        raise DatasetLoadError(f"invalid CSV header: {exc}") from exc
    if "text" not in columns or "label" not in columns:
        raise DatasetLoadError("dataset must contain text and label columns")
    groups: dict[str, set[str]] = {}
    total = valid = empty = invalid = overlong = duplicates = conflicts = 0
    bad_rows = 0
    for row in reader:
        total += 1
        value = row.get("text")
        label = (row.get("label") or "").strip().casefold()
        if not isinstance(value, str) or not value.strip():
            empty += 1; bad_rows += 1
            if strict: raise DatasetLoadError(f"empty text at row {total + 1}")
            continue
        if len(value) > max_text_length:
            overlong += 1; bad_rows += 1
            if strict: raise DatasetLoadError(f"text exceeds {max_text_length} characters at row {total + 1}")
            continue
        if label not in {"jailbreak", "benign"}:
            invalid += 1; bad_rows += 1
            if strict: raise DatasetLoadError(f"invalid label at row {total + 1}: {label!r}")
            continue
        normalized = normalize(value)
        labels = groups.setdefault(normalized, set())
        if label in labels: duplicates += 1
        labels.add(label); valid += 1
        if len(labels) > 1: conflicts += 1
        if bad_rows > max_bad_rows: raise DatasetLoadError(f"too many invalid rows: > {max_bad_rows}")
    jailbreak = frozenset(k for k, labels in groups.items() if labels == {"jailbreak"})
    benign = frozenset(k for k, labels in groups.items() if "benign" in labels)
    report = DatasetLoadReport(str(file_path), digest, total, valid, empty, invalid, overlong, duplicates, conflicts, len(jailbreak), len(benign), columns)
    return DatasetIndex(jailbreak, benign, report)


"""Small mapping-style finding value used by the vendored detector."""
from collections.abc import Mapping
from typing import Any


class DetectionFinding(Mapping):
    def __init__(self, data: dict[str, Any]):
        self.data = dict(data)
    def __getitem__(self, key): return self.data[key]
    def __iter__(self): return iter(self.data)
    def __len__(self): return len(self.data)
    def to_dict(self): return dict(self.data)
    def __getattr__(self, name):
        try: return self.data[name]
        except KeyError as exc: raise AttributeError(name) from exc

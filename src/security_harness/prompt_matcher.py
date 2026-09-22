from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from .domain import Decision, HandlerResult, HarnessError, RiskSignal, SecurityEvent

NORMALIZATION_VERSION = "normalize-v1"


def normalize(value: str) -> str:
    value = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"\s+", " ", value).strip()


@dataclass(frozen=True)
class PhraseRule:
    rule_id: str
    phrase: str
    enabled: bool = True
    description: str = ""
    version: str = "rules-v1"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PhraseRule":
        rule_id = str(raw.get("rule_id", "")).strip(); phrase = normalize(str(raw.get("phrase", "")))
        if not rule_id or not phrase or len(phrase) < 3: raise ValueError("rule_id and a non-trivial phrase are required")
        return cls(rule_id, phrase, bool(raw.get("enabled", True)), str(raw.get("description", "")), str(raw.get("version", "rules-v1")))


class PromptStringMatchHandler:
    name = "prompt_string_match"

    def __init__(self, jailbreak: frozenset[str], rules: tuple[PhraseRule, ...] = (), *, max_prompt_length: int = 32_768, dataset_sha256: str = "", rules_version: str = "rules-v1"):
        self.jailbreak, self.rules, self.max_prompt_length = jailbreak, rules, max_prompt_length
        self.dataset_sha256 = dataset_sha256; self.rules_version = rules_version
        if len(rules) > 50: raise ValueError("at most 50 phrase rules are supported")

    async def execute(self, event: SecurityEvent):
        if event.event_type != "user.prompt.submitted":
            return HandlerResult(self.name, "SKIPPED", 0, decision=Decision.ALLOW), []
        prompt = event.payload.get("prompt")
        if not isinstance(prompt, str): raise HarnessError("INVALID_PROMPT", "payload.prompt must be a string")
        if len(prompt) > self.max_prompt_length:
            return HandlerResult(self.name, "SUCCEEDED", 0, decision=Decision.REVIEW), [RiskSignal("PROMPT_TOO_LARGE", "WARN", "提示词超过扫描长度上限，需要人工研判")]
        normalized = normalize(prompt); signals: list[RiskSignal] = []
        if normalized in self.jailbreak:
            signals.append(RiskSignal("PROMPT_EXACT_MATCH", "WARN", "与已加载的对抗样本完全匹配"))
        for rule in self.rules:
            if rule.enabled and rule.phrase in normalized:
                signals.append(RiskSignal(f"PROMPT_PHRASE:{rule.rule_id}", "WARN", "命中人工维护的提示词短语规则"))
        return HandlerResult(self.name, "SUCCEEDED", 0, decision=Decision.REVIEW if signals else Decision.ALLOW), signals


def load_phrase_rules(path: str | None) -> tuple[PhraseRule, ...]:
    if not path: return ()
    import json
    from pathlib import Path
    try: raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: raise ValueError(f"cannot read rules file: {path}") from exc
    if not isinstance(raw, list): raise ValueError("rules file must contain a JSON list")
    return tuple(PhraseRule.from_dict(item) for item in raw)

from __future__ import annotations
import argparse, csv, hashlib, json, pathlib, sys, asyncio
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from security_harness.dataset_loader import load_dataset
from security_harness.domain import AgentIdentity, SecurityEvent
from security_harness.prompt_matcher import PromptStringMatchHandler, load_phrase_rules

async def evaluate(args):
    index = load_dataset(args.dataset, strict=not args.lenient)
    rules = load_phrase_rules(args.rules)
    counts = {"jailbreak": {"exact": 0, "phrase": 0, "no_match": 0}, "benign": {"exact": 0, "phrase": 0, "no_match": 0}}
    holdout = {"jailbreak": {"exact": 0, "phrase": 0, "no_match": 0}, "benign": {"exact": 0, "phrase": 0, "no_match": 0}}
    rows = []; seen = set(); groups = {}
    with open(args.dataset, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            label = row["label"].strip().casefold(); prompt = row["text"]
            normalized = __import__("security_harness.prompt_matcher", fromlist=["normalize"]).normalize(prompt)
            if normalized in seen: continue
            seen.add(normalized); groups.setdefault(normalized, set()).add(label); rows.append((normalized, prompt, label))
    dev_jailbreak = frozenset(normalized for normalized, _, label in rows if label == "jailbreak" and len(groups[normalized]) == 1 and int(hashlib.sha256(normalized.encode()).hexdigest()[:8], 16) % 100 < 80)
    handler = PromptStringMatchHandler(dev_jailbreak, rules, dataset_sha256=index.report.file_sha256)
    for seq, (normalized, prompt, label) in enumerate(rows, 1):
            event = SecurityEvent.from_dict({"event_id": __import__("uuid").uuid4().__str__(), "idempotency_key": f"eval-{seq}", "event_type": "user.prompt.submitted", "seq": seq, "occurred_at": "2026-01-01T00:00:00Z", "agent": {"agent_id": "dataset-eval"}, "session_id": "evaluation", "payload": {"prompt": prompt}, "metadata": {}})
            result, signals = await handler.execute(event); codes = [s.code for s in signals]
            bucket = "exact" if "PROMPT_EXACT_MATCH" in codes else "phrase" if any(x.startswith("PROMPT_PHRASE:") for x in codes) else "no_match"
            counts[label][bucket] += 1
            is_test = int(hashlib.sha256(normalized.encode()).hexdigest()[:8], 16) % 100 >= 80
            if is_test: holdout[label][bucket] += 1
    positive = holdout["jailbreak"]["exact"] + holdout["jailbreak"]["phrase"]
    false_negative = holdout["jailbreak"]["no_match"]
    false_positive = holdout["benign"]["exact"] + holdout["benign"]["phrase"]
    out = {"dataset": index.report.to_dict(), "rules_path": args.rules, "normalization": "normalize-v1", "index_replay": counts, "holdout_80_20": holdout, "holdout_confusion": {"true_positive": positive, "false_negative": false_negative, "false_positive": false_positive, "true_negative": holdout["benign"]["no_match"]}, "interpretation": "Index replay is functionality evidence. Holdout results measure this exact-string/phrase configuration on a stable split, not generalized prompt-injection accuracy."}
    print(json.dumps(out, ensure_ascii=False, indent=2))

def main():
    p=argparse.ArgumentParser(); p.add_argument("dataset"); p.add_argument("--rules"); p.add_argument("--lenient", action="store_true"); args=p.parse_args(); asyncio.run(evaluate(args))
if __name__ == "__main__": main()

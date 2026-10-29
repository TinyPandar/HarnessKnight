from __future__ import annotations
from dataclasses import dataclass
from .audit import AuditRepository
from .dataset_loader import DatasetLoadError, load_dataset
from .pipeline import MockRuleHandler, ObservationHandler, Pipeline
from .prompt_matcher import PromptStringMatchHandler, load_phrase_rules
from .runtime import Runtime
from .indirect_detector import IndirectInjectionHandler
from .taint import TaintPropagationHandler

@dataclass(frozen=True)
class HarnessConfig:
    db: str = "data/audit.db"
    mode: str = "observe"
    dataset_path: str | None = None
    rules_path: str | None = None
    policy_path: str | None = None
    concurrency: int = 32
    request_timeout_ms: int = 3000
    handler_timeout_ms: int = 1000
    queue_wait_timeout_ms: int = 500
    fail_mode: str = "fail_review"
    indirect_detection: bool = True

def build_runtime(config: HarnessConfig) -> Runtime:
    handlers = []
    dataset_report = None
    if config.mode == "stage2":
        if not config.dataset_path: raise DatasetLoadError("dataset_path is required in stage2 mode")
        index = load_dataset(config.dataset_path)
        handlers.append(PromptStringMatchHandler(index.jailbreak,load_phrase_rules(config.rules_path),dataset_sha256=index.report.file_sha256))
        dataset_report = index.report.to_dict()
    elif config.mode == "stage1": handlers.append(MockRuleHandler())
    elif config.mode == "observe": handlers.append(ObservationHandler())
    elif config.mode != "protect": raise ValueError("unknown harness mode")
    if config.indirect_detection: handlers.extend((IndirectInjectionHandler(), TaintPropagationHandler()))
    if config.policy_path:
        from .policy import load_policy
        handlers.append(load_policy(config.policy_path))
    if not handlers: raise ValueError("protect mode requires a policy or injected detectors")
    pipeline = Pipeline(handlers=handlers,handler_timeout_ms=config.handler_timeout_ms)
    # Validate runtime settings before opening a database.
    if config.concurrency < 1 or min(config.request_timeout_ms,config.queue_wait_timeout_ms) <= 0 or config.fail_mode not in {"fail_open","fail_closed","fail_review"}:
        raise ValueError("invalid runtime settings")
    runtime = Runtime(AuditRepository(config.db),pipeline=pipeline,concurrency=config.concurrency,
                      request_timeout_ms=config.request_timeout_ms,queue_wait_timeout_ms=config.queue_wait_timeout_ms,fail_mode=config.fail_mode)
    runtime.mode, runtime.dataset_report = config.mode, dataset_report
    return runtime

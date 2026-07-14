from enum import Enum


class ScanMode(str, Enum):
    REPO_SCAN = "repo_scan"
    DIFF_SCAN = "diff_scan"


class ProfileScope(str, Enum):
    FULL_REPO = "full_repo"
    DIFF_ENRICHED = "diff_enriched"
    DIFF_ONLY = "diff_only"


class AuditStageName(str, Enum):
    SECRET = "secret"
    INJECTION = "injection"
    COMMAND = "command"
    FILE = "file"
    AUTH = "auth"


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"
    BUDGET_EXHAUSTED = "budget_exhausted"


class ToolCallStatus(str, Enum):
    PENDING = "pending"
    VALIDATED = "validated"
    REJECTED = "rejected"
    RUNNING = "running"
    SUCCESS = "success"
    SKIPPED = "skipped"
    FALLBACK = "fallback"
    TIMEOUT = "timeout"
    ERROR = "error"


class AuditDecisionType(str, Enum):
    CALL_TOOL = "CALL_TOOL"
    EMIT_FINDING = "EMIT_FINDING"
    FINISH_STAGE = "FINISH_STAGE"


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    MERGED = "merged"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"
    NEEDS_REVIEW = "needs_review"
    REPORTED = "reported"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

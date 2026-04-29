import json
import re
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_KNOWLEDGE_BASE = PROJECT_ROOT / "knowledge"

ACTIVE_STATUSES = {"candidate", "active_low_confidence", "active", "active_high_confidence"}
CONFIDENCE_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _safe_repo_id(repo_id: Optional[str]) -> str:
    if not repo_id:
        return "unknown_repo"
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", repo_id.strip())
    return safe.strip("._") or "unknown_repo"


def _knowledge_base_path(knowledge_base_path: Optional[str] = None) -> Path:
    return Path(knowledge_base_path).expanduser() if knowledge_base_path else DEFAULT_KNOWLEDGE_BASE


def _experience_file(scope: str, repo_id: Optional[str], knowledge_base_path: Optional[str] = None) -> Path:
    base = _knowledge_base_path(knowledge_base_path)
    if scope == "global":
        return base / "global" / "experiences.jsonl"
    return base / "repos" / _safe_repo_id(repo_id) / "experiences.jsonl"


def _normalize_cwe(cwe: Optional[str]) -> Optional[str]:
    if cwe is None:
        return None
    raw = str(cwe).strip()
    if not raw:
        return None
    if raw.upper().startswith("CWE-"):
        return raw.upper()
    if raw.isdigit():
        return f"CWE-{raw}"
    return raw


def _normalize_confidence(confidence: Optional[str]) -> str:
    if not confidence:
        return "low"
    normalized = str(confidence).strip().lower()
    return normalized if normalized in CONFIDENCE_ORDER else "low"


def _normalize_scope(scope: Optional[str]) -> str:
    normalized = (scope or "repo").strip().lower()
    return "global" if normalized == "global" else "repo"


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in {path}:{line_no}: {exc}") from exc
            if isinstance(value, dict):
                records.append(value)
    return records


def _write_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            f.write("\n")
    tmp_path.replace(path)


def _append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
        f.write("\n")


def _required_string(value: Any, field_name: str) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text


def _normalize_experience(pattern: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(pattern, dict):
        raise ValueError("pattern must be a JSON object")

    experience = deepcopy(pattern)
    scope = _normalize_scope(experience.get("scope"))
    repo_id = _required_string(experience.get("repo_id"), "repo_id")
    if scope == "repo" and not repo_id:
        raise ValueError("repo_id is required for repo scoped experience")

    exp_type = _required_string(experience.get("type"), "type") or "call_sanitizer"
    function_name = _required_string(experience.get("function_name"), "function_name")
    matcher = experience.get("matcher")
    if not function_name and isinstance(matcher, dict):
        function_name = _required_string(matcher.get("function_name"), "matcher.function_name")
    if exp_type == "call_sanitizer" and not function_name:
        raise ValueError("function_name is required for call_sanitizer experience")

    now = _utc_now()
    experience["id"] = _required_string(experience.get("id"), "id") or f"exp-{uuid.uuid4().hex}"
    experience["version"] = int(experience.get("version", 1))
    experience["scope"] = scope
    if repo_id:
        experience["repo_id"] = repo_id
    experience["language"] = _required_string(experience.get("language"), "language")
    experience["cwe"] = _normalize_cwe(experience.get("cwe"))
    experience["query_id"] = _required_string(experience.get("query_id"), "query_id")
    experience["type"] = exp_type
    if function_name:
        experience["function_name"] = function_name
    experience["confidence"] = _normalize_confidence(experience.get("confidence"))
    experience["status"] = _required_string(experience.get("status"), "status") or "candidate"
    experience["created_at"] = _required_string(experience.get("created_at"), "created_at") or now
    experience["updated_at"] = now

    evidence = experience.get("evidence")
    experience["evidence"] = evidence if isinstance(evidence, dict) else {}

    validation = experience.get("validation")
    if not isinstance(validation, dict):
        validation = {}
    validation.setdefault("validated_count", 0)
    validation.setdefault("rejected_count", 0)
    validation.setdefault("notes", [])
    experience["validation"] = validation

    return experience


def _matches_optional(record_value: Any, query_value: Optional[str], normalize_cwe: bool = False) -> bool:
    if query_value is None:
        return True
    if record_value in (None, ""):
        return True
    left = _normalize_cwe(record_value) if normalize_cwe else str(record_value).strip().lower()
    right = _normalize_cwe(query_value) if normalize_cwe else str(query_value).strip().lower()
    return left == right


def _load_candidate_files(
    repo_id: Optional[str],
    include_global: bool,
    knowledge_base_path: Optional[str],
) -> List[Path]:
    files = []
    if repo_id:
        files.append(_experience_file("repo", repo_id, knowledge_base_path))
    if include_global:
        files.append(_experience_file("global", None, knowledge_base_path))
    return files


def save_experience_pattern(pattern: Dict[str, Any], knowledge_base_path: Optional[str] = None) -> Dict[str, Any]:
    """Save one LLM learned experience pattern into the JSONL knowledge store."""
    try:
        experience = _normalize_experience(pattern)
        path = _experience_file(experience["scope"], experience.get("repo_id"), knowledge_base_path)
        existing = _read_jsonl(path)
        if any(item.get("id") == experience["id"] for item in existing):
            return {
                "success": False,
                "error": f"experience id already exists: {experience['id']}",
                "experience_id": experience["id"],
                "knowledge_file": str(path),
            }

        _append_jsonl(path, experience)
        return {
            "success": True,
            "experience_id": experience["id"],
            "experience": experience,
            "knowledge_file": str(path),
            "message": "experience pattern saved",
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def load_applicable_experiences(
    repo_id: Optional[str] = None,
    language: Optional[str] = None,
    cwe: Optional[str] = None,
    query_id: Optional[str] = None,
    experience_type: Optional[str] = None,
    function_name: Optional[str] = None,
    min_confidence: str = "low",
    include_global: bool = True,
    include_rejected: bool = False,
    knowledge_base_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Load repo/global experiences that may apply to the current database analysis."""
    try:
        min_rank = CONFIDENCE_ORDER.get(_normalize_confidence(min_confidence), 1)
        files = _load_candidate_files(repo_id, include_global, knowledge_base_path)
        experiences: List[Dict[str, Any]] = []

        for path in files:
            for record in _read_jsonl(path):
                status = str(record.get("status", "")).strip()
                if not include_rejected and status not in ACTIVE_STATUSES:
                    continue
                if CONFIDENCE_ORDER.get(_normalize_confidence(record.get("confidence")), 1) < min_rank:
                    continue
                if not _matches_optional(record.get("language"), language):
                    continue
                if not _matches_optional(record.get("cwe"), cwe, normalize_cwe=True):
                    continue
                if not _matches_optional(record.get("query_id"), query_id):
                    continue
                if not _matches_optional(record.get("type"), experience_type):
                    continue
                if function_name and str(record.get("function_name", "")).strip() != function_name:
                    continue
                record_copy = deepcopy(record)
                record_copy["_knowledge_file"] = str(path)
                experiences.append(record_copy)

        return {
            "success": True,
            "experiences": experiences,
            "count": len(experiences),
            "knowledge_files": [str(path) for path in files],
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def update_experience_validation(
    experience_id: str,
    repo_id: Optional[str] = None,
    scope: str = "repo",
    status: Optional[str] = None,
    confidence: Optional[str] = None,
    validation_result: Optional[str] = None,
    note: Optional[str] = None,
    knowledge_base_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Update validation metadata for a saved experience."""
    try:
        if not experience_id:
            raise ValueError("experience_id is required")

        normalized_scope = _normalize_scope(scope)
        path = _experience_file(normalized_scope, repo_id, knowledge_base_path)
        records = _read_jsonl(path)
        updated_record: Optional[Dict[str, Any]] = None

        for record in records:
            if record.get("id") != experience_id:
                continue

            if status:
                record["status"] = str(status).strip()
            if confidence:
                record["confidence"] = _normalize_confidence(confidence)

            validation = record.get("validation")
            if not isinstance(validation, dict):
                validation = {}
            validation.setdefault("validated_count", 0)
            validation.setdefault("rejected_count", 0)
            validation.setdefault("notes", [])

            normalized_result = str(validation_result or "").strip().lower()
            if normalized_result in {"pass", "passed", "valid", "validated", "accepted"}:
                validation["validated_count"] = int(validation.get("validated_count", 0)) + 1
            elif normalized_result in {"fail", "failed", "invalid", "rejected"}:
                validation["rejected_count"] = int(validation.get("rejected_count", 0)) + 1

            if note:
                validation["notes"].append({"time": _utc_now(), "text": str(note)})

            record["validation"] = validation
            record["updated_at"] = _utc_now()
            updated_record = record
            break

        if updated_record is None:
            return {
                "success": False,
                "error": f"experience not found: {experience_id}",
                "knowledge_file": str(path),
            }

        _write_jsonl(path, records)
        return {
            "success": True,
            "experience_id": experience_id,
            "experience": updated_record,
            "knowledge_file": str(path),
            "message": "experience validation updated",
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}

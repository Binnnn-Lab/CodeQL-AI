import tempfile
import unittest
from pathlib import Path

import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from libs.lib_knowledge import (  # noqa: E402
    load_applicable_experiences,
    save_experience_pattern,
    update_experience_validation,
)


class KnowledgeStoreTest(unittest.TestCase):
    def test_save_load_and_update_repo_experience(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            saved = save_experience_pattern(
                {
                    "scope": "repo",
                    "repo_id": "example/project",
                    "language": "cpp",
                    "cwe": "22",
                    "query_id": "path-injection",
                    "type": "call_sanitizer",
                    "function_name": "strip_parent_traversal",
                    "effect": "remove_parent_traversal_risk",
                    "evidence": {
                        "file": "src/path.c",
                        "reason": "removes '..' from the path buffer",
                    },
                },
                knowledge_base_path=tmp_dir,
            )

            self.assertTrue(saved["success"])
            self.assertEqual(saved["experience"]["confidence"], "low")
            self.assertEqual(saved["experience"]["status"], "candidate")

            loaded = load_applicable_experiences(
                repo_id="example/project",
                language="cpp",
                cwe="CWE-22",
                query_id="path-injection",
                experience_type="call_sanitizer",
                knowledge_base_path=tmp_dir,
            )

            self.assertTrue(loaded["success"])
            self.assertEqual(loaded["count"], 1)
            self.assertEqual(loaded["experiences"][0]["function_name"], "strip_parent_traversal")

            updated = update_experience_validation(
                experience_id=saved["experience_id"],
                repo_id="example/project",
                status="active_low_confidence",
                validation_result="passed",
                note="confirmed on current false positive case",
                knowledge_base_path=tmp_dir,
            )

            self.assertTrue(updated["success"])
            self.assertEqual(updated["experience"]["status"], "active_low_confidence")
            self.assertEqual(updated["experience"]["validation"]["validated_count"], 1)
            self.assertEqual(len(updated["experience"]["validation"]["notes"]), 1)


if __name__ == "__main__":
    unittest.main()

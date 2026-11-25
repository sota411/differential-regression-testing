from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


SKILL = Path(__file__).resolve().parents[1]
GATE = SKILL / "scripts/check_coverage.py"


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


class ExecutionEvidenceTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.plan = json.loads((SKILL / "assets/plan-example.json").read_text())
        self.conditions = json.loads((SKILL / "assets/conditions-example.json").read_text())
        case = self.plan["cases"][0]
        covers = case.pop("covers") if "covers" in case else case["steps"][0]["covers"]
        case["steps"] = [{"id": "request", "target": "words-limit", "values": {"limit": "-1"}, "covers": covers}]
        self.inventory = {"requirements": [
            {"target": "words-limit", "boundary": "other", "values": {"limit": "-1"}, "layer": "direct",
             "field": key, "evidence": f"Published CLI contract §2 {key}"}
            for key in ("process.exit_code", "stderr")
        ]}
        self.traces = {
            side: {"side": side, "revision": self.plan["scope"][scope], "controls": [], "steps": [
                {"case": case["id"], "step": "request", "target": "words-limit", "values": {"limit": "-1"},
                 "outputs": {"O-exit-code": {"raw": 2}, "O-stderr": {"raw": "invalid_limit\n"}}}
            ]} for side, scope in (("old", "current"), ("new", "candidate"))
        }

    def command(self, verb, *args, inventory=True):
        for key, data in (("plan", self.plan), ("conditions", self.conditions), ("inventory", self.inventory)):
            write(self.folder / f"{key}.json", data)
        command = [sys.executable, str(GATE), verb, "plan.json", *args, "--conditions", "conditions.json"]
        if inventory:
            command += ["--inventory", "inventory.json"]
        return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", cwd=self.folder)

    def matches(self, run, code, message):
        self.assertEqual(run.returncode, code, run.stdout + run.stderr)
        self.assertIn(message, run.stdout + run.stderr)

    def results(self):
        planned = self.command("plan")
        self.matches(planned, 0, "計画ゲート PASS")
        digest = re.search(r"計画 SHA-256 `([a-f0-9]{64})`", planned.stdout).group(1)
        executions = {}
        for side, trace in self.traces.items():
            path = self.folder / f"{side}.json"
            trace.setdefault("plan_sha256", digest)
            write(path, trace)
            executions[side] = {"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        return {"plan_sha256": digest, "executions": executions, "rule_checks": [], "negative_checks": [],
                "premortem": {axis: {"status": "checked", "evidence": "Verified synthetic sources."}
                              for axis in ("inventory", "oracle", "assertions", "state", "rules")}}

    def verify(self, result):
        write(self.folder / "results.json", result)
        return self.command("verify", "results.json")

    def test_inventory_catches_removal_from_both_conditions_and_plan(self):
        self.conditions["models"][0]["outputs"]["direct"].remove("stderr")
        self.plan["observations"].pop()
        self.plan["risks"].pop()
        self.plan["cases"][0]["steps"][0]["covers"].remove("R-stderr")
        self.matches(self.command("plan"), 2, "inventory / words-limit / limit=-1 / 直接出力 / stderr")

    def test_conditions_catch_removal_from_independent_inventory(self):
        self.inventory["requirements"].pop()
        self.matches(self.command("plan"), 2, "独立一覧にない条件・出力")

    def test_checkpoint_must_match_required_input(self):
        self.plan["cases"][0]["steps"][0]["values"]["limit"] = "-2"
        self.matches(self.command("plan"), 2, "計画の実行条件が不一致")

    def test_independent_inventory_is_required_even_when_a_plan_exists(self):
        self.matches(self.command("plan", inventory=False), 2, "--inventory が必要")

    def test_wrong_input_in_both_execution_artifacts_cannot_pass(self):
        for trace in self.traces.values():
            trace["steps"][0]["values"]["limit"] = "-2"
        self.matches(self.verify(self.results()), 1, "実測の実行条件が不一致")

    def test_missing_artifact_cannot_pass(self):
        result = self.results()
        (self.folder / "new.json").unlink()
        self.matches(self.verify(result), 2, "new.json")

    def test_actual_output_difference_detected_even_if_exit_codes_match(self):
        self.traces["new"]["steps"][0]["outputs"]["O-stderr"]["raw"] = ""
        self.matches(self.verify(self.results()), 1, "R-stderr")

    def test_two_matching_execution_artifacts_pass(self):
        self.matches(self.verify(self.results()), 0, "比較を確認した項目 2/2")

    def test_no_step_is_not_counted_as_verified(self):
        self.traces["new"]["steps"].clear()
        self.matches(self.verify(self.results()), 1, "比較を確認した項目 0/2")

    def test_one_output_does_not_count_as_evidence_for_another(self):
        del self.traces["new"]["steps"][0]["outputs"]["O-stderr"]
        run = self.verify(self.results())
        self.matches(run, 1, "比較を確認した項目 1/2")
        self.assertIn("未採取", run.stdout)

    def test_duplicate_step_is_rejected(self):
        self.traces["new"]["steps"].append(deepcopy(self.traces["new"]["steps"][0]))
        self.matches(self.verify(self.results()), 2, "重複")

    def split_checkpoints(self):
        case = self.plan["cases"][0]
        case["steps"][0]["covers"] = ["R-exit-code"]
        case["steps"].append({**case["steps"][0], "id": "stderr", "covers": ["R-stderr"]})
        for trace in self.traces.values():
            first = trace["steps"][0]
            stderr = first["outputs"].pop("O-stderr")
            trace["steps"].append({**first, "step": "stderr", "outputs": {"O-stderr": stderr}})

    def test_checkpoint_order_must_match_within_each_case(self):
        self.split_checkpoints()
        self.traces["new"]["steps"].reverse()
        self.matches(self.verify(self.results()), 2, "採取順が計画と不一致")

    def test_known_output_at_the_wrong_checkpoint_is_not_silently_ignored(self):
        self.split_checkpoints()
        self.traces["new"]["steps"][0]["outputs"]["O-stderr"] = {"raw": "unexpected"}
        self.matches(self.verify(self.results()), 2, "計画にない出力")

    def test_matching_evidence_cannot_satisfy_a_high_risk_negative_control(self):
        self.plan["risks"][1]["priority"] = "high"
        for trace in self.traces.values():
            trace["controls"].append({"id": "control", "outputs": {"O-stderr": {"raw": "same"}}})
        result = self.results()
        self.matches(self.verify(result), 1, "高リスクの検出確認なし")
        result["negative_checks"] = [{"risk": "R-stderr", "control": "control"}]
        self.matches(self.verify(result), 2, "検出確認の値を比較しても失敗しません")
        self.traces["new"]["controls"][0]["outputs"]["O-stderr"]["raw"] = "different"
        result = self.results()
        result["negative_checks"] = [{"risk": "R-stderr", "control": "control"}]
        self.matches(self.verify(result), 0, "比較を確認した項目 2/2")

    def test_frozen_plan_change_invalidates_old_evidence(self):
        result = self.results()
        self.plan["risks"][0]["expected"] = "New contract for this synthetic test."
        self.matches(self.verify(result), 2, "plan_sha256")

    def test_hash_binds_inventory_and_conditions_and_both_traces(self):
        for document in (self.inventory["requirements"][0], self.conditions["models"][0]):
            with self.subTest(document=document):
                result = self.results()
                original = document["evidence"]
                document["evidence"] += " Revised source."
                self.matches(self.verify(result), 2, "plan_sha256")
                planned = self.command("plan")
                result["plan_sha256"] = re.search(r"計画 SHA-256 `([a-f0-9]{64})`", planned.stdout).group(1)
                self.matches(self.verify(result), 2, "実行記録の plan_sha256 が不一致")
                document["evidence"] = original

    def test_sha_mismatch_after_artifact_change_is_rejected(self):
        result = self.results()
        with (self.folder / "new.json").open("a", encoding="utf-8") as artifact:
            artifact.write("\n")
        self.matches(self.verify(result), 2, "sha256 が不一致")

    def test_open_assessment_preserves_partial_status(self):
        self.plan["targets"][0]["checks"]["concurrency"] = {"status": "open", "evidence": "Pending review."}
        self.matches(self.verify(self.results()), 1, "未確定の調査項目")

    def test_blocked_runtime_stays_unverified(self):
        self.plan["targets"][0]["execution"] = "blocked"
        self.plan["cases"].clear()
        for risk in self.plan["risks"]:
            risk["gap"] = {"reason": "Runtime unavailable.", "next": "Start an isolated process."}
        for trace in self.traces.values():
            trace["steps"].clear()
        self.matches(self.verify(self.results()), 1, "比較を確認した項目 0/2")

    def test_normalized_comparison_needs_two_checked_controls(self):
        self.plan["observations"][1].update(mode="normalize", transform="Map CRLF to LF.")
        for side, trace in self.traces.items():
            raw = "invalid_limit\n" if side == "old" else "invalid_limit\r\n"
            valid = {"raw": raw, "normalized": "invalid_limit\n"}
            invalid = {"raw": "unexpected\r\n", "normalized": "unexpected\n"}
            trace["steps"][0]["outputs"]["O-stderr"] = valid
            trace["controls"] = [{"id": "accept", "outputs": {"O-stderr": valid}},
                                 {"id": "reject", "outputs": {"O-stderr": valid if side == "old" else invalid}}]
        result = self.results()
        self.matches(self.verify(result), 1, "比較ルールの検出確認なし")
        result["rule_checks"] = [{"observation": "O-stderr", "accept": "accept", "reject": "reject"}]
        self.matches(self.verify(result), 0, "比較を確認した項目 2/2")
        result["rule_checks"][0]["reject"] = "accept"
        self.matches(self.verify(result), 2, "許容と拒否には別の採取点が必要")

    def test_intentional_difference_compares_typed_old_and_new_expectations(self):
        observation = self.plan["observations"][1]
        del observation["predicate"]
        observation.update(mode="intentional", decision="Approved wording revision.",
                           current_expected="Original wording.", candidate_expected="Updated wording.",
                           expected_values={"old": "invalid_limit\n", "new": "limit_invalid\n"})
        for side, trace in self.traces.items():
            value = {"raw": observation["expected_values"][side]}
            trace["steps"][0]["outputs"]["O-stderr"] = value
            trace["controls"] = [{"id": "accept", "outputs": {"O-stderr": value}},
                                 {"id": "reject", "outputs": {"O-stderr": value if side == "old" else {"raw": ""}}}]
        rule = {"observation": "O-stderr", "accept": "accept", "reject": "reject"}
        result = self.results()
        result["rule_checks"] = [rule]
        self.matches(self.verify(result), 0, "比較を確認した項目 2/2")
        self.traces["new"]["steps"][0]["outputs"]["O-stderr"] = {"raw": "unexpected"}
        result = self.results()
        result["rule_checks"] = [rule]
        self.matches(self.verify(result), 1, "不一致")

    def test_exclusion_checks_a_retained_output_and_a_real_variation(self):
        ignored = dict(self.plan["observations"][1], id="O-ignored", mode="exclude",
                       reason="Ignore only decoration suffix.", safeguard="R-stderr")
        del ignored["predicate"]
        self.plan["observations"].append(ignored)
        for side, trace in self.traces.items():
            trace["controls"] = [
                {"id": "accept", "outputs": {"O-stderr": {"raw": "stable"}, "O-ignored": {"raw": side}}},
                {"id": "reject", "outputs": {"O-stderr": {"raw": side}}},
            ]
        result = self.results()
        self.matches(self.verify(result), 1, "比較を確認した項目 1/2")
        result["rule_checks"] = [{"observation": "O-ignored", "accept": "accept", "reject": "reject"}]
        self.matches(self.verify(result), 0, "比較を確認した項目 2/2")

    def test_view_example_detects_pagination_off_by_one(self):
        models = json.loads((SKILL / "assets/search-conditions-example.json").read_text())["models"]
        view = next(row for row in models if row["boundary"] == "view")
        counts = [int(re.match(r"\d+", row["values"]["results"]).group()) for row in view["rows"]]
        self.assertEqual(counts, [0, 1, 2, 3])
        self.assertEqual([count for count in counts if (count > 2) != (count >= 2)], [2])


if __name__ == "__main__":
    unittest.main()

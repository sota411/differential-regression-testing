import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


GATE = Path(__file__).with_name("check_coverage.py")


def fixture():
    evidence = "current@v1 and candidate@v2, checkout.py:42"
    checks = {
        name: {"status": "na", "evidence": evidence}
        for name in (
            "legacy", "input", "numeric", "time", "text", "order",
            "state", "failure", "concurrency", "performance", "auth", "logs",
        )
    }
    for name in ("input", "state", "failure"):
        checks[name]["status"] = "risk"
    target = {
        "id": "checkout",
        "entry": "CLI checkout --order",
        "evidence": evidence,
        "oracle": "captured",
        "execution": "ready",
        "fixtures": "Restore independent SQLite files from fixture.sql and compare order keys.",
        "isolation": "Use temporary namespaces and a local receipt sink.",
        "checks": checks,
        "layers": {name: {"status": "required", "evidence": evidence}
                   for name in ("direct", "state", "effects")},
    }
    observations = [
        {"id": "amount", "target": "checkout", "layer": "direct", "field": "$.amount",
         "evidence": evidence, "method": "Read stdout JSON from client process.",
         "mode": "exact", "predicate": "The amount in cents and its JSON number type match."},
        {"id": "rows", "target": "checkout", "layer": "state", "field": "ledger.amount",
         "evidence": evidence, "method": "Query SQLite after commit.",
         "mode": "exact", "predicate": "The ledger rows and cent amounts by order key match."},
        {"id": "sink", "target": "checkout", "layer": "effects", "field": "receipt.total",
         "evidence": evidence, "method": "Read the local receipt sink after worker stop.",
         "containment": "Redirect the receipt sender to loopback and reject other destinations.",
         "mode": "normalize", "predicate": "Receipt total in cents matches for each receipt.",
         "transform": "Map fixed decimal dollars to integer cents without rounding."},
    ]
    risks = [
        {"id": "R1", "observation": "amount", "dimension": "input", "priority": "normal",
         "condition": "An order priced at zero cents is accepted.",
         "expected": "The CLI prints a JSON number 0.", "evidence": evidence},
        {"id": "R2", "observation": "rows", "dimension": "state", "priority": "high",
         "condition": "The valid order completes.",
         "expected": "Exactly one row is committed with an amount of zero.", "evidence": evidence},
        {"id": "R3", "observation": "sink", "dimension": "failure", "priority": "high",
         "condition": "The adapter returns a retryable response and the worker retries.",
         "expected": "Exactly one receipt is accepted and its total is zero.", "evidence": evidence},
    ]
    return {
        "scope": {"current": "Synthetic checkout v1", "candidate": "Synthetic checkout v2",
                  "inventory": "Enumerate both tagged CLI registrations and receipt writers."},
        "targets": [target], "observations": observations, "risks": risks,
        "cases": [
            {"id": "C1", "scenario": "Checkout the seeded zero-cent order and wait for commit.",
             "covers": ["R1", "R2"]},
            {"id": "C2", "scenario": "Retry receipt delivery after the first receiver timeout.",
             "covers": ["R3"]},
        ],
    }


class CoverageGateTest(unittest.TestCase):
    def setUp(self):
        self.plan = fixture()

    def run_gate(self, phase, code, message, conditions=None):
        with tempfile.TemporaryDirectory() as folder:
            plan = Path(folder) / "plan.json"
            results = Path(folder) / "results.json"
            plan.write_text(json.dumps(self.plan), encoding="utf-8")
            results.write_text("{}", encoding="utf-8")
            command = [sys.executable, str(GATE), phase, str(plan)]
            if phase == "verify":
                command.append(str(results))
            if conditions is not None:
                design_path = Path(folder) / "conditions.json"
                design_path.write_text(json.dumps(conditions), encoding="utf-8")
                if phase == "design":
                    command[-1] = str(design_path)
                else:
                    command += ["--conditions", str(design_path)]
            run = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(run.returncode, code, run.stdout + run.stderr)
        self.assertIn(message, run.stdout + run.stderr)

    def test_plan_writes_pre_generation_tables(self):
        for heading in ("差分リスク表", "比較ルール表", "観測範囲マトリクス",
                        "トレーサビリティ", "ケース候補"):
            with self.subTest(heading=heading):
                self.run_gate("plan", 0, heading)

    def test_legacy_free_text_plan_cannot_complete_verification(self):
        self.run_gate("verify", 2, "--conditions と --inventory が必要")

    def test_stateless_cli_can_mark_state_and_effects_inapplicable(self):
        target = self.plan["targets"][0]
        for layer in ("state", "effects"):
            target["layers"][layer] = {"status": "na", "evidence": "CLI exits without any write."}
        for check in ("state", "failure"):
            target["checks"][check] = {"status": "na", "evidence": "No side-effect path in this scope."}
        del self.plan["observations"][1:], self.plan["risks"][1:], self.plan["cases"][1:]
        self.plan["cases"][0]["covers"] = ["R1"]
        self.run_gate("plan", 0, "計画プレビュー")

    def test_missing_layer_is_rejected_before_codegen(self):
        del self.plan["targets"][0]["layers"]["state"]
        self.run_gate("plan", 2, "state")

    def test_unmapped_risk_needs_an_explicit_gap(self):
        self.plan["cases"].pop()
        self.run_gate("plan", 2, "R3")

    def test_unavailable_current_cannot_be_used_as_an_oracle(self):
        self.plan["targets"][0]["oracle"] = "unavailable"
        self.run_gate("plan", 2, "unavailable")

    def test_blocked_runtime_can_only_be_planned_as_gaps(self):
        self.plan["targets"][0]["execution"] = "blocked"
        self.run_gate("plan", 2, "実行条件が blocked")
        self.plan["cases"].clear()
        for risk in self.plan["risks"]:
            risk["gap"] = {"reason": "The local sink is unavailable.",
                           "next": "Configure an isolated sink and record the route."}
        self.run_gate("plan", 0, "ケース候補　なし")

    def test_an_entry_cannot_be_silently_bypassed(self):
        target = copy.deepcopy(self.plan["targets"][0])
        target["id"] = "cancel"
        target["entry"] = "CLI cancel --order"
        for assessment in target["layers"].values():
            assessment["status"] = "na"
        for assessment in target["checks"].values():
            assessment["status"] = "na"
        self.plan["targets"].append(target)
        self.run_gate("plan", 2, "cancel.layers")

    def test_raw_value_exclusion_can_keep_an_invariant_on_the_same_field(self):
        self.plan["observations"].append({
            "id": "raw_sink", "target": "checkout", "layer": "effects", "field": "receipt.total",
            "mode": "exclude", "evidence": "Adapter contract §2", "method": "Read receipt sink.",
            "containment": "Local receipt sink", "reason": "Ignore only raw string formatting.",
            "safeguard": "R3",
        })
        self.run_gate("plan", 0, "raw_sink")

    def test_intentional_difference_needs_two_expectations_and_a_decision(self):
        observation = self.plan["observations"][2]
        del observation["predicate"], observation["transform"]
        observation.update(mode="intentional", decision="Synthetic change specification §3",
                           current_expected="Decimal dollars", candidate_expected="Integer cents")
        self.run_gate("plan", 0, "意図的差分")
        observation["current_expected"] = observation["candidate_expected"]
        self.run_gate("plan", 2, "別々の期待結果")
        observation["current_expected"] = "Decimal dollars"
        del observation["decision"]
        self.run_gate("plan", 2, "decision")

    def prepare_design(self):
        conditions = {"models": [
            {"id": "amount-check", "target": "checkout", "evidence": "current@v1:checkout.py:42",
             "axes": {"amount": ["0", "-1"]}, "layers": ["direct", "state"]},
            {"id": "delivery-failure", "target": "checkout", "evidence": "current@v1:worker.py:9",
             "axes": {"receiver": ["timeout"]}, "layers": ["effects"]},
        ]}
        for row in self.plan["risks"][:2]:
            row["design"] = {"model": "amount-check", "values": {"amount": "0"},
                             "regression": "Reject valid zero-cent checkout."}
        self.plan["risks"][2]["design"] = {
            "model": "delivery-failure", "values": {"receiver": "timeout"},
            "regression": "The worker sends a duplicate receipt on retry.",
        }
        return conditions

    def add_rejection(self, count):
        new_ids = []
        for original in self.plan["risks"][:count]:
            row = copy.deepcopy(original)
            row["id"] += "-negative"
            row["condition"] = "Checkout receives an order priced at -1."
            row["expected"] = "Reject with invalid_amount." if original["id"] == "R1" else "No row is added."
            row["design"]["values"]["amount"] = "-1"
            row["design"]["regression"] = "The negative amount is accepted and an order is inserted."
            self.plan["risks"].append(row)
            new_ids.append(row["id"])
        self.plan["cases"].append({"id": "C-negative", "scenario": "Seed and submit a -1-cent order.", "covers": new_ids})

    def test_design_enumerates_conditions_before_cases_exist(self):
        self.run_gate("design", 0, "amount=-1", self.prepare_design())

    def test_normal_cases_cannot_hide_unplanned_input(self):
        self.run_gate("plan", 2, "amount=-1", self.prepare_design())

    def test_rejection_needs_its_own_state_assertion(self):
        conditions = self.prepare_design()
        self.add_rejection(1)
        self.run_gate("plan", 2, "amount=-1 / 永続化データ", conditions)

    def test_separate_axis_values_do_not_cover_their_combinations(self):
        conditions = self.prepare_design()
        self.add_rejection(2)
        conditions["models"][0]["axes"]["order_state"] = ["new", "exists"]
        for risk in self.plan["risks"]:
            design = risk["design"]
            if design["model"] == "amount-check":
                design["values"]["order_state"] = "new" if design["values"]["amount"] == "0" else "exists"
        self.run_gate("plan", 2, "amount=-1, order_state=new", conditions)

    def test_condition_to_test_mapping_passes(self):
        conditions = self.prepare_design()
        self.add_rejection(2)
        self.run_gate("plan", 0, "現新テスト項目一覧", conditions)

    def test_designed_risks_require_a_failure_example(self):
        conditions = self.prepare_design()
        self.add_rejection(2)
        del self.plan["risks"][0]["design"]["regression"]
        self.run_gate("plan", 2, "regression", conditions)

    def boundary_design(self):
        conditions = self.prepare_design()
        self.add_rejection(2)
        model = conditions["models"][0]
        del model["layers"]
        model["boundary"] = "service"
        model["outputs"] = {"direct": ["$.amount"], "state": ["ledger.amount"]}
        return conditions

    def test_omitted_output_in_a_covered_layer_blocks_plan(self):
        conditions = self.boundary_design()
        self.run_gate("plan", 0, "現新テスト項目一覧", conditions)
        conditions["models"][0]["outputs"]["direct"].append("$.currency")
        self.run_gate("plan", 2, "amount=-1 / 直接出力 / $.currency", conditions)

    def test_source_rows_preserve_valid_pairs_without_expanding_a_product(self):
        conditions = self.boundary_design()
        model = conditions["models"][0]
        del model["axes"]
        model["rows"] = [
            {"values": {"amount": "0", "state": "new"}, "evidence": "legacy:checkout.py:12 new order"},
            {"values": {"amount": "-1", "state": "pending"}, "evidence": "legacy:checkout.py:18 pending order"},
        ]
        for risk in self.plan["risks"]:
            design = risk["design"]
            if design["model"] == "amount-check":
                design["values"]["state"] = "new" if design["values"]["amount"] == "0" else "pending"
        self.run_gate("design", 0, "条件の組み合わせ 3 件", conditions)
        self.run_gate("plan", 0, "amount-check / amount=-1, state=pending", conditions)
        self.plan["risks"][-1]["design"]["values"]["state"] = "new"
        self.run_gate("plan", 2, "条件候補にない組", conditions)

    def test_axes_and_source_rows_are_alternative_inputs(self):
        conditions = self.boundary_design()
        conditions["models"][0]["rows"] = [{"values": {"amount": "0"}, "evidence": "checkout.py:42"}]
        self.run_gate("design", 2, "axes または rows の片方", conditions)


if __name__ == "__main__":
    unittest.main()

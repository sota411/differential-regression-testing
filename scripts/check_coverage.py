#!/usr/bin/env python3
import argparse
from collections import defaultdict
import hashlib
from itertools import product
import json
from pathlib import Path
import sys


DIMENSIONS = (
    "legacy", "input", "numeric", "time", "text", "order",
    "state", "failure", "concurrency", "performance", "auth", "logs",
)
LAYERS = {"direct": "直接出力", "state": "永続化データ", "effects": "外部副作用"}
BOUNDARIES = {"routing": "入口・経路", "service": "処理結果", "sql": "SQL・永続化",
              "view": "画面", "job": "ジョブ・ファイル・メッセージ", "other": "その他"}
MODES = {"exact": "完全一致", "normalize": "正規化比較", "exclude": "比較除外",
         "intentional": "意図的差分"}
PREMORTEM = ("inventory", "oracle", "assertions", "state", "rules")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def record(value, at, required, optional=()):
    require(isinstance(value, dict), f"{at}: オブジェクトが必要")
    missing = set(required) - value.keys()
    extra = value.keys() - set(required) - set(optional)
    require(not (missing or extra), f"{at}: 必須項目の欠落={sorted(missing)} 未知の項目={sorted(extra)}")


def text(value, at):
    require(isinstance(value, str) and value.strip() and value.strip().lower() not in
            {"-", "—", "?", "tbd", "todo", "n/a", "none"},
            f"{at}: 具体的な文字列が必要")
    return value


def fields(row, at, required, optional=()):
    record(row, at, required, optional)
    for key, value in row.items():
        text(value, f"{at}.{key}")


def choice(value, allowed, at):
    text(value, at)
    require(value in allowed, f"{at}: {value} は無効。有効値={list(allowed)}")


def unique_rows(value, at, keys):
    require(isinstance(value, list), f"{at}: 配列が必要")
    result = {}
    for number, row in enumerate(value, 1):
        location = f"{at}[{number}]"
        require(isinstance(row, dict), f"{location}: オブジェクトが必要")
        parts = tuple(text(row.get(key), f"{location}.{key}") for key in keys)
        key = parts[0] if len(parts) == 1 else parts
        require(key not in result, f"{at}: {key} が重複")
        result[key] = row
    return result


def assessments(value, keys, allowed, at):
    record(value, at, keys)
    for key, row in value.items():
        location = f"{at}.{key}"
        fields(row, location, ("status", "evidence"))
        choice(row["status"], allowed, location)


def parse_json(data, path):
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"{path}: JSON キー {key} が重複")
            result[key] = value
        return result

    def invalid_number(value):
        raise ValueError(f"{path}: {value} は JSON 数値として無効")

    return json.loads(data, object_pairs_hook=unique_keys, parse_constant=invalid_number)


def read_json(path):
    return parse_json(Path(path).read_text(encoding="utf-8"), path)


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def validate_plan(plan):
    record(plan, "plan", ("scope", "targets", "observations", "risks", "cases"))
    fields(plan["scope"], "scope", ("current", "candidate", "inventory"))
    targets = unique_rows(plan["targets"], "targets", ("id",))
    observations = unique_rows(plan["observations"], "observations", ("id",))
    risks = unique_rows(plan["risks"], "risks", ("id",))
    cases = unique_rows(plan["cases"], "cases", ("id",))
    require(targets, "targets: 対象の入口が必要")

    for key, row in targets.items():
        record(row, key, ("id", "entry", "evidence", "oracle", "execution", "fixtures", "isolation", "checks", "layers"))
        for field in ("entry", "evidence", "fixtures", "isolation"):
            text(row[field], f"{key}.{field}")
        choice(row["oracle"], ("live", "captured", "unavailable"), f"{key}.oracle")
        choice(row["execution"], ("ready", "blocked"), f"{key}.execution")
        assessments(row["checks"], DIMENSIONS, ("risk", "na", "open"), f"{key}.checks")
        assessments(row["layers"], LAYERS, ("required", "na", "open"), f"{key}.layers")
        require(any(layer["status"] != "na" for layer in row["layers"].values()),
                f"{key}.layers: 対象入口には required または open の観測層が必要")

    comparing_layers = set()
    selectors = set()
    comparison_fields = ("id", "target", "layer", "field", "evidence", "method", "mode")
    mode_fields = {
        "exact": ("predicate",),
        "normalize": ("predicate", "transform"),
        "exclude": ("reason", "safeguard"),
        "intentional": ("decision", "current_expected", "candidate_expected"),
    }
    for key, row in observations.items():
        choice(row.get("layer"), LAYERS, f"{key}.layer")
        choice(row.get("mode"), MODES, f"{key}.mode")
        required = comparison_fields + mode_fields[row["mode"]]
        if row["layer"] == "effects":
            required += ("containment",)
        record(row, key, required, ("expected_values",) if row["mode"] == "intentional" else ())
        for name in required:
            text(row[name], f"{key}.{name}")
        if "expected_values" in row:
            values = row["expected_values"]
            record(values, f"{key}.expected_values", ("old", "new"))
            require(canonical_json(values["old"]) != canonical_json(values["new"]),
                    f"{key}: 意図的差分には別々の期待結果が必要")
        target, layer, field = row["target"], row["layer"], row["field"]
        require(target in targets, f"{key}: 未知の対象 {target}")
        require(targets[target]["layers"][layer]["status"] == "required",
                f"{key}: {target}/{layer} を required にする必要あり")
        selector = (target, layer, field, row["mode"] == "exclude")
        require(selector not in selectors, f"{key}: 同じ観測項目が重複")
        selectors.add(selector)
        if row["mode"] == "exclude":
            require("*" not in field and field.strip() not in {"$", "/", "."},
                    f"{key}: 比較除外には単一項目の指定が必要")
        else:
            comparing_layers.add((target, layer))
        if row["mode"] == "intentional":
            require(row["current_expected"].strip() != row["candidate_expected"].strip(),
                    f"{key}: 意図的差分には別々の期待結果が必要")

    observed_risks = set()
    screened_risks = set()
    for key, row in risks.items():
        required = ("id", "observation", "dimension", "priority", "condition", "expected", "evidence")
        record(row, key, required, ("gap", "design"))
        for field in required:
            text(row[field], f"{key}.{field}")
        if "gap" in row:
            fields(row["gap"], f"{key}.gap", ("reason", "next"))
        choice(row["dimension"], DIMENSIONS, f"{key}.dimension")
        choice(row["priority"], ("high", "normal"), f"{key}.priority")
        observation = observations.get(row["observation"])
        require(observation and observation["mode"] != "exclude",
                f"{key}: 検証項目には比較可能な観測 ID が必要")
        target, dimension = observation["target"], row["dimension"]
        require(targets[target]["checks"][dimension]["status"] == "risk",
                f"{key}: {target}/{dimension} を risk にする必要あり")
        observed_risks.add(row["observation"])
        screened_risks.add((target, dimension))

    for key, row in targets.items():
        for layer, item in row["layers"].items():
            if item["status"] == "required":
                require((key, layer) in comparing_layers, f"{key}/{layer}: 比較できる観測項目が必要")
        for dimension, item in row["checks"].items():
            if item["status"] == "risk":
                require((key, dimension) in screened_risks, f"{key}/{dimension}: リスク行が必要")

    for key, row in observations.items():
        if row["mode"] == "exclude":
            safeguard = risks.get(row["safeguard"])
            require(safeguard and observations[safeguard["observation"]]["target"] == row["target"],
                    f"{key}: 同じ対象で意味を保護するリスク ID が必要")
        else:
            require(key in observed_risks, f"{key}: 観測を検証するリスク行が必要")

    links = defaultdict(list)
    for key, row in cases.items():
        record(row, key, ("id", "scenario"), ("covers", "steps"))
        text(row["scenario"], f"{key}.scenario")
        require(("covers" in row) != ("steps" in row), f"{key}: covers または steps の片方が必要")
        covers = row.get("covers")
        if "steps" in row:
            steps = unique_rows(row["steps"], f"{key}.steps", ("id",))
            require(steps, f"{key}.steps: 採取する操作が必要")
            covers = []
            for step_id, step in steps.items():
                location = f"{key}/{step_id}"
                record(step, location, ("id", "target", "values", "covers"))
                text(step["target"], f"{location}.target")
                observed_values = ordered_values(step["values"], f"{location}.values")
                distinct_values(step["covers"], f"{location}.covers")
                for risk_id in step["covers"]:
                    require(risk_id in risks, f"{location}: 未知のリスク {risk_id}")
                    risk, observation = risks[risk_id], observations[risks[risk_id]["observation"]]
                    design = risk.get("design")
                    require(isinstance(design, dict) and observed_values == ordered_values(
                        design.get("values"), f"{risk_id}.design.values") and step["target"] == observation["target"],
                        f"{location}/{risk_id}: 計画の実行条件が不一致")
                covers.extend(step["covers"])
            cases[key] = {**row, "covers": covers}
        require(isinstance(covers, list) and covers, f"{key}.covers: リスク ID が必要")
        covered = set()
        for risk_id in covers:
            text(risk_id, f"{key}.covers")
            require(risk_id in risks, f"{key}: 未知のリスク {risk_id}")
            require(risk_id not in covered, f"{key}: {risk_id} が重複")
            covered.add(risk_id)
            links[risk_id].append(key)
            target = observations[risks[risk_id]["observation"]]["target"]
            require(targets[target]["oracle"] != "unavailable",
                    f"{key}/{risk_id}: 現行の比較元が unavailable")
            require(targets[target]["execution"] == "ready", f"{key}/{risk_id}: 実行条件が blocked")
    for key, row in risks.items():
        require(bool(links[key]) != ("gap" in row), f"{key}: ケースまたは gap の片方が必要")

    return targets, observations, risks, cases, links


def distinct_values(values, at):
    require(isinstance(values, list) and values, f"{at}: 値の配列が必要")
    for value in values:
        text(value, at)
    require(len(set(values)) == len(values), f"{at}: 値が重複")


def ordered_values(values, at):
    require(isinstance(values, dict) and values, f"{at}: 条件名と値が必要")
    for name, value in values.items():
        text(name, at)
        text(value, f"{at}.{name}")
    return tuple(sorted(values.items()))


def condition_rows(model, key):
    if "rows" in model:
        rows = model["rows"]
        require(isinstance(rows, list) and rows, f"{key}.rows: 根拠から列挙した行が必要")
        for index, row in enumerate(rows, 1):
            at = f"{key}.rows[{index}]"
            record(row, at, ("values", "evidence"))
            evidence = text(row["evidence"], f"{at}.evidence")
            yield ordered_values(row["values"], f"{at}.values"), f"{model['evidence']} / {evidence}"
        return

    axes = model["axes"]
    require(isinstance(axes, dict) and axes, f"{key}.axes: 条件軸が必要")
    for axis, values in axes.items():
        text(axis, f"{key}.axes")
        distinct_values(values, f"{key}.{axis}")
    ordered_axes = sorted(axes)
    for values in product(*(axes[axis] for axis in ordered_axes)):
        yield tuple(zip(ordered_axes, values)), model["evidence"]


def required_outputs(model, key):
    if "boundary" not in model:
        # Keep accepting the earlier layer-only input for saved test plans.
        require("layers" in model and "outputs" not in model and "rows" not in model,
                f"{key}: boundary と outputs、または旧書式の layers が必要")
        distinct_values(model["layers"], f"{key}.layers")
        for layer in model["layers"]:
            choice(layer, LAYERS, f"{key}.layers")
        return [(layer, None) for layer in model["layers"]]

    choice(model["boundary"], BOUNDARIES, f"{key}.boundary")
    outputs = model.get("outputs")
    require("layers" not in model and isinstance(outputs, dict) and outputs,
            f"{key}: 境界ごとの出力項目を outputs に指定する必要あり")
    for layer, fields in outputs.items():
        choice(layer, LAYERS, f"{key}.outputs")
        distinct_values(fields, f"{key}.outputs.{layer}")
    return [(layer, field) for layer, fields in outputs.items() for field in fields]


def expand_conditions(conditions):
    record(conditions, "conditions", ("models",))
    models = unique_rows(conditions["models"], "models", ("id",))
    expanded = {}
    for key, model in models.items():
        record(model, key, ("id", "target", "evidence"), ("axes", "rows", "boundary", "outputs", "layers"))
        for field in ("target", "evidence"):
            text(model[field], f"{key}.{field}")
        require(("axes" in model) != ("rows" in model), f"{key}: axes または rows の片方が必要")
        outputs = required_outputs(model, key)
        for values, evidence in condition_rows(model, key):
            require((key, values) not in expanded, f"{key}: 条件 {show_values(values)} が重複")
            expanded[key, values] = {"target": model["target"], "boundary": model.get("boundary"),
                                     "evidence": evidence, "outputs": outputs}
    return expanded


def show_values(values):
    return ", ".join(f"{axis}={value}" for axis, value in values)


def show_output(layer, field):
    return f"{LAYERS[layer]} / {field}" if field is not None else LAYERS[layer]


def validate_design(expanded, targets, observations, risks):
    modeled = {row["target"] for row in expanded.values()}
    required_targets = {key for key, row in targets.items()
                        if any(layer["status"] == "required" for layer in row["layers"].values())}
    require(not modeled - targets.keys(), f"未登録の対象入口: {sorted(modeled - targets.keys())}")
    require(not required_targets - modeled, f"条件モデルがない入口: {sorted(required_targets - modeled)}")
    covered = defaultdict(set)
    for key, row in risks.items():
        design = row.get("design")
        record(design, f"{key}.design", ("model", "values", "regression"))
        model = text(design["model"], f"{key}.design.model")
        regression = text(design["regression"], f"{key}.design.regression")
        require(regression.strip() != row["expected"].strip(),
                f"{key}: 回帰例には期待値と異なる振る舞いが必要")
        condition = (model, ordered_values(design["values"], f"{key}.design.values"))
        require(condition in expanded, f"{key}: 条件候補にない組 {model} / {show_values(condition[1])}")
        observed = observations[row["observation"]]
        require(expanded[condition]["target"] == observed["target"], f"{key}: 比較項目の対象入口が不一致")
        covered[condition].update(((observed["layer"], None), (observed["layer"], observed["field"])))

    missing = [f"{model} / {show_values(values)} / {show_output(*output)}"
               for (model, values), row in expanded.items() for output in row["outputs"]
               if output not in covered[model, values]]
    require(not missing, "条件候補に対する比較項目なし:\n" + "\n".join(missing))


def validate_inventory(inventory, expanded):
    record(inventory, "inventory", ("requirements",))
    rows = inventory["requirements"]
    require(isinstance(rows, list) and rows, "inventory.requirements: 根拠から抽出した比較項目が必要")
    declared = {(model["target"], model["boundary"], values, layer, field)
                for (_, values), model in expanded.items() for layer, field in model["outputs"]}
    seen = set()
    for number, row in enumerate(rows, 1):
        at = f"inventory.requirements[{number}]"
        record(row, at, ("target", "boundary", "values", "layer", "field", "evidence"))
        for key in ("target", "field", "evidence"):
            text(row[key], f"{at}.{key}")
        choice(row["boundary"], BOUNDARIES, f"{at}.boundary")
        choice(row["layer"], LAYERS, f"{at}.layer")
        values = ordered_values(row["values"], f"{at}.values")
        item = (row["target"], row["boundary"], values, row["layer"], row["field"])
        require(item not in seen, f"{at}: 比較項目が重複")
        seen.add(item)
        require(item in declared, f"inventory / {row['target']} / {show_values(values)} / "
                f"{show_output(row['layer'], row['field'])}: 条件モデルに独立した必須項目がありません")
    missing = [f"{target} / {boundary} / {show_values(values)} / {show_output(layer, field)}"
               for target, boundary, values, layer, field in sorted(declared - seen)]
    require(not missing, "独立一覧にない条件・出力:\n" + "\n".join(missing))


def table(headers, rows):
    def cell(value):
        return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")

    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        print("| " + " | ".join(cell(value) for value in row) + " |")
    print()


def open_assessments(targets):
    return [
        (key, item, row["evidence"])
        for key, target in targets.items()
        for section in ("checks", "layers")
        for item, row in target[section].items()
        if row["status"] == "open"
    ]


def gap_details(risk):
    if "gap" in risk:
        return f"{risk['gap']['reason']} / {risk['gap']['next']}"
    return ""


def design_report(expanded):
    print(f"# テスト項目を導く条件候補\n\n条件の組み合わせ {len(expanded)} 件\n")
    table(("条件モデル", "境界", "入口", "入力・状態・操作条件", "比較する項目", "列挙根拠"),
          ((model, BOUNDARIES.get(row["boundary"], ""), row["target"], show_values(values),
            ", ".join(show_output(*output) for output in row["outputs"]), row["evidence"])
           for (model, values), row in expanded.items()))


def condition_description(risk):
    if "design" not in risk:
        return risk["condition"]
    design = risk["design"]
    return f"{design['model']} / {show_values(sorted(design['values'].items()))}\n{risk['condition']}"


def plan_report(scope, targets, observations, risks, cases, links, digest, inventory_checked):
    status = "計画ゲート PASS（独立一覧・採取点を照合）" if inventory_checked else "計画プレビュー（構造検査）"
    print(f"# 現新比較テスト計画\n\n{status}\n\n計画 SHA-256 `{digest}`\n")
    for label, key in (("現行", "current"), ("新", "candidate"), ("対象の列挙元", "inventory")):
        print(f"- {label}　{scope[key]}")
    ready = ", ".join(cases) or "なし"
    label = "生成対象" if inventory_checked else "ケース候補"
    print(f"- {label}　{ready}\n")
    print("## 現新テスト項目一覧\n")
    table(("ケース", "初期条件・入力・操作順", "比較項目と期待値"),
          ((key, row["scenario"], " / ".join(f"{risk} {risks[risk]['expected']}" for risk in row["covers"]))
           for key, row in cases.items()))
    table(("入口 ID", "入口", "根拠", "現行の比較元", "実行可否", "初期条件と固定", "隔離"),
          ((key, t["entry"], t["evidence"], t["oracle"], t["execution"], t["fixtures"], t["isolation"])
           for key, t in targets.items()))
    print("## 差分リスク表\n")
    table(("リスク", "優先度", "区分", "入力・状態", "期待する観測", "検出する回帰", "根拠"),
          ((key, r["priority"], r["dimension"], condition_description(r), r["expected"],
            r.get("design", {}).get("regression", ""), r["evidence"])
           for key, r in risks.items()))
    print("## 比較ルール表\n")
    rule_fields = ("predicate", "transform", "reason", "safeguard", "decision",
                   "current_expected", "candidate_expected")
    table(("観測", "項目", "分類", "判定条件と根拠"),
          ((key, o["field"], MODES[o["mode"]],
            " / ".join(o[k] for k in rule_fields if k in o) + " / " + o["evidence"])
           for key, o in observations.items()))
    print("## 観測範囲マトリクス\n")
    table(("入口", "層", "適用", "根拠", "観測 ID・採取方法・遮断"),
          ((target, name, row["status"], row["evidence"], " / ".join(
              f"{key} {o['method']} {o.get('containment', '')}".rstrip()
              for key, o in observations.items() if (o["target"], o["layer"]) == (target, layer)))
           for target, t in targets.items() for layer, name in LAYERS.items() for row in [t["layers"][layer]]))
    print("## トレーサビリティ\n")
    table(("リスク", "観測", "ケース", "未計画の理由と次の検証"),
          ((key, r["observation"], ", ".join(links[key]), gap_details(r)) for key, r in risks.items()))
    print("## 観点の調査状況\n")
    table(("入口", "観点", "判定", "根拠"),
          ((key, dimension, row["status"], row["evidence"])
           for key, t in targets.items() for dimension, row in t["checks"].items()))


def report_verification(assertion_rows, rule_rows, premortem, digest, targets, observations, risks, links):
    assertions = {(row["case"], row["risk"]): row for row in assertion_rows}
    rule_checks = {row["observation"]: row for row in rule_rows}
    assessments(premortem, PREMORTEM, ("checked", "open"), "premortem")
    guarded_rules = {key for key, row in observations.items() if row["mode"] != "exact"}
    unchecked_rules = guarded_rules - rule_checks.keys()
    unchecked_safeguards = {observations[key]["safeguard"] for key in unchecked_rules
                            if observations[key]["mode"] == "exclude"}
    issues = []
    verified = planned = implemented = 0
    rows = []
    for key, risk in risks.items():
        cases = links[key]
        entries = [assertions.get((case, key), {}) for case in cases]
        if cases:
            planned += 1
            implemented += all("assertion" in row for row in entries)
            passed = all(row.get("status") == "pass" for row in entries)
            sensitive = risk["priority"] != "high" or any(
                row.get("status") == "pass" and "negative" in row for row in entries)
            rules_checked = risk["observation"] not in unchecked_rules and key not in unchecked_safeguards
            if not passed:
                disposition = "不一致" if any(row.get("status") == "fail" for row in entries) else "未検証"
            elif not sensitive:
                disposition = "高リスクの検出確認なし"
            elif not rules_checked:
                disposition = "比較ルールの検出確認なし"
            else:
                verified += 1
                disposition = "確認済み"
        else:
            disposition = "未計画"
        if disposition != "確認済み":
            issues.append((key, disposition, gap_details(risk) or risk["expected"]))
        evidence = " / ".join(" ".join([case] + [row[field] for field in
                                                ("assertion", "baseline", "evidence", "negative") if field in row])
                              for case, row in zip(cases, entries))
        rows.append((key, risk["observation"], ", ".join(cases), disposition, evidence))

    for key in sorted(unchecked_rules):
        issues.append((key, "比較ルールの検出確認なし", observations[key]["field"]))
    for key, item, evidence in open_assessments(targets):
        issues.append((f"{key}/{item}", "未確定の調査項目", evidence))
    for key, row in premortem.items():
        if row["status"] == "open":
            issues.append((key, "プリモーテムで未解決", row["evidence"]))
    if not risks:
        issues.append(("scope", "比較項目なし", "対象の根拠から比較項目を確定する"))

    print("# 現新比較テスト結果\n")
    print(f"完了ゲート {'FAIL' if issues else 'PASS'}\n\n計画 SHA-256 `{digest}`\n")
    count = len(risks)
    print(f"- 計画済み {planned}/{count}、実装根拠あり {implemented}/{count}、比較を確認した項目 {verified}/{count}")
    print(f"- 比較ルールの許容・拒否確認 {len(rule_checks)}/{len(guarded_rules)}")
    print(f"- 未解決 {len(issues)} 件\n")
    if issues:
        table(("ID", "未解決事項", "根拠・次の検証"), issues)
    table(("リスク", "観測", "ケース", "判定", "アサーション・現行・実行・検出確認"), rows)
    if rule_checks:
        table(("観測", "許容の証拠", "拒否の証拠"),
              ((key, row["accept"], row["reject"]) for key, row in rule_checks.items()))
    return 1 if issues else 0


def load_execution(reference, output_dir, side, revision, digest, observations):
    fields(reference, f"executions.{side}", ("path", "sha256"))
    path = (output_dir / reference["path"]).resolve()
    require(path.is_relative_to(output_dir), f"executions.{side}: 結果ディレクトリ内のファイルが必要")
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == reference["sha256"], f"{path}: sha256 が不一致")
    execution = parse_json(data.decode("utf-8"), path)
    record(execution, str(path), ("side", "revision", "plan_sha256", "steps", "controls"))
    require(execution["side"] == side and execution["revision"] == revision,
            f"{path}: 実行側または revision が計画と不一致")
    require(execution["plan_sha256"] == digest, f"{path}: 実行記録の plan_sha256 が不一致")
    steps = unique_rows(execution["steps"], f"{path}.steps", ("case", "step"))
    controls = unique_rows(execution["controls"], f"{path}.controls", ("id",))
    for (case, step), row in steps.items():
        at = f"{path}/{case}/{step}"
        record(row, at, ("case", "step", "target", "values", "outputs"))
        text(row["target"], f"{at}.target")
        ordered_values(row["values"], f"{at}.values")
        validate_outputs(row["outputs"], observations, at)
    for control, row in controls.items():
        at = f"{path}/controls/{control}"
        record(row, at, ("id", "outputs"))
        validate_outputs(row["outputs"], observations, at)
    return path, steps, controls


def validate_outputs(outputs, observations, at):
    require(isinstance(outputs, dict), f"{at}.outputs: 出力オブジェクトが必要")
    for key, sample in outputs.items():
        require(key in observations, f"{at}: 未登録の観測 ID {key}")
        required = ("raw", "normalized") if observations[key]["mode"] == "normalize" else ("raw",)
        record(sample, f"{at}.outputs.{key}", required)
        canonical_json(sample)


def matches_observation(observation, old, new):
    mode = observation["mode"]
    if mode == "intentional":
        expected = observation["expected_values"]
        return all(canonical_json(actual["raw"]) == canonical_json(expected[side])
                   for side, actual in (("old", old), ("new", new)))
    key = "normalized" if mode == "normalize" else "raw"
    return canonical_json(old[key]) == canonical_json(new[key])


def verify_artifacts(results_path, digest, scope, targets, observations, risks, cases, links):
    results = read_json(results_path)
    record(results, "results", ("plan_sha256", "executions", "rule_checks", "negative_checks", "premortem"))
    require(results["plan_sha256"] == digest, "plan_sha256: 計画と証拠のハッシュが一致しない")
    record(results["executions"], "results.executions", ("old", "new"))
    for key, observation in observations.items():
        require(observation["mode"] != "intentional" or "expected_values" in observation,
                f"{key}: 意図的差分の検証には expected_values が必要")

    directory = Path(results_path).resolve().parent
    old_path, old_steps, old_controls = load_execution(results["executions"]["old"], directory,
                                                       "old", scope["current"], digest, observations)
    new_path, new_steps, new_controls = load_execution(results["executions"]["new"], directory,
                                                       "new", scope["candidate"], digest, observations)
    checkpoints = {(case, step["id"]): step for case, row in cases.items() for step in row["steps"]}
    for path, steps in ((old_path, old_steps), (new_path, new_steps)):
        require(not steps.keys() - checkpoints.keys(), f"{path}: 計画にない採取点 {sorted(steps.keys() - checkpoints.keys())}")
        recorded = defaultdict(list)
        for case, step in steps:
            recorded[case].append(step)
        for case, step_ids in recorded.items():
            planned = [step["id"] for step in cases[case]["steps"] if (case, step["id"]) in steps]
            require(step_ids == planned, f"{path}/{case}: 採取順が計画と不一致")

    def control_pair(control, obs, at):
        text(control, at)
        require(all(control in controls and obs in controls[control]["outputs"]
                    for controls in (old_controls, new_controls)), f"{at}: 旧新の検出確認出力が不足")
        return old_controls[control]["outputs"][obs], new_controls[control]["outputs"][obs]

    controls_report = []
    for key, row in unique_rows(results["rule_checks"], "rule_checks", ("observation",)).items():
        fields(row, key, ("observation", "accept", "reject"))
        require(key in observations and observations[key]["mode"] != "exact", f"{key}: 検出確認の対象外")
        require(row["accept"] != row["reject"], f"{key}: 許容と拒否には別の採取点が必要")
        observation = observations[key]
        compared = risks[observation["safeguard"]]["observation"] if observation["mode"] == "exclude" else key
        accept = control_pair(row["accept"], compared, key)
        reject = control_pair(row["reject"], compared, key)
        variations = control_pair(row["accept"], key, key)
        require(canonical_json(variations[0]["raw"]) != canonical_json(variations[1]["raw"]),
                f"{key}: 許容側の採取値に実際の差が必要")
        require(matches_observation(observations[compared], *accept)
                and not matches_observation(observations[compared], *reject),
                f"{key}: 許容・拒否を実測値で再現できません")
        controls_report.append(row)

    negatives = {}
    for key, row in unique_rows(results["negative_checks"], "negative_checks", ("risk",)).items():
        fields(row, key, ("risk", "control"))
        require(key in risks and links[key], f"{key}: 計画済みの比較項目が必要")
        obs = risks[key]["observation"]
        require(not matches_observation(observations[obs], *control_pair(row["control"], obs, key)),
                f"{key}: 検出確認の値を比較しても失敗しません")
        negatives[key] = f"{new_path}#controls/{row['control']}/{obs}"

    assertions = []
    for (case, step_id), step in checkpoints.items():
        key = (case, step_id)
        old, new = old_steps.get(key), new_steps.get(key)
        compared = {risks[risk]["observation"] for risk in step["covers"]}
        excluded = {key for key, row in observations.items() if row["mode"] == "exclude"
                    and row["safeguard"] in step["covers"]}
        for path, sample in ((old_path, old), (new_path, new)):
            if sample is not None:
                extra = sample["outputs"].keys() - compared - excluded
                require(not extra, f"{path}/{case}/{step_id}: 計画にない出力 {sorted(extra)}")
        for risk in step["covers"]:
            obs = risks[risk]["observation"]
            old_ref, new_ref = (f"{path}#steps/{case}/{step_id}/{obs}" for path in (old_path, new_path))
            base = {"case": case, "risk": risk}
            if old is None or new is None or obs not in old["outputs"] or obs not in new["outputs"]:
                assertions.append({**base, "status": "unverified", "evidence": f"未採取 {old_ref} / {new_ref}"})
                continue
            left, right = old["outputs"][obs], new["outputs"][obs]
            same_inputs = all(sample["target"] == step["target"] and sample["values"] == step["values"]
                              for sample in (old, new))
            matched = same_inputs and matches_observation(observations[obs], left, right)
            detail = ""
            if not same_inputs:
                detail = (f" 実測の実行条件が不一致（旧 {old['target']} {canonical_json(old['values'])} "
                          f"/ 新 {new['target']} {canonical_json(new['values'])}）")
            elif not matched:
                detail = f" 旧 {canonical_json(left)} / 新 {canonical_json(right)}"
            assertion = {**base, "status": "pass" if matched else "fail", "assertion": f"{case}/{step_id}/{obs}",
                         "baseline": old_ref, "evidence": new_ref + detail}
            if risk in negatives:
                assertion["negative"] = negatives[risk]
            assertions.append(assertion)

    return report_verification(assertions, controls_report, results["premortem"],
                               digest, targets, observations, risks, links)


def main():
    parser = argparse.ArgumentParser(description="現新比較テストの計画と実行証拠を照合する")
    commands = parser.add_subparsers(dest="phase", required=True)
    commands.add_parser("design").add_argument("conditions")
    plan_parser = commands.add_parser("plan")
    plan_parser.add_argument("plan")
    plan_parser.add_argument("--conditions")
    plan_parser.add_argument("--inventory")
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("plan")
    verify_parser.add_argument("results")
    verify_parser.add_argument("--conditions")
    verify_parser.add_argument("--inventory")
    args = parser.parse_args()

    try:
        if args.phase == "design":
            design_report(expand_conditions(read_json(args.conditions)))
            return 0
        plan = read_json(args.plan)
        targets, observations, risks, cases, links = validate_plan(plan)
        if args.phase == "verify" or any("steps" in row for row in cases.values()):
            require(args.conditions and args.inventory, "実行を検証する計画には --conditions と --inventory が必要")
        if args.conditions:
            conditions = read_json(args.conditions)
            expanded = expand_conditions(conditions)
            source = {"plan": plan, "conditions": conditions}
            if args.inventory:
                require(all("steps" in row for row in cases.values()), "独立した比較項目を使う計画には cases[].steps が必要")
                require(all(row["boundary"] is not None for row in expanded.values()),
                        "独立した比較項目を使う計画には models[].boundary と outputs が必要")
                inventory = read_json(args.inventory)
                validate_inventory(inventory, expanded)
                source["inventory"] = inventory
            validate_design(expanded, targets, observations, risks)
        else:
            require(not args.inventory, "--inventory を使うには --conditions が必要")
            require(not any("design" in row for row in risks.values()), "設計付きの計画には --conditions が必要")
            source = plan
        digest = hashlib.sha256(canonical_json(source).encode()).hexdigest()
        if args.phase == "plan":
            plan_report(plan["scope"], targets, observations, risks, cases, links, digest, bool(args.inventory))
            return 0
        return verify_artifacts(args.results, digest, plan["scope"], targets, observations, risks, cases, links)
    except (ValueError, OSError) as error:
        print(f"構造ゲート FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

# 現新比較テストSkill

移行やリライトで、同じ入出力の契約を持つ旧基盤と新基盤に同じテストを実行し、得られた出力を比較するためのエージェント用Skillです。

1. ルート登録、仕様、クエリなどを根拠に、どの条件で何を比較するかを決めます。設計段階で、必須項目とテスト計画の対応を検査できます。
2. 対象リポジトリのテストランナーで両基盤を実行し、採取した値から比較結果を検証します。応答に加え、データ更新や外部送信も比較できます。

エージェントへの指示とファイルの書式は [SKILL.md](SKILL.md) から参照できます。同梱のJSONは架空のシステムの例です。

## サンプル計画を確認する

リポジトリのルートで実行します。検査スクリプトはPythonの標準ライブラリを使います。

```bash
python3 scripts/check_coverage.py plan assets/plan-example.json \
  --conditions assets/conditions-example.json \
  --inventory assets/inventory-example.json
```

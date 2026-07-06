# NOTE: this file writes JS source containing `eval(...)` to disk purely as
# inert sample text for the static AST parser (esprima) to inspect. It is
# never executed, evaluated, or required by Python or Node — parsing only.
from npm_ide_analyst.static.ast_analysis import analyze_ast, deminify


def test_flags_eval_via_ast(tmp_path):
    (tmp_path / "a.js").write_text("var x = 1; eval(atobResult);", encoding="utf-8")
    findings = analyze_ast(tmp_path)
    assert any(f.category == "dynamic-code" and "eval" in f.detail for f in findings)


def test_flags_dynamic_require(tmp_path):
    (tmp_path / "b.js").write_text("const m = require(name + 'x');", encoding="utf-8")
    findings = analyze_ast(tmp_path)
    assert any(f.category == "dynamic-require" for f in findings)


def test_literal_require_not_flagged(tmp_path):
    (tmp_path / "c.js").write_text("const fs = require('fs');", encoding="utf-8")
    findings = analyze_ast(tmp_path)
    assert not any(f.category == "dynamic-require" for f in findings)


def test_deminify_expands_one_liner():
    out = deminify("function f(){return 1;}")
    assert out.count("\n") >= 1

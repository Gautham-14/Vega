"""Quality checks inspect generated syntax, never run generated programs."""

import json
from pathlib import Path

import pytest

from scripts.local_model_evaluation import answer_check, load_suite


def test_reviewed_synthetic_suite():
    cases = load_suite(
        Path(__file__).resolve().parents[1] / "evaluations/local-routing-public.json"
    )
    assert len(cases) == 12 and {case["role"] for case in cases} == {"text", "code", "vision"}


@pytest.mark.parametrize(
    "kind,text,expected",
    [
        ("python-square", "```python\ndef square(x):\n    return x * x\n```", True),
        ("python-square", "def square(x):\n    return x ** 2", True),
        ("python-square", "def square(x):\n    return x * 2", False),
        ("python-square", "import os\nos.remove('anything')", False),
        ("python-add", "def add(a, b):\n    return b + a", True),
        ("python-add", "def add(a, b):\n    return a - b", False),
        ("python-add", "Use addition to combine two numbers", False),
    ],
)
def test_code_checks(kind, text, expected):
    assert answer_check(text, {"kind": kind, "groups": []}) is expected


def test_fact_checks_use_word_boundaries():
    check = {"kind": "contains", "groups": [["red"]]}
    assert answer_check("The image is red.", check)
    assert not answer_check("It is colored blue.", check)


def test_suite_rejects_executable_checks(tmp_path):
    case = {
        "id": "unsafe",
        "role": "text",
        "prompt": "synthetic",
        "color": None,
        "check": {"kind": "exec", "groups": []},
    }
    path = tmp_path / "suite.json"
    path.write_text(json.dumps({"schema": 1, "cases": [case]}), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported answer check"):
        load_suite(path)

"""Small, repeatable synthetic quality checks; never execute generated code."""

import ast
import json
import re

from aegis.security.private_files import no_links


def load_suite(path):
    path = no_links(path)
    if path.stat().st_size > 65536:
        raise ValueError("Local evaluation suite is too large")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"schema", "cases"} or value["schema"] != 1:
        raise ValueError("Use a schema-1 local evaluation suite")
    cases = value["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= 40:
        raise ValueError("Use 1-40 synthetic evaluation cases")
    identities = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"id", "role", "prompt", "color", "check"}:
            raise ValueError("Invalid local evaluation case")
        if (
            not isinstance(case["id"], str)
            or not re.fullmatch(r"[a-z0-9-]{1,64}", case["id"])
            or case["id"] in identities
            or case["role"] not in {"text", "code", "vision"}
            or not isinstance(case["prompt"], str)
            or not 1 <= len(case["prompt"]) <= 2000
            or case["color"] not in {None, "red", "blue", "green"}
            or (case["role"] == "vision") != (case["color"] is not None)
        ):
            raise ValueError("Invalid evaluation identity, modality or prompt")
        identities.add(case["id"])
        check = case["check"]
        if not isinstance(check, dict) or set(check) != {"kind", "groups"}:
            raise ValueError("Invalid evaluation answer check")
        if check["kind"] not in {"contains", "python-square", "python-add"}:
            raise ValueError("Unsupported answer check")
        groups = check["groups"]
        if not isinstance(groups, list) or len(groups) > 16:
            raise ValueError("Invalid answer-check groups")
        for group in groups:
            if not isinstance(group, list) or not 1 <= len(group) <= 8:
                raise ValueError("Use bounded, nonempty answer-check groups")
            if any(not isinstance(word, str) or not 1 <= len(word) <= 80 for word in group):
                raise ValueError("Use bounded answer-check strings")
    return cases


def answer_check(text, check):
    if not isinstance(text, str) or not text.strip():
        return False
    if check["kind"] == "contains":
        # Every group needs at least one whole-word phrase. These narrow checks
        # are a regression probe, not a semantic/domain accuracy certification.
        return all(
            any(re.search(r"(?<!\w)" + re.escape(word) + r"(?!\w)", text, re.I) for word in group)
            for group in check["groups"]
        )
    snippets = re.findall(r"```(?:python|py)?\s*\n(.*?)```", text, re.S | re.I) or [text]
    for snippet in snippets:
        try:
            tree = ast.parse(snippet.strip())
        except (SyntaxError, ValueError):
            continue
        # Inspect a narrow pure function shape without eval/exec, imports or
        # calls. This does not execute an untrusted model response on the host.
        if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
            continue
        function = tree.body[0]
        args = function.args
        body = function.body
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            body = body[1:]  # Allow a function docstring.
        if (
            function.decorator_list
            or args.posonlyargs
            or args.kwonlyargs
            or args.defaults
            or args.vararg
            or args.kwarg
            or len(body) != 1
            or not isinstance(body[0], ast.Return)
            or not isinstance(body[0].value, ast.BinOp)
        ):
            continue
        expression = body[0].value
        names = [arg.arg for arg in args.args]
        if check["kind"] == "python-add" and len(names) == 2:
            if (
                isinstance(expression.op, ast.Add)
                and isinstance(expression.left, ast.Name)
                and isinstance(expression.right, ast.Name)
                and {expression.left.id, expression.right.id} == set(names)
            ):
                return True
        elif check["kind"] == "python-square" and len(names) == 1:
            if isinstance(expression.left, ast.Name) and expression.left.id == names[0]:
                if (
                    isinstance(expression.op, ast.Mult)
                    and isinstance(expression.right, ast.Name)
                    and expression.right.id == names[0]
                ) or (
                    isinstance(expression.op, ast.Pow)
                    and isinstance(expression.right, ast.Constant)
                    and type(expression.right.value) is int
                    and expression.right.value == 2
                ):
                    return True
    return False

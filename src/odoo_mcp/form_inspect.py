"""Pure helpers behind the ``inspect_record_form`` tool.

Nothing in here talks to Odoo.  The module parses a *combined* form arch (the
result of ``get_view``, i.e. after every inherited view and customisation was
applied and after Odoo removed the nodes the user's groups may not see),
evaluates view modifiers against known record values with a three-valued
logic, and shapes field values for an agent.

The guiding rule: a modifier that cannot be evaluated reliably is never
reported as a plain ``visible``/``hidden`` — it becomes ``conditional`` (no
record to evaluate against) or ``unknown`` (record present, expression not
decidable), and the expression is returned with it.
"""

from __future__ import annotations

import ast
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

VISIBLE = "visible"
HIDDEN = "hidden"
CONDITIONAL = "conditional"
UNKNOWN_STATE = "unknown"

# Sub-view tags that may be embedded in an x2many <field>.  'tree' is the
# pre-18 spelling of 'list'; customised views still carry it.
SUBVIEW_TAGS = ("list", "tree", "form", "kanban")
LIST_SUBVIEW_TAGS = ("list", "tree")

X2MANY_TYPES = ("one2many", "many2many")
LONG_TEXT_TYPES = ("text", "html", "char")

_STATIC_TRUE = {"1", "true"}
_STATIC_FALSE = {"0", "false", ""}


class _Unknown:
    """Sentinel for "this sub-expression cannot be decided"."""

    _instance: Optional["_Unknown"] = None

    def __new__(cls) -> "_Unknown":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "UNKNOWN"


UNKNOWN = _Unknown()


# ----- modifier expressions ------------------------------------------------


def static_modifier(expression: Optional[str]) -> Optional[bool]:
    """Return True/False for a literal modifier, None for a dynamic one."""
    if expression is None:
        return False
    text = expression.strip().lower()
    if text in _STATIC_TRUE:
        return True
    if text in _STATIC_FALSE:
        return False
    return None


MAX_EXPRESSION_CHARS = 4000
_PARSE_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError)


def _parse_expression(expression: str) -> Optional[ast.AST]:
    """Parse a modifier; a hostile or broken one is 'undecidable', not a crash."""
    text = expression.strip()
    if len(text) > MAX_EXPRESSION_CHARS:
        return None
    try:
        return ast.parse(text, mode="eval")
    except _PARSE_ERRORS:
        return None


def expression_field_names(expression: str) -> List[str]:
    """Bare names an expression reads (candidates for record fields)."""
    tree = _parse_expression(expression)
    if tree is None:
        return []
    names: List[str] = []
    skip: set[int] = set()
    for node in ast.walk(tree):
        # ``parent.x`` / ``context.get`` read another namespace, not a field.
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            skip.add(id(node.value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and id(node) not in skip:
            if node.id not in names:
                names.append(node.id)
    return names


def _truth(value: Any) -> Any:
    return UNKNOWN if value is UNKNOWN else bool(value)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _differs_from_web_client(operator: ast.cmpop, left: Any, right: Any) -> bool:
    """Comparisons where Python and Odoo's py.js interpreter disagree.

    py.js compares arrays by identity (``tag_ids == []`` is always false
    there) and does not equate booleans with numbers inside ``in``.
    """
    if isinstance(operator, (ast.Eq, ast.NotEq)):
        return isinstance(left, list) or isinstance(right, list)
    if isinstance(operator, (ast.In, ast.NotIn)) and isinstance(right, list):
        if isinstance(left, list):
            return True
        # Only the pairs Python equates across kinds matter: True/1, False/0.
        if isinstance(left, bool):
            return any(_is_number(i) and i == left for i in right)
        if _is_number(left):
            return any(isinstance(i, bool) and i == left for i in right)
    return False


def _eval_node(node: ast.AST, names: Dict[str, Any]) -> Any:
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, names)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in ("True", "False", "None"):  # pragma: no cover - py<3.8
            return {"True": True, "False": False, "None": None}[node.id]
        return names.get(node.id, UNKNOWN)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = [_eval_node(item, names) for item in node.elts]
        if any(item is UNKNOWN for item in items):
            return UNKNOWN
        return items
    if isinstance(node, ast.UnaryOp):
        operand = _eval_node(node.operand, names)
        if operand is UNKNOWN:
            return UNKNOWN
        if isinstance(node.op, ast.Not):
            return not operand
        if isinstance(node.op, ast.USub) and isinstance(operand, (int, float)):
            return -operand
        return UNKNOWN
    if isinstance(node, ast.BoolOp):
        values = [_eval_node(value, names) for value in node.values]
        if isinstance(node.op, ast.Or):
            # Any decided-true operand decides the whole 'or', even next to
            # an undecidable one.
            for value in values:
                if value is not UNKNOWN and value:
                    return value
            if any(value is UNKNOWN for value in values):
                return UNKNOWN
            return values[-1]
        for value in values:
            if value is not UNKNOWN and not value:
                return value
        if any(value is UNKNOWN for value in values):
            return UNKNOWN
        return values[-1]
    if isinstance(node, ast.IfExp):
        test = _eval_node(node.test, names)
        if test is UNKNOWN:
            return UNKNOWN
        return _eval_node(node.body if test else node.orelse, names)
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, names)
        for operator, comparator in zip(node.ops, node.comparators):
            right = _eval_node(comparator, names)
            if left is UNKNOWN or right is UNKNOWN:
                return UNKNOWN
            if _differs_from_web_client(operator, left, right):
                return UNKNOWN
            try:
                if isinstance(operator, ast.Eq):
                    result = left == right
                elif isinstance(operator, ast.NotEq):
                    result = left != right
                elif isinstance(operator, ast.In):
                    result = left in right
                elif isinstance(operator, ast.NotIn):
                    result = left not in right
                elif isinstance(operator, ast.Lt):
                    result = left < right
                elif isinstance(operator, ast.LtE):
                    result = left <= right
                elif isinstance(operator, ast.Gt):
                    result = left > right
                elif isinstance(operator, ast.GtE):
                    result = left >= right
                else:
                    return UNKNOWN
            except TypeError:
                # JS and Python disagree on mixed-type ordering; do not guess.
                return UNKNOWN
            if not result:
                return False
            left = right
        return True
    # Calls (context.get, len, ...), attributes (parent.x), arithmetic,
    # subscripts: not decidable from the record alone.
    return UNKNOWN


def evaluate_modifier(expression: str, names: Dict[str, Any]) -> Any:
    """Evaluate a modifier expression to True, False or ``UNKNOWN``."""
    tree = _parse_expression(expression)
    if tree is None:
        return UNKNOWN
    try:
        return _truth(_eval_node(tree, names))
    except (Exception, RecursionError):  # noqa: BLE001 - "unknown", not a crash
        return UNKNOWN


def evaluation_value(field_type: str, value: Any) -> Any:
    """Map an RPC ``read`` value to what the web client evaluates against."""
    if field_type == "many2one":
        if isinstance(value, (list, tuple)) and value:
            return value[0]
        return False
    if field_type in X2MANY_TYPES:
        return list(value) if isinstance(value, (list, tuple)) else []
    if value is None:
        return False
    return value


def resolve_flag(
    expression: Optional[str],
    names: Optional[Dict[str, Any]],
) -> Tuple[Any, Optional[str]]:
    """Resolve a modifier to (True | False | 'conditional' | 'unknown', condition)."""
    static = static_modifier(expression)
    if static is not None:
        return static, None
    assert expression is not None
    if names is None:
        return CONDITIONAL, expression
    result = evaluate_modifier(expression, names)
    if result is UNKNOWN:
        return UNKNOWN_STATE, expression
    return bool(result), expression


# ----- arch parsing --------------------------------------------------------


@dataclass
class Condition:
    source: str
    expression: str


@dataclass
class Occurrence:
    name: str
    section_path: List[str]
    attrs: Dict[str, str]
    ancestor_static_hidden: bool
    ancestor_conditions: List[Condition]
    subview_columns: List[Dict[str, Any]] = field(default_factory=list)
    subview_types: List[str] = field(default_factory=list)
    index: int = 1
    total: int = 1


def _section_token(node: ET.Element) -> Optional[str]:
    tag = node.tag
    label = (node.get("string") or "").strip()
    name = (node.get("name") or "").strip()
    if tag in ("header", "sheet", "footer"):
        return tag
    if tag == "page":
        return f"page:{label or name or '?'}"
    if tag == "group":
        if label or name:
            return f"group:{label or name}"
        return None
    if tag == "setting":
        return f"setting:{label or name or '?'}"
    if tag == "block":
        return f"block:{label or node.get('title') or name or '?'}"
    if tag == "div" and name == "button_box":
        return "button_box"
    return None


def _subview_columns(list_node: ET.Element) -> List[Dict[str, Any]]:
    columns: List[Dict[str, Any]] = []
    seen: set[str] = set()
    # Direct children only: fields below <groupby> or a nested sub-view belong
    # to another model.
    for column in list_node.findall("field"):
        name = column.get("name")
        if not name or name in seen:
            continue
        seen.add(name)
        hidden = column.get("column_invisible") or column.get("invisible")
        columns.append({
            "name": name,
            "label": column.get("string"),
            "static_hidden": static_modifier(hidden) is True,
        })
    return columns


def parse_form_arch(arch: str) -> Tuple[List[Occurrence], Dict[str, str]]:
    """Walk a combined form arch in document order.

    Returns the field occurrences (fields embedded in x2many sub-views are
    *not* occurrences of the parent model; their list columns are attached to
    the x2many occurrence instead) and the root <form> attributes.
    """
    root = ET.fromstring(arch.encode("utf-8") if isinstance(arch, str) else arch)
    if root.tag != "form":
        # get_view runs sudo and accepts any view_id; the arch root is the one
        # check that needs no ir.ui.view access.
        raise ValueError(f"The view is a <{root.tag}> view, not a form view")
    occurrences: List[Occurrence] = []

    def walk(
        node: ET.Element,
        path: List[str],
        static_hidden: bool,
        conditions: List[Condition],
    ) -> None:
        separator: Optional[str] = None
        for child in node:
            if not isinstance(child.tag, str):
                continue
            if child.tag == "separator":
                label = (child.get("string") or "").strip()
                separator = f"separator:{label}" if label else None
                continue
            child_path = path + [separator] if separator else list(path)
            if child.tag == "field":
                name = child.get("name")
                if not name:
                    continue
                occurrence = Occurrence(
                    name=name,
                    section_path=child_path,
                    attrs=dict(child.attrib),
                    ancestor_static_hidden=static_hidden,
                    ancestor_conditions=list(conditions),
                )
                for sub in child:
                    if sub.tag in SUBVIEW_TAGS:
                        occurrence.subview_types.append(sub.tag)
                        if sub.tag in LIST_SUBVIEW_TAGS and not occurrence.subview_columns:
                            occurrence.subview_columns = _subview_columns(sub)
                occurrences.append(occurrence)
                continue
            token = _section_token(child)
            next_path = child_path + [token] if token else child_path
            next_hidden = static_hidden
            next_conditions = conditions
            invisible = child.get("invisible")
            if invisible is not None:
                static = static_modifier(invisible)
                if static is True:
                    next_hidden = True
                elif static is None:
                    source = token or child.tag
                    next_conditions = conditions + [Condition(source, invisible)]
            walk(child, next_path, next_hidden, next_conditions)

    try:
        walk(root, ["form"], False, [])
    except RecursionError as exc:
        raise ValueError("The form arch is nested too deeply to inspect") from exc

    totals: Dict[str, int] = {}
    for occurrence in occurrences:
        totals[occurrence.name] = totals.get(occurrence.name, 0) + 1
    counters: Dict[str, int] = {}
    for occurrence in occurrences:
        counters[occurrence.name] = counters.get(occurrence.name, 0) + 1
        occurrence.index = counters[occurrence.name]
        occurrence.total = totals[occurrence.name]
    return occurrences, dict(root.attrib)


def referenced_names(occurrences: Iterable[Occurrence]) -> List[str]:
    """Every name any modifier on or above a field occurrence reads."""
    names: List[str] = []
    for occurrence in occurrences:
        expressions = [
            occurrence.attrs.get(key) for key in ("invisible", "readonly", "required")
        ]
        expressions.extend(c.expression for c in occurrence.ancestor_conditions)
        for expression in expressions:
            if not expression or static_modifier(expression) is not None:
                continue
            for name in expression_field_names(expression):
                if name not in names:
                    names.append(name)
    return names


def occurrence_visibility(
    occurrence: Occurrence, names: Optional[Dict[str, Any]]
) -> Tuple[str, Optional[str], List[Dict[str, str]]]:
    """Combine the field's own and its ancestors' ``invisible`` modifiers.

    Returns (visibility, own condition, undecided-or-dynamic ancestor
    conditions).  Hidden wins, then unknown, then conditional.
    """
    own, own_condition = resolve_flag(occurrence.attrs.get("invisible"), names)
    states: List[Any] = [True if occurrence.ancestor_static_hidden else False, own]
    inherited: List[Dict[str, str]] = []
    for condition in occurrence.ancestor_conditions:
        state, _ = resolve_flag(condition.expression, names)
        states.append(state)
        inherited.append({
            "source": condition.source,
            "condition": condition.expression,
            "result": (
                state if isinstance(state, str) else ("hidden" if state else "visible")
            ),
        })
    if any(state is True for state in states):
        visibility = HIDDEN
    elif UNKNOWN_STATE in states:
        visibility = UNKNOWN_STATE
    elif CONDITIONAL in states:
        visibility = CONDITIONAL
    else:
        visibility = VISIBLE
    return visibility, own_condition, inherited


def resolve_readonly(
    expression: Optional[str], metadata_flag: bool, names: Optional[Dict[str, Any]]
) -> Tuple[Any, Optional[str]]:
    """Readonly as the web client decides it (web/views/fields/field.js).

    The model flag only applies when the view carries no ``readonly``
    attribute; ``readonly="0"`` makes a model-readonly field editable.
    """
    if expression is None:
        return bool(metadata_flag), None
    return resolve_flag(expression, names)


def resolve_required(
    expression: Optional[str], metadata_flag: bool, names: Optional[Dict[str, Any]]
) -> Tuple[Any, Optional[str]]:
    """Required is sticky: the ORM enforces a model-level required on write."""
    flag, condition = resolve_flag(expression, names)
    return (True if metadata_flag else flag), condition


# ----- value shaping -------------------------------------------------------


_BIN_SIZE_RE = re.compile(r"^\d+(?:[.,]\d+)?\s*(?:bytes|[KMGT]b)$", re.IGNORECASE)
_DATA_URI_RE = re.compile(
    r"data:[^,;\s\"']*(?:;[^,;\s\"']+)*;base64,[A-Za-z0-9+/=\s]{64,}"
)


def scrub_inline_base64(value: Any) -> Tuple[Any, int]:
    """Replace inline ``data:...;base64,`` payloads in html/text values."""
    if not isinstance(value, str) or ";base64," not in value:
        return value, 0
    return _DATA_URI_RE.subn("[inline base64 omitted]", value)


def decode_x2many_default(value: Any) -> Tuple[List[int], int]:
    """ids and number of new rows of a ``default_get`` x2many value.

    default_get answers with commands such as ``[[6, 0, [1, 2]]]`` or
    ``[[0, 0, {...}]]``, not with a plain id list.
    """
    ids: List[int] = []
    new_rows = 0
    for item in value if isinstance(value, (list, tuple)) else []:
        if isinstance(item, int) and not isinstance(item, bool):
            ids.append(item)
        elif isinstance(item, (list, tuple)) and item:
            command = item[0]
            if command == 6 and len(item) > 2 and isinstance(item[2], (list, tuple)):
                ids.extend(i for i in item[2] if isinstance(i, int))
            elif command in (1, 4) and len(item) > 1 and isinstance(item[1], int):
                ids.append(item[1])
            elif command == 0:
                new_rows += 1
    return ids, new_rows


def shape_binary(value: Any) -> Dict[str, Any]:
    """Presence and size of a binary read with ``bin_size`` — never content."""
    if not value:
        return {"present": False}
    shaped: Dict[str, Any] = {"present": True}
    if isinstance(value, str) and _BIN_SIZE_RE.match(value.strip()):
        # bin_size answers with a human readable size such as '12.30 Kb'.
        # Anything else is content of a compute that ignored bin_size.
        shaped["size"] = value.strip()
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        shaped["size_bytes"] = value
    else:
        shaped["content_omitted"] = True
    return shaped


def is_empty_value(field_type: str, value: Any) -> bool:
    if field_type == "binary":
        return not (isinstance(value, dict) and value.get("present"))
    if field_type in X2MANY_TYPES:
        return not (
            isinstance(value, dict) and (value.get("count") or value.get("new_rows"))
        )
    if field_type == "boolean":
        return False
    if field_type in ("integer", "float", "monetary"):
        return value is None
    return value in (False, None, "", [], {})


def selection_label(metadata: Dict[str, Any], value: Any) -> Optional[str]:
    for option in metadata.get("selection") or []:
        if isinstance(option, (list, tuple)) and len(option) == 2 and option[0] == value:
            return str(option[1])
    return None


def chunked(items: List[str], size: int) -> List[List[str]]:
    size = max(1, size)
    return [items[i:i + size] for i in range(0, len(items), size)]


def payload_chars(payload: Any) -> int:
    return len(json.dumps(payload, ensure_ascii=False, default=str))

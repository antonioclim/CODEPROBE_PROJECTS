#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CodeProbe v2.0.0
================
Browser-oriented heuristic analyser for source code and Markdown.

The engine is designed for execution inside Pyodide and uses only the Python
standard library. It preserves the registry-based metric architecture of the
original browser build and extends the analysis to C, C++, C# and Markdown.

The output is probabilistic. It supports local classroom screening and code
quality review, but it is not evidence of misconduct.
"""

from __future__ import annotations

import ast
import io
import json
import keyword
import math
import re
import statistics
import time
import tokenize
from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Type

APP_NAME = "CodeProbe"
APP_VERSION = "2.0.0"
APP_TITLE = f"{APP_NAME} v{APP_VERSION}"
DEFAULT_PROFILE = "default"
DEFAULT_REGISTERS_X64 = 13

SUPPORTED_LANGUAGES = (
    "python",
    "javascript",
    "bash",
    "c",
    "cpp",
    "csharp",
    "markdown",
)
LANGUAGE_LABELS = {
    "auto": "Auto",
    "python": "Python",
    "javascript": "JavaScript",
    "bash": "Bash",
    "c": "C",
    "cpp": "C++",
    "csharp": "C#",
    "markdown": "Markdown",
    "unknown": "Unknown",
}
VERDICTS = {
    "low": "Low probability of AI generation or assistance",
    "moderate": "Moderate probability — mixed signals",
    "elevated": "Elevated probability of AI assistance",
    "high": "Very high probability of AI generation",
    "insufficient": "Insufficient data for a robust verdict",
}

PYTHON_EXTENSIONS = {"py", "pyw"}
JAVASCRIPT_EXTENSIONS = {"js", "mjs", "cjs", "jsx", "ts", "tsx"}
BASH_EXTENSIONS = {"sh", "bash", "zsh", "ksh"}
C_EXTENSIONS = {"c", "h"}
CPP_EXTENSIONS = {"cpp", "cxx", "cc", "hpp", "hxx", "hh"}
CSHARP_EXTENSIONS = {"cs"}
MARKDOWN_EXTENSIONS = {"md", "markdown"}

SOFT_KEYWORDS_PYTHON = {"match", "case"}
PYTHON_CONTROL_KEYWORDS = {
    "if", "elif", "else", "for", "while", "try", "except", "finally", "with", "match", "case",
}
PYTHON_DECLARATIVE_KEYWORDS = {
    "import", "from", "def", "class", "global", "nonlocal", "async def", "@",
}
JAVASCRIPT_CONTROL_KEYWORDS = {
    "if", "else", "for", "while", "switch", "case", "catch", "try", "finally", "do",
}
JAVASCRIPT_DECLARATIVE_KEYWORDS = {
    "import", "export", "const", "let", "var", "function", "class",
}
BASH_CONTROL_KEYWORDS = {
    "if", "then", "elif", "else", "fi", "for", "while", "until", "case", "select", "do", "done", "esac",
}
BASH_DECLARATIVE_KEYWORDS = {
    "readonly", "local", "declare", "typeset", "export", "source", ".",
}
C_CONTROL_KEYWORDS = {
    "if", "else", "for", "while", "switch", "case", "default", "do", "goto",
}
C_DECLARATIVE_KEYWORDS = {
    "#include", "#define", "#ifdef", "#ifndef", "#endif", "#if", "#elif", "#else",
    "typedef", "struct", "union", "enum", "static", "extern", "register", "const", "volatile",
}
CPP_CONTROL_KEYWORDS = C_CONTROL_KEYWORDS | {"try", "catch", "throw"}
CPP_DECLARATIVE_KEYWORDS = C_DECLARATIVE_KEYWORDS | {
    "namespace", "template", "class", "using", "constexpr", "inline", "friend", "virtual", "typename",
}
CSHARP_CONTROL_KEYWORDS = {
    "if", "else", "for", "foreach", "while", "switch", "case", "default", "do", "try", "catch", "finally", "lock",
}
CSHARP_DECLARATIVE_KEYWORDS = {
    "using", "namespace", "class", "struct", "interface", "enum", "record", "delegate",
    "public", "private", "protected", "internal", "static", "readonly", "const", "partial", "sealed", "abstract",
}

LANGUAGE_KEYWORDS: Dict[str, Set[str]] = {
    "python": set(keyword.kwlist) | SOFT_KEYWORDS_PYTHON,
    "javascript": JAVASCRIPT_CONTROL_KEYWORDS | JAVASCRIPT_DECLARATIVE_KEYWORDS | {
        "return", "new", "await", "async", "throw", "break", "continue", "default",
        "typeof", "instanceof", "delete", "yield", "null", "undefined", "true", "false",
    },
    "bash": BASH_CONTROL_KEYWORDS | BASH_DECLARATIVE_KEYWORDS | {"return", "read", "test", "printf", "echo", "trap", "shift", "exit", "in"},
    "c": C_CONTROL_KEYWORDS | C_DECLARATIVE_KEYWORDS | {
        "return", "break", "continue", "sizeof", "void", "char", "short", "int", "long",
        "float", "double", "signed", "unsigned", "bool", "_Bool", "auto", "restrict",
    },
    "cpp": CPP_CONTROL_KEYWORDS | CPP_DECLARATIVE_KEYWORDS | {
        "return", "break", "continue", "sizeof", "void", "char", "short", "int", "long",
        "float", "double", "signed", "unsigned", "bool", "auto", "decltype", "new", "delete",
        "operator", "nullptr", "this", "public", "private", "protected", "override", "final",
    },
    "csharp": CSHARP_CONTROL_KEYWORDS | CSHARP_DECLARATIVE_KEYWORDS | {
        "return", "break", "continue", "new", "this", "base", "void", "bool", "byte", "char",
        "decimal", "double", "float", "int", "long", "object", "sbyte", "short", "string",
        "uint", "ulong", "ushort", "var", "async", "await", "null", "true", "false",
    },
}

GENERIC_COMMENT_PATTERNS = [
    re.compile(r"^(?:define|create|initiali[sz]e|set\s+up|import|load|configure|main)\b", re.I),
    re.compile(r"^(?:function|class|method|variable|module|helper)\b", re.I),
    re.compile(r"^this\s+(?:function|method|class|code)\b", re.I),
    re.compile(r"^(?:the\s+following|below|above|here\s+we)\b", re.I),
    re.compile(r"^(?:step\s+\d+|example|note:)\b", re.I),
    re.compile(r"^(?:get|set|check|validate|process|handle|parse|convert|calculate|ensure|verify)\b", re.I),
]
HUMAN_COMMENT_MARKERS = [
    re.compile(r"^(?:TODO|FIXME|HACK|XXX|TEMP|WTF|KLUDGE|UGLY)\b", re.I),
]
COMMENTED_OUT_CODE_PATTERNS = [
    re.compile(r"^(?:if|for|while|try|except|catch|return|print|echo|const|let|var|function|def|class|import|from|export|switch|case)\b"),
    re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*.+"),
    re.compile(r"^\w+\(.*\)\s*\{?$"),
]

RE_JS_IDENTIFIERS = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")
RE_BASH_IDENTIFIERS = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
RE_GENERIC_IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
RE_CSHARP_IDENTIFIER = re.compile(r"\b@?[A-Za-z_][A-Za-z0-9_]*\b")
RE_NUMBER = re.compile(r"(?<![A-Za-z_])[-+]?(?:0x[0-9A-Fa-f]+|\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)(?![A-Za-z_])")
RE_PY_FUNCTION_LINE = re.compile(r"^\s*(?:async\s+def|def)\s+")
RE_JS_FUNCTION_START = re.compile(
    r"(?:^|[;\n])\s*(?:function\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\(|(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*(?:async\s+)?(?:\([^\n]*?\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*\{)",
    re.M,
)
RE_BASH_FUNCTION_START = re.compile(
    r"(?:^|\n)\s*(?:function\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\(\))?\s*\{|[A-Za-z_][A-Za-z0-9_]*\s*\(\)\s*\{)",
    re.M,
)

REFERENCE_LIBRARY: Dict[str, str] = {
    "rahman_detection": "Rahman, M., Khatoonabadi, S. H., Abdellatif, A. and Shihab, E. (2024). Automatic Detection of LLM-Generated Code: A Case Study of Claude 3 Haiku. arXiv. https://doi.org/10.48550/arXiv.2409.01382",
    "mccabe": "McCabe, T. J. (1976). A complexity measure. IEEE Transactions on Software Engineering, SE-2(4), 308–320. https://doi.org/10.1109/TSE.1976.233837",
    "halstead": "Halstead, M. H. (1977). Elements of Software Science. Elsevier North-Holland.",
    "buse_weimer": "Buse, R. P. L. and Weimer, W. (2010). Learning a metric for code readability. IEEE Transactions on Software Engineering, 36(4), 546–558. https://doi.org/10.1109/TSE.2009.70",
    "chaitin": "Chaitin, G. J., Auslander, M. A., Chandra, A. K., Cocke, J., Hopkins, M. E. and Markstein, P. W. (1982). Register allocation and spilling via graph colouring. SIGPLAN Symposium on Compiler Construction. https://doi.org/10.1145/872726.806984",
    "poletto": "Poletto, M. and Sarkar, V. (1999). Linear scan register allocation. ACM Transactions on Programming Languages and Systems, 21(5), 895–913. https://doi.org/10.1145/330249.330250",
    "aho": "Aho, A. V., Lam, M. S., Sethi, R. and Ullman, J. D. (2006). Compilers: Principles, Techniques and Tools (2nd ed.). Pearson.",
    "muchnick": "Muchnick, S. S. (1997). Advanced Compiler Design and Implementation. Morgan Kaufmann.",
    "pep8": "van Rossum, G., Warsaw, B. and Coghlan, N. (2001). PEP 8 – Style Guide for Python Code. Python Software Foundation.",
    "pep257": "Goodger, D. and van Rossum, G. (2001). PEP 257 – Docstring Conventions. Python Software Foundation.",
    "pep484": "van Rossum, G., Lehtosalo, J. and Langa, Ł. (2014). PEP 484 – Type Hints. Python Software Foundation.",
    "c99": "ISO/IEC 9899:1999. Programming languages — C.",
    "cpp_core": "ISO/IEC 14882. Programming languages — C++.",
    "csharp_spec": "Microsoft. C# language specification.",
    "commonmark": "CommonMark Specification. CommonMark project.",
}


METRIC_CONFIG: Dict[str, Dict[str, Any]] = {
    "line_length_uniformity": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {"ai_low": 0.22, "ai_high": 0.45, "human_high": 0.70},
        "notes": "Low variance can indicate templated structure, but disciplined humans and formatters can look similar.",
    },
    "comment_density": {
        "enabled": True,
        "weight": 0.02,
        "thresholds": {"ai_low": 0.12, "ai_high": 0.32, "human_low": 0.03},
        "notes": "A companion to the literature-backed comment-to-code ratio.",
    },
    "comment_genericness": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {"ai_low": 0.20, "ai_high": 0.50},
        "notes": "Formulaic explanatory comments are common in LLM output.",
    },
    "blank_line_regularity": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {"ai_low": 0.18, "ai_high": 0.55},
        "notes": "Repeatedly regular blank-line spacing can suggest templated production.",
    },
    "lexical_entropy": {
        "enabled": True,
        "weight": 0.02,
        "thresholds": {"ai_low": 3.8, "ai_high": 4.5},
        "notes": "Exploratory token entropy. The weight remains low by design.",
    },
    "error_handling_density": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {"ai_low": 0.4, "ai_high": 1.8},
        "notes": "LLMs often add explicit guards and error wrappers more systematically than students do.",
    },
    "boilerplate_presence": {
        "enabled": True,
        "weight": 0.02,
        "thresholds": {"ai_low": 0.20, "ai_high": 0.80},
        "notes": "A weak signal. Disciplined human code can also contain boilerplate.",
    },
    "identifier_style": {
        "enabled": True,
        "weight": 0.05,
        "thresholds": {"ai_low": 0.45, "ai_high": 0.80},
        "notes": "Identifier regularity and semantic adequacy can reveal templated code.",
    },
    "function_length": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {"ai_low": 8.0, "ai_high": 24.0, "cv_high": 0.55},
        "notes": "Function length and dispersion are recurring structural signals.",
    },
    "cyclomatic_complexity": {
        "enabled": True,
        "weight": 0.05,
        "thresholds": {"ai_low": 1.5, "ai_high": 4.5, "density_high": 2.6},
        "notes": "Exact AST-based McCabe for Python and approximate counting elsewhere.",
    },
    "halstead_difficulty": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {"ai_low": 8.0, "ai_high": 24.0, "mi_high": 65.0},
        "notes": "Exploratory software-science metric.",
    },
    "magic_numbers": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {"ai_low": 0.3, "ai_high": 1.4},
        "notes": "Student code often leaves more unexplained literals.",
    },
    "dead_code_residue": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {"ai_low": 0.00, "ai_high": 0.04},
        "notes": "Commented-out code and residue are more typical of incremental human drafting.",
    },
    "nesting_depth": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {"ai_low": 2.0, "ai_high": 4.0},
        "notes": "Maximum nesting recurs in interpretable detection studies.",
    },
    "defensive_programming": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {"ai_low": 0.4, "ai_high": 2.0},
        "notes": "LLMs often produce conspicuous validation scaffolding.",
    },
    "comment_to_code_ratio": {
        "enabled": True,
        "weight": 0.12,
        "thresholds": {"human_low": 0.03, "ai_low": 0.10, "ai_peak": 0.24, "ai_high": 0.40},
        "notes": "This is the strongest default stylometric signal across broad configurations.",
    },
    "declarative_ratio": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {"ai_low": 0.10, "ai_high": 0.28},
        "notes": "Moderate declaration-heavy structure can indicate scaffold-driven generation.",
    },
    "control_ratio": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {"ai_low": 0.10, "ai_high": 0.24},
        "notes": "Separated from declarative ratio to avoid conflating dimensions.",
    },
    "type_token_ratio": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {"ai_low": 0.82, "ai_high": 0.92},
        "notes": "Uses the logarithmic type-token ratio to reduce length sensitivity.",
    },
    "indentation_consistency": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {"ai_low": 0.85, "ai_high": 0.99},
        "notes": "Very regular indentation can be AI-like, but formatters produce the same effect.",
    },
    "used_import_ratio": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {"ai_low": 0.80, "ai_high": 1.00},
        "notes": "Refines the original dead-code idea with actual import-use analysis where feasible.",
    },
    "structural_self_similarity": {
        "enabled": True,
        "weight": 0.05,
        "thresholds": {"ai_low": 0.55, "ai_high": 0.82},
        "notes": "Exploratory structural repetition metric.",
    },
    "function_complexity_uniformity": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {"ai_low": 0.18, "ai_high": 0.48},
        "notes": "Low variance in per-function complexity can indicate templated generation.",
    },
    "docstring_coverage": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {"ai_low": 0.35, "ai_high": 0.80},
        "notes": "Useful, but prone to false positives in advanced or style-enforced Python work.",
    },
    "type_hint_coverage": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {"ai_low": 0.25, "ai_high": 0.75},
        "notes": "Most useful where type hints are not mandated.",
    },
    "javascript_modern_syntax": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {"ai_low": 0.55, "ai_high": 0.92},
        "notes": "A weak JavaScript-only stylistic hint.",
    },
    "bash_quoting_consistency": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {"ai_low": 0.55, "ai_high": 0.98},
        "notes": "Generated shell scripts often quote variables more consistently than students do.",
    },
    "import_organization": {
        "enabled": True,
        "weight": 0.02,
        "thresholds": {"ai_low": 0.50, "ai_high": 1.00},
        "notes": "A low-weight style signal rather than a discriminative feature on its own.",
    },
    "register_pressure": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {"low": 0.50, "moderate": 0.85},
        "notes": "Source-level estimate of live scalar pressure against a typical x86-64 register budget.",
    },
    "stack_frame_depth": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {"small": 256.0, "medium": 4096.0},
        "notes": "Estimated local stack footprint per function.",
    },
    "redundant_memory_access": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {"low": 0.40, "high": 1.60},
        "notes": "Density of repeated memory expressions, missed loop hoists and missing const or restrict opportunities.",
    },
    "code_elegance": {
        "enabled": True,
        "weight": 0.05,
        "thresholds": {},
        "notes": "Composite quality metric based on naming, cohesion, duplication, literals and guard style.",
    },
    "preprocessor_hygiene": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {},
        "notes": "Composite quality metric for include guards, macro use, conditional depth and include ordering.",
    },
    "markdown_heading_structure": {
        "enabled": True,
        "weight": 0.04,
        "thresholds": {},
        "notes": "Assesses heading hierarchy and regularity.",
    },
    "markdown_code_fence_density": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {"low": 0.5, "high": 4.0},
        "notes": "Assesses fenced-code block density.",
    },
    "markdown_link_density": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {"low": 0.5, "high": 8.0},
        "notes": "Assesses hyperlink density in prose.",
    },
    "markdown_prose_entropy": {
        "enabled": True,
        "weight": 0.03,
        "thresholds": {"low": 3.5, "high": 4.8},
        "notes": "Assesses prose variability outside code fences.",
    },
}
SCORING_PROFILES: Dict[str, Dict[str, Dict[str, Any]]] = {
    "default": {},
    "strict": {
        "comment_to_code_ratio": {"weight": 0.14},
        "blank_line_regularity": {"weight": 0.05},
        "dead_code_residue": {"weight": 0.04},
        "docstring_coverage": {"weight": 0.02},
        "type_hint_coverage": {"weight": 0.02},
    },
    "permissive": {
        "comment_to_code_ratio": {"weight": 0.10},
        "docstring_coverage": {"weight": 0.02},
        "type_hint_coverage": {"weight": 0.02},
        "boilerplate_presence": {"weight": 0.01},
    },
}

COMMON_IDENTIFIER_WORDS = {
    "add", "all", "analyse", "analysis", "apply", "arg", "args", "array", "base", "buffer",
    "build", "cache", "calculate", "call", "case", "check", "class", "clear", "close", "code",
    "column", "config", "count", "create", "current", "data", "decode", "default", "detail",
    "detect", "display", "document", "element", "encode", "engine", "entry", "error", "event",
    "export", "file", "filter", "find", "flag", "format", "frame", "function", "guard", "handle",
    "header", "help", "hook", "index", "input", "item", "key", "label", "length", "line", "link",
    "list", "load", "local", "loop", "main", "make", "map", "match", "memory", "metric",
    "module", "name", "node", "note", "number", "offset", "open", "option", "output", "parse",
    "path", "pointer", "position", "pressure", "profile", "project", "push", "range", "read",
    "record", "register", "render", "report", "result", "return", "row", "save", "scan", "score",
    "section", "select", "set", "size", "stack", "start", "state", "step", "store", "string",
    "struct", "style", "summary", "table", "text", "token", "type", "update", "use", "user",
    "value", "view", "warning", "width", "window", "word", "write",
}

SCALAR_TYPE_SIZES: Dict[str, int] = {
    "char": 1, "signed char": 1, "unsigned char": 1, "bool": 1, "_Bool": 1,
    "short": 2, "short int": 2, "unsigned short": 2, "unsigned short int": 2,
    "int": 4, "unsigned": 4, "unsigned int": 4, "float": 4,
    "long": 8, "long int": 8, "unsigned long": 8, "unsigned long int": 8,
    "long long": 8, "long long int": 8, "unsigned long long": 8, "unsigned long long int": 8,
    "double": 8, "long double": 16, "size_t": 8, "ssize_t": 8,
    "intptr_t": 8, "uintptr_t": 8, "ptrdiff_t": 8,
    "byte": 1, "sbyte": 1, "short?": 2, "ushort": 2, "int?": 4, "uint": 4,
    "long?": 8, "ulong": 8, "float?": 4, "double?": 8, "decimal": 16, "decimal?": 16,
    "char?": 2, "bool?": 1,
}

POINTER_LIKE_TYPES = {"string", "object", "dynamic"}


@dataclass
class MetricResult:
    """Result of a single metric computation."""

    name: str
    display_name: str
    value: Optional[float]
    value_display: str
    score: float
    weight: float
    applicable: bool
    explanation: str
    detail: str = ""
    references: List[str] = field(default_factory=list)
    group: str = "stylometry"
    contributes_to_overall: bool = True


@dataclass
class FunctionInfo:
    """Precomputed per-function or per-method data."""

    name: str
    lineno: int
    end_lineno: int
    length: int
    cyclomatic: int
    has_docstring: bool = False
    has_type_hints: bool = False
    ast_signature: Counter = field(default_factory=Counter)
    signature: str = ""
    body: str = ""
    parameters: List[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.body.strip()


@dataclass
class MarkdownInfo:
    """Parsed Markdown features."""

    headings: List[Tuple[int, int, str]] = field(default_factory=list)
    code_fence_count: int = 0
    code_fence_line_count: int = 0
    link_count: int = 0
    prose_text: str = ""
    prose_word_count: int = 0


@dataclass
class AnalysisContext:
    """Shared precomputed data reused by all metrics."""

    filename: str
    language: str
    code: str
    lines: List[str]
    non_blank_lines: List[str]
    comment_lines: List[str]
    code_lines: List[str]
    comment_texts: List[str]
    cleaned_code: str
    line_categories: Dict[int, str]
    identifiers: List[str]
    tokens_operators: List[str]
    tokens_operands: List[str]
    blank_runs: List[int]
    indentation_widths: List[int]
    indentation_kinds: Counter
    declarative_line_count: int
    control_line_count: int
    executable_line_count: int
    commented_out_code_lines: int
    ast_tree: Optional[ast.AST] = None
    ast_error: str = ""
    functions: List[FunctionInfo] = field(default_factory=list)
    imported_names: Dict[str, str] = field(default_factory=dict)
    used_names: Set[str] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)
    tokenizer_error: str = ""
    markdown: MarkdownInfo = field(default_factory=MarkdownInfo)
    file_extension: str = ""

    @property
    def loc(self) -> int:
        return len(self.lines)

    @property
    def sloc(self) -> int:
        return len(self.non_blank_lines)

    @property
    def active_line_count(self) -> int:
        return len(self.comment_lines) + len(self.code_lines)


@dataclass
class AnalysisReport:
    """Aggregated analysis result."""

    filename: str
    language: str
    loc: int
    sloc: int
    metrics: List[MetricResult] = field(default_factory=list)
    overall_score: float = 0.0
    confidence: str = "low"
    verdict: str = VERDICTS["insufficient"]
    verdict_class: str = "insufficient"
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    profile: str = DEFAULT_PROFILE
    duration_seconds: float = 0.0


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def safe_div(numerator: float, denominator: float, default: float = 0.0) -> float:
    if denominator == 0:
        return default
    return numerator / denominator


def coefficient_of_variation(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean_value = statistics.mean(values)
    if mean_value == 0:
        return 0.0
    return statistics.stdev(values) / mean_value


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = float(len(text))
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def cosine_similarity(left: Counter, right: Counter) -> float:
    if not left or not right:
        return 0.0
    intersection = set(left) & set(right)
    numerator = sum(left[key] * right[key] for key in intersection)
    left_norm = math.sqrt(sum(value * value for value in left.values()))
    right_norm = math.sqrt(sum(value * value for value in right.values()))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return numerator / (left_norm * right_norm)


def bell_score(value: float, low: float, peak: float, high: float) -> float:
    if value <= low or value >= high:
        return 0.0
    if value == peak:
        return 1.0
    if value < peak:
        return clamp((value - low) / max(peak - low, 1e-9))
    return clamp((high - value) / max(high - peak, 1e-9))


def band_score(value: float, low: float, high: float, softness: float = 0.25) -> float:
    if low > high:
        low, high = high, low
    if low <= value <= high:
        return 1.0
    width = max(high - low, 1e-9)
    if value < low:
        return clamp(1.0 - ((low - value) / (width * (1.0 + softness))))
    return clamp(1.0 - ((value - high) / (width * (1.0 + softness))))


def low_cv_score(cv: float, low: float, high: float) -> float:
    if cv <= low:
        return 1.0
    if cv >= high:
        return 0.0
    return clamp(1.0 - ((cv - low) / max(high - low, 1e-9)))


def high_ratio_score(value: float, low: float, high: float) -> float:
    if value <= low:
        return 0.0
    if value >= high:
        return 1.0
    return clamp((value - low) / max(high - low, 1e-9))


def low_value_score(value: float, low: float, high: float) -> float:
    if value <= low:
        return 1.0
    if value >= high:
        return 0.0
    return clamp(1.0 - ((value - low) / max(high - low, 1e-9)))


def format_float(value: Optional[float], digits: int = 3) -> str:
    if value is None:
        return "N/A"
    return f"{value:.{digits}f}"


def normalise_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def merged_metric_config(profile: str, external_override: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Dict[str, Any]]:
    merged = json.loads(json.dumps(METRIC_CONFIG))
    for metric_name, override in SCORING_PROFILES.get(profile, {}).items():
        merged.setdefault(metric_name, {}).update(override)
    if external_override:
        for metric_name, metric_data in external_override.items():
            target = merged.setdefault(metric_name, {})
            if isinstance(metric_data, dict):
                if "thresholds" in metric_data and isinstance(metric_data["thresholds"], dict):
                    target.setdefault("thresholds", {}).update(metric_data["thresholds"])
                for key, value in metric_data.items():
                    if key == "thresholds" and isinstance(value, dict):
                        continue
                    target[key] = value
    return merged


def strip_comment_prefix(text: str) -> str:
    return re.sub(r"^(?:#|//|/\*+|\*+/|\*)\s*", "", text.strip())


def blank_runs_from_lines(lines: Sequence[str]) -> List[int]:
    runs: List[int] = []
    current = 0
    seen_non_blank = False
    for line in lines:
        if line.strip():
            if seen_non_blank and current > 0:
                runs.append(current)
            current = 0
            seen_non_blank = True
        else:
            current += 1
    return runs


def indentation_profile(lines: Sequence[str]) -> Tuple[List[int], Counter]:
    widths: List[int] = []
    kinds: Counter = Counter()
    for line in lines:
        if not line.strip():
            continue
        match = re.match(r"^[ \t]*", line)
        prefix = match.group(0) if match else ""
        widths.append(len(prefix.expandtabs(4)))
        if "\t" in prefix and " " in prefix:
            kinds["mixed"] += 1
        elif "\t" in prefix:
            kinds["tabs"] += 1
        elif " " in prefix:
            kinds["spaces"] += 1
        else:
            kinds["none"] += 1
    return widths, kinds


def count_commented_out_code(comment_texts: Sequence[str]) -> int:
    count = 0
    for raw in comment_texts:
        text = strip_comment_prefix(raw)
        if any(pattern.match(text) for pattern in COMMENTED_OUT_CODE_PATTERNS):
            count += 1
    return count


def split_identifier(identifier: str) -> List[str]:
    name = identifier.strip("_")
    if not name:
        return []
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return [part.lower() for part in re.split(r"[_\W]+", name) if part]


def identifier_style_kind(identifier: str) -> str:
    if re.match(r"^[a-z]+(?:_[a-z0-9]+)+$", identifier):
        return "snake"
    if re.match(r"^[a-z]+(?:[A-Z][a-z0-9]*)+$", identifier):
        return "camel"
    if re.match(r"^[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)*$", identifier):
        return "pascal"
    if re.match(r"^[A-Z][A-Z0-9_]*$", identifier):
        return "upper"
    return "other"


def detect_language(filename: str, code: str, hint: Optional[str] = None) -> str:
    if hint in SUPPORTED_LANGUAGES:
        return str(hint)

    lower_name = (filename or "").lower()
    extension = lower_name.rsplit(".", 1)[-1] if "." in lower_name else ""
    if extension in PYTHON_EXTENSIONS:
        return "python"
    if extension in JAVASCRIPT_EXTENSIONS:
        return "javascript"
    if extension in BASH_EXTENSIONS:
        return "bash"
    if extension in CSHARP_EXTENSIONS:
        return "csharp"
    if extension in CPP_EXTENSIONS:
        return "cpp"
    if extension in C_EXTENSIONS:
        if extension == "h":
            cpp_hits = len(re.findall(r"\b(?:namespace|template\s*<|std::|class\s+\w+|using\s+namespace|constexpr)\b", code))
            return "cpp" if cpp_hits >= 2 else "c"
        return "c"
    if extension in MARKDOWN_EXTENSIONS:
        return "markdown"

    first_line = code.split("\n", 1)[0] if code else ""
    if "python" in first_line:
        return "python"
    if "node" in first_line or "deno" in first_line:
        return "javascript"
    if "bash" in first_line or first_line.startswith("#!/bin/sh") or "/sh" in first_line:
        return "bash"

    scores = {
        "python": 0,
        "javascript": 0,
        "bash": 0,
        "c": 0,
        "cpp": 0,
        "csharp": 0,
        "markdown": 0,
    }
    scores["python"] += len(re.findall(r"(^|\n)\s*(?:def |class |import |from |if __name__ == )", code))
    scores["javascript"] += len(re.findall(r"(^|\n)\s*(?:function |const |let |var |import |export )", code))
    scores["bash"] += len(re.findall(r"(^|\n)\s*(?:#!\/bin\/(?:ba)?sh|if \[|for \w+ in|echo |export )", code))
    scores["c"] += len(re.findall(r"(^|\n)\s*#include\s*<[^>]+>|(^|\n)\s*(?:int|char|float|double|void)\s+\**\w+\s*\(", code))
    scores["c"] += len(re.findall(r"\b(?:printf|scanf|malloc|free)\s*\(", code))
    scores["cpp"] += len(re.findall(r"\b(?:namespace|template\s*<|std::|cout|cin|cerr|using\s+namespace|constexpr|typename)\b", code))
    scores["cpp"] += len(re.findall(r"#include\s*<(?:(?:iostream)|(?:vector)|(?:string)|(?:map)|(?:memory)|(?:algorithm))>", code))
    scores["csharp"] += len(re.findall(r"\b(?:using\s+System|namespace\s+\w+|public\s+class|public\s+static\s+void\s+Main|Console\.WriteLine|readonly|record)\b", code))
    scores["csharp"] += len(re.findall(r"(^|\n)\s*///", code))
    scores["markdown"] += len(re.findall(r"(^|\n)\s*#{1,6}\s+\S", code))
    scores["markdown"] += len(re.findall(r"(^|\n)\s*```", code))
    scores["markdown"] += len(re.findall(r"\[[^\]]+\]\([^)]+\)", code))
    scores["markdown"] += len(re.findall(r"(^|\n)\s*(?:[-*+]|\d+\.)\s+\S", code))

    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    return ranked[0][0] if ranked[0][1] > 0 else "unknown"


@dataclass
class ScanResult:
    cleaned_code: str
    comment_line_numbers: Set[int]
    code_line_numbers: Set[int]
    comment_texts: List[str]
    tokenizer_error: str = ""


class ScannerState:
    NORMAL = "normal"
    SINGLE = "single"
    DOUBLE = "double"
    TEMPLATE = "template"
    CHAR = "char"
    VERBATIM = "verbatim"
    RAW = "raw"
    LINE_COMMENT = "line_comment"
    BLOCK_COMMENT = "block_comment"


def _absolute_offset(text: str, line_no: int, column: int) -> int:
    if line_no <= 1:
        return column
    lines = text.split("\n")
    offset = sum(len(line) + 1 for line in lines[: line_no - 1])
    return offset + column


def scan_javascript(code: str) -> ScanResult:
    cleaned: List[str] = []
    line_no = 1
    state = ScannerState.NORMAL
    comment_line_numbers: Set[int] = set()
    code_line_numbers: Set[int] = set()
    comment_texts: List[str] = []
    comment_buffer: List[str] = []
    current_quote = ""
    escaped = False

    def flush_comment() -> None:
        if comment_buffer:
            comment_texts.append("".join(comment_buffer).strip())
            comment_buffer[:] = []

    i = 0
    length = len(code)
    while i < length:
        ch = code[i]
        nxt = code[i + 1] if i + 1 < length else ""

        if state == ScannerState.NORMAL:
            if ch == "\n":
                cleaned.append(ch)
                line_no += 1
                i += 1
                continue
            if ch in {"'", '"', "`"}:
                state = {"'": ScannerState.SINGLE, '"': ScannerState.DOUBLE, "`": ScannerState.TEMPLATE}[ch]
                current_quote = ch
                cleaned.append(" ")
                i += 1
                continue
            if ch == "/" and nxt == "/":
                state = ScannerState.LINE_COMMENT
                comment_line_numbers.add(line_no)
                comment_buffer.extend([ch, nxt])
                cleaned.extend([" ", " "])
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = ScannerState.BLOCK_COMMENT
                comment_line_numbers.add(line_no)
                comment_buffer.extend([ch, nxt])
                cleaned.extend([" ", " "])
                i += 2
                continue
            if not ch.isspace():
                code_line_numbers.add(line_no)
            cleaned.append(ch)
            i += 1
            continue

        if state in {ScannerState.SINGLE, ScannerState.DOUBLE, ScannerState.TEMPLATE}:
            if ch == "\n":
                cleaned.append("\n")
                line_no += 1
                escaped = False
                i += 1
                continue
            cleaned.append(" ")
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == current_quote:
                state = ScannerState.NORMAL
            i += 1
            continue

        if state == ScannerState.LINE_COMMENT:
            if ch == "\n":
                flush_comment()
                state = ScannerState.NORMAL
                cleaned.append("\n")
                line_no += 1
                i += 1
                continue
            comment_line_numbers.add(line_no)
            comment_buffer.append(ch)
            cleaned.append(" ")
            i += 1
            continue

        if state == ScannerState.BLOCK_COMMENT:
            if ch == "\n":
                comment_line_numbers.add(line_no)
                comment_buffer.append(ch)
                cleaned.append("\n")
                line_no += 1
                i += 1
                continue
            comment_line_numbers.add(line_no)
            comment_buffer.append(ch)
            cleaned.append(" ")
            if ch == "*" and nxt == "/":
                comment_buffer.append(nxt)
                cleaned.append(" ")
                i += 2
                flush_comment()
                state = ScannerState.NORMAL
                continue
            i += 1

    flush_comment()
    return ScanResult("".join(cleaned), comment_line_numbers, code_line_numbers, comment_texts)


def scan_bash(code: str) -> ScanResult:
    cleaned: List[str] = []
    line_no = 1
    state = ScannerState.NORMAL
    comment_line_numbers: Set[int] = set()
    code_line_numbers: Set[int] = set()
    comment_texts: List[str] = []
    comment_buffer: List[str] = []
    escaped = False
    current_quote = ""

    def flush_comment() -> None:
        if comment_buffer:
            comment_texts.append("".join(comment_buffer).strip())
            comment_buffer[:] = []

    i = 0
    length = len(code)
    while i < length:
        ch = code[i]
        prev = code[i - 1] if i > 0 else "\n"

        if state == ScannerState.NORMAL:
            if ch == "\n":
                cleaned.append(ch)
                line_no += 1
                i += 1
                continue
            if ch in {"'", '"'}:
                state = ScannerState.DOUBLE if ch == '"' else ScannerState.SINGLE
                current_quote = ch
                cleaned.append(" ")
                i += 1
                continue
            if ch == "#" and not escaped and prev != "\\":
                state = ScannerState.LINE_COMMENT
                comment_line_numbers.add(line_no)
                comment_buffer.append(ch)
                cleaned.append(" ")
                i += 1
                continue
            if not ch.isspace():
                code_line_numbers.add(line_no)
            cleaned.append(ch)
            escaped = ch == "\\" and not escaped
            i += 1
            continue

        if state in {ScannerState.SINGLE, ScannerState.DOUBLE}:
            if ch == "\n":
                cleaned.append("\n")
                line_no += 1
                escaped = False
                i += 1
                continue
            cleaned.append(" ")
            if state == ScannerState.DOUBLE and ch == "\\" and not escaped:
                escaped = True
            elif escaped:
                escaped = False
            elif ch == current_quote:
                state = ScannerState.NORMAL
            i += 1
            continue

        if state == ScannerState.LINE_COMMENT:
            if ch == "\n":
                flush_comment()
                state = ScannerState.NORMAL
                cleaned.append("\n")
                line_no += 1
                i += 1
                continue
            comment_line_numbers.add(line_no)
            comment_buffer.append(ch)
            cleaned.append(" ")
            i += 1
            continue

    flush_comment()
    return ScanResult("".join(cleaned), comment_line_numbers, code_line_numbers, comment_texts)


def scan_c_like(code: str, language: str) -> ScanResult:
    cleaned: List[str] = []
    line_no = 1
    state = ScannerState.NORMAL
    comment_line_numbers: Set[int] = set()
    code_line_numbers: Set[int] = set()
    comment_texts: List[str] = []
    comment_buffer: List[str] = []
    escaped = False
    raw_delim = ""
    current_quote = ""

    def flush_comment() -> None:
        if comment_buffer:
            comment_texts.append("".join(comment_buffer).strip())
            comment_buffer[:] = []

    i = 0
    length = len(code)
    while i < length:
        ch = code[i]
        nxt = code[i + 1] if i + 1 < length else ""
        nxt2 = code[i + 2] if i + 2 < length else ""

        if state == ScannerState.NORMAL:
            if ch == "\n":
                cleaned.append("\n")
                line_no += 1
                i += 1
                continue
            if language == "csharp" and ch == "@" and nxt == '"':
                state = ScannerState.VERBATIM
                cleaned.extend([" ", " "])
                i += 2
                continue
            if language == "csharp" and ((ch == "$" and nxt == "@") or (ch == "@" and nxt == "$")) and nxt2 == '"':
                state = ScannerState.VERBATIM
                cleaned.extend([" ", " ", " "])
                i += 3
                continue
            if language == "csharp" and ch == "$" and nxt == '"':
                state = ScannerState.DOUBLE
                current_quote = '"'
                cleaned.extend([" ", " "])
                i += 2
                continue
            if language in {"c", "cpp"} and ch == "R" and nxt == '"':
                opener = code.find("(", i + 2, min(length, i + 24))
                if opener != -1:
                    raw_delim = code[i + 2 : opener]
                    state = ScannerState.RAW
                    cleaned.extend(" " * (opener - i + 1))
                    i = opener + 1
                    continue
            if ch == "/" and nxt == "/":
                state = ScannerState.LINE_COMMENT
                comment_line_numbers.add(line_no)
                comment_buffer.extend([ch, nxt])
                cleaned.extend([" ", " "])
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = ScannerState.BLOCK_COMMENT
                comment_line_numbers.add(line_no)
                comment_buffer.extend([ch, nxt])
                cleaned.extend([" ", " "])
                i += 2
                continue
            if ch == "'":
                state = ScannerState.CHAR
                current_quote = "'"
                cleaned.append(" ")
                i += 1
                continue
            if ch == '"':
                state = ScannerState.DOUBLE
                current_quote = '"'
                cleaned.append(" ")
                i += 1
                continue
            if not ch.isspace():
                code_line_numbers.add(line_no)
            cleaned.append(ch)
            i += 1
            continue

        if state == ScannerState.DOUBLE:
            if ch == "\n":
                cleaned.append("\n")
                line_no += 1
                escaped = False
                i += 1
                continue
            cleaned.append(" ")
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == current_quote:
                state = ScannerState.NORMAL
            i += 1
            continue

        if state == ScannerState.CHAR:
            if ch == "\n":
                cleaned.append("\n")
                line_no += 1
                escaped = False
                i += 1
                continue
            cleaned.append(" ")
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "'":
                state = ScannerState.NORMAL
            i += 1
            continue

        if state == ScannerState.VERBATIM:
            if ch == "\n":
                cleaned.append("\n")
                line_no += 1
                i += 1
                continue
            cleaned.append(" ")
            if ch == '"' and nxt == '"':
                cleaned.append(" ")
                i += 2
                continue
            if ch == '"':
                state = ScannerState.NORMAL
            i += 1
            continue

        if state == ScannerState.RAW:
            if ch == "\n":
                cleaned.append("\n")
                line_no += 1
                i += 1
                continue
            cleaned.append(" ")
            closing = ")" + raw_delim + '"'
            if code.startswith(closing, i):
                for _ in closing[1:]:
                    cleaned.append(" ")
                i += len(closing)
                state = ScannerState.NORMAL
                raw_delim = ""
                continue
            i += 1
            continue

        if state == ScannerState.LINE_COMMENT:
            if ch == "\n":
                flush_comment()
                state = ScannerState.NORMAL
                cleaned.append("\n")
                line_no += 1
                i += 1
                continue
            comment_line_numbers.add(line_no)
            comment_buffer.append(ch)
            cleaned.append(" ")
            i += 1
            continue

        if state == ScannerState.BLOCK_COMMENT:
            if ch == "\n":
                comment_line_numbers.add(line_no)
                comment_buffer.append(ch)
                cleaned.append("\n")
                line_no += 1
                i += 1
                continue
            comment_line_numbers.add(line_no)
            comment_buffer.append(ch)
            cleaned.append(" ")
            if ch == "*" and nxt == "/":
                comment_buffer.append(nxt)
                cleaned.append(" ")
                i += 2
                flush_comment()
                state = ScannerState.NORMAL
                continue
            i += 1
            continue

    flush_comment()
    return ScanResult("".join(cleaned), comment_line_numbers, code_line_numbers, comment_texts)


def scan_markdown(code: str) -> ScanResult:
    lines = code.split("\n") if code else []
    code_line_numbers = {index for index, line in enumerate(lines, start=1) if line.strip()}
    return ScanResult(code, set(), code_line_numbers, [], "")


def scan_python(code: str) -> ScanResult:
    comment_line_numbers: Set[int] = set()
    code_line_numbers: Set[int] = set()
    comment_texts: List[str] = []
    tokenizer_error = ""

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(code).readline))
    except tokenize.TokenError as exc:
        tokenizer_error = str(exc)
        lines = code.split("\n")
        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                comment_line_numbers.add(index)
                comment_texts.append(stripped)
            else:
                code_line_numbers.add(index)
        return ScanResult(code, comment_line_numbers, code_line_numbers, comment_texts, tokenizer_error)

    line_has_code: Dict[int, bool] = defaultdict(bool)
    line_has_comment: Dict[int, bool] = defaultdict(bool)
    char_buffer = list(code)

    for token in tokens:
        token_type = token.type
        token_text = token.string
        start_line, start_col = token.start
        end_line, end_col = token.end
        if token_type == tokenize.COMMENT:
            line_has_comment[start_line] = True
            comment_texts.append(token_text)
            comment_line_numbers.add(start_line)
            if start_line == end_line:
                absolute_start = _absolute_offset(code, start_line, start_col)
                absolute_end = _absolute_offset(code, end_line, end_col)
                for offset in range(absolute_start, absolute_end):
                    if offset < len(char_buffer):
                        char_buffer[offset] = " "
            continue
        if token_type in {tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER, tokenize.ENCODING}:
            continue
        for row in range(start_line, end_line + 1):
            line_has_code[row] = True

    lines = code.split("\n")
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if line_has_comment[index] and not line_has_code[index]:
            comment_line_numbers.add(index)
        elif line_has_code[index]:
            code_line_numbers.add(index)

    return ScanResult("".join(char_buffer), comment_line_numbers, code_line_numbers, comment_texts, tokenizer_error)


def python_tokens_and_identifiers(code: str) -> Tuple[List[str], List[str], List[str], str]:
    identifiers: List[str] = []
    operators: List[str] = []
    operands: List[str] = []
    tokenizer_error = ""
    try:
        tokens = tokenize.generate_tokens(io.StringIO(code).readline)
        for token in tokens:
            token_type = token.type
            token_text = token.string
            if token_type in {
                tokenize.ENCODING,
                tokenize.NL,
                tokenize.NEWLINE,
                tokenize.INDENT,
                tokenize.DEDENT,
                tokenize.ENDMARKER,
                tokenize.COMMENT,
            }:
                continue
            if token_type == tokenize.OP:
                operators.append(token_text)
                continue
            if token_type == tokenize.NAME:
                if keyword.iskeyword(token_text) or token_text in SOFT_KEYWORDS_PYTHON:
                    operators.append(token_text)
                else:
                    identifiers.append(token_text)
                    operands.append(token_text)
                continue
            if token_type in {tokenize.NUMBER, tokenize.STRING}:
                operands.append(token_text)
    except tokenize.TokenError as exc:
        tokenizer_error = str(exc)
    return identifiers, operators, operands, tokenizer_error


def generic_tokens_and_identifiers(cleaned_code: str, language: str) -> Tuple[List[str], List[str], List[str]]:
    identifiers: List[str] = []
    operators: List[str] = []
    operands: List[str] = []
    if language == "javascript":
        words = RE_JS_IDENTIFIERS.findall(cleaned_code)
    elif language == "bash":
        words = RE_BASH_IDENTIFIERS.findall(cleaned_code)
    elif language == "csharp":
        words = [item.lstrip("@") for item in RE_CSHARP_IDENTIFIER.findall(cleaned_code)]
    elif language == "markdown":
        words = re.findall(r"\b[A-Za-z][A-Za-z0-9_-]*\b", cleaned_code)
    else:
        words = RE_GENERIC_IDENTIFIER.findall(cleaned_code)
    keywords_set = LANGUAGE_KEYWORDS.get(language, set())
    for word in words:
        if word in keywords_set:
            operators.append(word)
        else:
            identifiers.append(word)
            operands.append(word)
    if language == "javascript":
        operators.extend(re.findall(r"===|!==|=>|\?\?|\?\.|\+\+|--|&&|\|\||[+\-*/%=<>!&|^~?:;,.()\[\]{}]", cleaned_code))
    elif language in {"c", "cpp", "csharp"}:
        operators.extend(re.findall(r"::|->|=>|==|!=|<=|>=|\+\+|--|&&|\|\||<<|>>|[+\-*/%=<>!&|^~?:;,.()\[\]{}#]", cleaned_code))
    elif language == "bash":
        operators.extend(re.findall(r"\|\||&&|;;|[|&;><(){}$!]", cleaned_code))
    else:
        operators.extend(re.findall(r"[+\-*/%=<>!&|^~?:;,.()\[\]{}]", cleaned_code))
    operands.extend(match.group(0) for match in RE_NUMBER.finditer(cleaned_code))
    return identifiers, operators, operands


def python_parse(code: str) -> Tuple[Optional[ast.AST], str, List[str]]:
    warnings: List[str] = []
    try:
        return ast.parse(code, type_comments=True), "", warnings
    except SyntaxError as exc:
        message = str(exc)
        if re.search(r"(^|\n)\s*match\s+", code):
            warnings.append("Pattern matching was detected. AST parsing may be limited when the runtime parser is older than the source syntax.")
        if ":=" in code:
            warnings.append("Assignment expressions were detected. Parsing may be limited on older runtimes.")
        return None, message, warnings


def node_end_lineno(node: ast.AST, fallback: int) -> int:
    end_lineno = getattr(node, "end_lineno", None)
    if isinstance(end_lineno, int):
        return end_lineno
    max_lineno = fallback
    for child in ast.walk(node):
        child_end = getattr(child, "end_lineno", None)
        child_line = getattr(child, "lineno", None)
        if isinstance(child_end, int):
            max_lineno = max(max_lineno, child_end)
        elif isinstance(child_line, int):
            max_lineno = max(max_lineno, child_line)
    return max_lineno


MATCH_NODE = getattr(ast, "Match", None)


class PythonCyclomaticVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.complexity = 1

    def generic_visit(self, node: ast.AST) -> None:
        if isinstance(node, ast.If):
            self.complexity += 1
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Assert, ast.IfExp)):
            self.complexity += 1
        elif isinstance(node, ast.ExceptHandler):
            self.complexity += 1
        elif isinstance(node, ast.BoolOp):
            self.complexity += max(len(node.values) - 1, 0)
        elif isinstance(node, ast.comprehension):
            self.complexity += 1 + len(node.ifs)
        elif MATCH_NODE is not None and isinstance(node, MATCH_NODE):
            for case in getattr(node, "cases", []):
                pattern = getattr(case, "pattern", None)
                is_default = (
                    pattern is not None
                    and pattern.__class__.__name__ == "MatchAs"
                    and getattr(pattern, "name", None) is None
                )
                if not is_default:
                    self.complexity += 1
        super().generic_visit(node)


class PythonStructureCollector(ast.NodeVisitor):
    def __init__(self, source_lines: List[str]) -> None:
        self.source_lines = source_lines
        self.functions: List[FunctionInfo] = []
        self.imported_names: Dict[str, str] = {}
        self.used_names: Set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound_name = alias.asname or alias.name.split(".", 1)[0]
            self.imported_names[bound_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                continue
            bound_name = alias.asname or alias.name
            full_name = f"{node.module or ''}.{alias.name}".strip(".")
            self.imported_names[bound_name] = full_name
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        self.used_names.add(node.id)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append(self._function_info(node))
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.functions.append(self._function_info(node))
        self.generic_visit(node)

    def _function_info(self, node: ast.AST) -> FunctionInfo:
        complexity_visitor = PythonCyclomaticVisitor()
        complexity_visitor.visit(node)
        decorators = getattr(node, "decorator_list", []) or []
        decorator_lines = [getattr(dec, "lineno", None) for dec in decorators if getattr(dec, "lineno", None)]
        start_lineno = min([getattr(node, "lineno", 1)] + [int(line) for line in decorator_lines if line is not None])
        end_lineno = node_end_lineno(node, start_lineno)
        signature = Counter(type(child).__name__ for child in ast.walk(node))
        raw_doc = ast.get_docstring(node, clean=False)
        has_docstring = bool(raw_doc)
        has_type_hints = False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
            if node.args.vararg is not None:
                arguments.append(node.args.vararg)
            if node.args.kwarg is not None:
                arguments.append(node.args.kwarg)
            has_type_hints = bool(node.returns) or any(arg.annotation is not None for arg in arguments)
            params = [arg.arg for arg in arguments]
        else:
            params = []
        body_text = "\n".join(self.source_lines[start_lineno - 1 : end_lineno])
        header_line = self.source_lines[getattr(node, "lineno", start_lineno) - 1] if self.source_lines else ""
        return FunctionInfo(
            name=getattr(node, "name", "<lambda>"),
            lineno=start_lineno,
            end_lineno=end_lineno,
            length=max(1, end_lineno - start_lineno + 1),
            cyclomatic=complexity_visitor.complexity,
            has_docstring=has_docstring,
            has_type_hints=has_type_hints,
            ast_signature=signature,
            signature=header_line,
            body=body_text,
            parameters=params,
        )


def line_category(language: str, line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return "blank"
    if language == "python":
        if stripped.startswith("#"):
            return "comment"
        if stripped.startswith("@"):
            return "declarative"
        if re.match(r"^(?:async\s+def|def|class|import|from|global|nonlocal)\b", stripped):
            return "declarative"
        if re.match(r"^(?:if|elif|else|for|while|try|except|finally|with|match|case)\b", stripped):
            return "control"
        return "executable"
    if language == "javascript":
        if stripped.startswith("//") or stripped.startswith("/*"):
            return "comment"
        if re.match(r"^(?:import|export|const|let|var|function|class)\b", stripped):
            return "declarative"
        if re.match(r"^(?:if|else|for|while|switch|case|catch|try|finally|do)\b", stripped):
            return "control"
        return "executable"
    if language == "bash":
        if stripped.startswith("#"):
            return "comment"
        if re.match(r"^(?:readonly|local|declare|typeset|export|source|\.)\b", stripped):
            return "declarative"
        if re.match(r"^(?:if|then|elif|else|fi|for|while|until|case|select|do|done|esac)\b", stripped):
            return "control"
        if re.match(r"^(?:function\s+\w+|\w+\s*\(\)\s*\{)", stripped):
            return "declarative"
        return "executable"
    if language in {"c", "cpp"}:
        if stripped.startswith("//") or stripped.startswith("/*"):
            return "comment"
        if stripped.startswith("#"):
            return "declarative"
        if re.match(r"^(?:typedef|struct|union|enum|class|namespace|template|using|static|extern|constexpr|inline|friend|virtual|const\b|volatile\b)", stripped):
            return "declarative"
        if re.match(r"^(?:if|else|for|while|switch|case|default|do|try|catch)\b", stripped):
            return "control"
        if re.match(r"^(?:[A-Za-z_][A-Za-z0-9_:<>~*&\s]+\s+\**[A-Za-z_~][A-Za-z0-9_:<>~]*\s*\()", stripped):
            return "declarative"
        return "executable"
    if language == "csharp":
        if stripped.startswith("//") or stripped.startswith("/*"):
            return "comment"
        if stripped.startswith("#") or stripped.startswith("["):
            return "declarative"
        if re.match(r"^(?:using|namespace|class|struct|interface|enum|record|delegate|public|private|protected|internal|static|sealed|abstract|partial)\b", stripped):
            return "declarative"
        if re.match(r"^(?:if|else|for|foreach|while|switch|case|default|do|try|catch|finally|lock)\b", stripped):
            return "control"
        return "executable"
    if language == "markdown":
        if re.match(r"^#{1,6}\s+\S", stripped):
            return "declarative"
        if stripped.startswith("```") or stripped.startswith("~~~"):
            return "declarative"
        return "executable"
    return "executable"


def _match_braces(text: str, start_brace_index: int) -> int:
    depth = 0
    for index in range(start_brace_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _deduplicate_ranges(ranges: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    unique: List[Tuple[int, int]] = []
    seen = set()
    for item in ranges:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return sorted(unique)


def extract_javascript_function_ranges(cleaned_code: str) -> List[Tuple[int, int]]:
    ranges: List[Tuple[int, int]] = []
    for match in RE_JS_FUNCTION_START.finditer(cleaned_code):
        start_index = match.start()
        brace_index = cleaned_code.find("{", match.start(), min(len(cleaned_code), match.end() + 200))
        if brace_index == -1:
            continue
        end_index = _match_braces(cleaned_code, brace_index)
        if end_index == -1:
            continue
        start_line = cleaned_code.count("\n", 0, start_index) + 1
        end_line = cleaned_code.count("\n", 0, end_index) + 1
        if end_line >= start_line:
            ranges.append((start_line, end_line))
    return _deduplicate_ranges(ranges)


def extract_bash_function_ranges(cleaned_code: str) -> List[Tuple[int, int]]:
    ranges: List[Tuple[int, int]] = []
    for match in RE_BASH_FUNCTION_START.finditer(cleaned_code):
        start_index = match.start()
        brace_index = cleaned_code.find("{", match.start(), min(len(cleaned_code), match.end() + 120))
        if brace_index == -1:
            continue
        end_index = _match_braces(cleaned_code, brace_index)
        if end_index == -1:
            continue
        start_line = cleaned_code.count("\n", 0, start_index) + 1
        end_line = cleaned_code.count("\n", 0, end_index) + 1
        if end_line >= start_line:
            ranges.append((start_line, end_line))
    return _deduplicate_ranges(ranges)


def approx_cyclomatic_from_text(text: str, language: str) -> int:
    if not text.strip():
        return 1
    if language == "javascript":
        count = len(re.findall(r"\b(?:if|else\s+if|for|while|catch|switch|case)\b|&&|\|\||\?\?", text))
        return max(1, count + 1)
    if language in {"c", "cpp"}:
        count = len(re.findall(r"\b(?:if|else\s+if|for|while|switch|case|catch)\b|&&|\|\||\?", text))
        return max(1, count + 1)
    if language == "csharp":
        count = len(re.findall(r"\b(?:if|else\s+if|for|foreach|while|switch|case|catch)\b|&&|\|\||\?", text))
        return max(1, count + 1)
    if language == "bash":
        count = len(re.findall(r"\b(?:if|elif|for|while|until|case)\b|&&|\|\|", text))
        return max(1, count + 1)
    return 1


def function_lengths(context: AnalysisContext) -> List[int]:
    return [item.length for item in context.functions]


def approx_brace_nesting(cleaned_code: str) -> int:
    depth = 0
    best = 0
    for char in cleaned_code:
        if char == "{":
            depth += 1
            best = max(best, depth)
        elif char == "}":
            depth = max(0, depth - 1)
    return best


def approx_bash_nesting(lines: Sequence[str]) -> int:
    depth = 0
    best = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^(?:if|for|while|until|case|select|do|then)\b", stripped):
            depth += 1
            best = max(best, depth)
        if re.match(r"^(?:fi|done|esac)\b", stripped):
            depth = max(0, depth - 1)
    return best


def python_max_nesting(tree: Optional[ast.AST]) -> int:
    if tree is None:
        return 0
    control_types: List[Type[ast.AST]] = [ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith]
    if MATCH_NODE is not None:
        control_types.append(MATCH_NODE)
    control_tuple = tuple(control_types)

    def visit(node: ast.AST, depth: int) -> int:
        child_depth = depth + 1 if isinstance(node, control_tuple) else depth
        best = child_depth
        for child in ast.iter_child_nodes(node):
            best = max(best, visit(child, child_depth))
        return best

    return visit(tree, 0)


def python_docstring_coverage(tree: Optional[ast.AST]) -> Tuple[int, int]:
    if tree is None:
        return 0, 0
    targets = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    documented = sum(1 for node in targets if ast.get_docstring(node, clean=False))
    return documented, len(targets)


def python_guard_count(tree: Optional[ast.AST]) -> int:
    if tree is None:
        return 0
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            count += 1
        elif isinstance(node, ast.Raise):
            count += 1
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in {"isinstance", "issubclass", "len", "all", "any"}:
                count += 1
        elif isinstance(node, ast.Compare):
            text = ast.unparse(node) if hasattr(ast, "unparse") else ""
            if "None" in text:
                count += 1
    return count


def python_error_count(tree: Optional[ast.AST]) -> int:
    if tree is None:
        return 0
    return sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, (ast.Try, ast.ExceptHandler, ast.Raise, ast.Assert))
    )


def approx_js_import_use_ratio(context: AnalysisContext) -> Optional[float]:
    bindings: Set[str] = set()
    for line in context.lines:
        stripped = line.strip()
        if not stripped.startswith("import "):
            continue
        brace_match = re.search(r"\{([^}]*)\}", stripped)
        if brace_match:
            for chunk in brace_match.group(1).split(","):
                chunk = chunk.strip()
                if not chunk:
                    continue
                if " as " in chunk:
                    bindings.add(chunk.split(" as ")[-1].strip())
                else:
                    bindings.add(chunk)
        namespace_match = re.search(r"\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)", stripped)
        if namespace_match:
            bindings.add(namespace_match.group(1))
        default_match = re.match(r"import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:,|from)", stripped)
        if default_match and "from" in stripped:
            bindings.add(default_match.group(1))
    if not bindings:
        return None
    code_without_imports = "\n".join(line for line in context.lines if not line.strip().startswith("import "))
    used = set(RE_JS_IDENTIFIERS.findall(code_without_imports))
    return safe_div(len(bindings & used), len(bindings), default=0.0)


def parse_markdown(code: str) -> MarkdownInfo:
    info = MarkdownInfo()
    lines = code.split("\n") if code else []
    in_fence = False
    fence_marker = ""
    prose_lines: List[str] = []
    for line in lines:
        stripped = line.rstrip()
        fence_match = re.match(r"^\s*(```+|~~~+)", stripped)
        if fence_match:
            marker = fence_match.group(1)
            if not in_fence:
                in_fence = True
                fence_marker = marker[0]
                info.code_fence_count += 1
            elif marker[0] == fence_marker:
                in_fence = False
            info.code_fence_line_count += 1
            continue
        if in_fence:
            info.code_fence_line_count += 1
            continue
        heading_match = re.match(r"^\s*(#{1,6})\s+(.+?)\s*$", stripped)
        if heading_match:
            info.headings.append((len(heading_match.group(1)), len(info.headings) + 1, heading_match.group(2)))
        info.link_count += len(re.findall(r"\[[^\]]+\]\([^)]+\)", stripped))
        plain = re.sub(r"\[[^\]]+\]\(([^)]+)\)", lambda m: m.group(0).split("](")[0][1:], stripped)
        plain = re.sub(r"`[^`]+`", " ", plain)
        plain = re.sub(r"[*_~>#-]", " ", plain)
        if plain.strip():
            prose_lines.append(plain)
    info.prose_text = "\n".join(prose_lines)
    info.prose_word_count = len(re.findall(r"\b[A-Za-z][A-Za-z'-]*\b", info.prose_text))
    return info

def _range_to_function_info(lines: List[str], start_line: int, end_line: int, language: str, name_hint: str = "") -> FunctionInfo:
    start_line = max(1, start_line)
    end_line = max(start_line, end_line)
    snippet = "\n".join(lines[start_line - 1 : end_line])
    header = lines[start_line - 1] if lines and start_line - 1 < len(lines) else ""
    name = name_hint
    if language == "javascript":
        match = re.search(r"function\s+([A-Za-z_$][A-Za-z0-9_$]*)", header)
        if not match:
            match = re.search(r"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=", header)
        if match:
            name = match.group(1)
    elif language == "bash":
        match = re.search(r"(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\))?\s*\{", header)
        if match:
            name = match.group(1)
    if not name:
        name = f"{language}_function_{start_line}"
    return FunctionInfo(
        name=name,
        lineno=start_line,
        end_lineno=end_line,
        length=max(1, end_line - start_line + 1),
        cyclomatic=approx_cyclomatic_from_text(snippet, language),
        signature=header.strip(),
        body=snippet,
        parameters=[],
    )


def _extract_c_like_name(signature: str) -> Optional[str]:
    signature = re.sub(r"\s+", " ", signature.strip())
    if not signature or "(" not in signature:
        return None
    pre = signature.split("(", 1)[0].strip()
    pre = re.sub(r"\b(?:if|for|while|switch|catch|foreach|using|lock|return|sizeof|new|delete)\b.*$", "", pre)
    match = re.search(r"([~A-Za-z_][A-Za-z0-9_:~]*)(?:\s*<[^<>]+>)?$", pre)
    if not match:
        return None
    name = match.group(1)
    short = name.split("::")[-1]
    if short in {"if", "for", "while", "switch", "catch", "foreach", "using", "lock", "return"}:
        return None
    return short



def _prepare_c_like_signature(candidate: str) -> Tuple[str, int]:
    lines = candidate.splitlines(True)
    offset = 0
    while lines and (not lines[0].strip() or lines[0].lstrip().startswith("#")):
        offset += len(lines.pop(0))
    joined = "".join(lines)
    leading = len(joined) - len(joined.lstrip())
    return joined.strip(), offset + leading


def extract_c_like_functions(cleaned_code: str, lines: List[str], language: str) -> List[FunctionInfo]:
    functions: List[FunctionInfo] = []
    seen: Set[Tuple[int, int, str]] = set()
    for index, ch in enumerate(cleaned_code):
        if ch != "{":
            continue
        window_start = max(0, index - 800)
        prefix = cleaned_code[window_start:index]
        if "(" not in prefix or ")" not in prefix or prefix.rfind(")") < prefix.rfind("("):
            continue
        sig_start = max(prefix.rfind(";"), prefix.rfind("}"), prefix.rfind("{"), prefix.rfind("\n\n"))
        sig_abs_start = window_start + sig_start + 1
        candidate = cleaned_code[sig_abs_start:index]
        signature, relative_offset = _prepare_c_like_signature(candidate)
        sig_abs_start += relative_offset
        if not signature:
            continue
        if re.match(r"^(?:if|for|while|switch|catch|foreach|do|else|try|using|lock)\b", signature):
            continue
        name = _extract_c_like_name(signature)
        if not name:
            continue
        end_index = _match_braces(cleaned_code, index)
        if end_index == -1:
            continue
        start_line = cleaned_code.count("\n", 0, sig_abs_start) + 1
        end_line = cleaned_code.count("\n", 0, end_index) + 1
        key = (start_line, end_line, name)
        if key in seen:
            continue
        seen.add(key)
        snippet = cleaned_code[sig_abs_start : end_index + 1]
        params_match = re.search(r"\((.*)\)", signature, re.S)
        params = []
        if params_match:
            raw_params = params_match.group(1)
            params = [item.strip() for item in re.split(r",(?![^<]*>)", raw_params) if item.strip()]
        functions.append(
            FunctionInfo(
                name=name,
                lineno=start_line,
                end_lineno=end_line,
                length=max(1, end_line - start_line + 1),
                cyclomatic=approx_cyclomatic_from_text(snippet, language),
                signature=signature,
                body=snippet,
                parameters=params,
            )
        )
    return sorted(functions, key=lambda item: item.lineno)




def extract_generic_functions(lines: List[str], cleaned_code: str, language: str) -> List[FunctionInfo]:
    if language == "javascript":
        return [_range_to_function_info(lines, start, end, language) for start, end in extract_javascript_function_ranges(cleaned_code)]
    if language == "bash":
        return [_range_to_function_info(lines, start, end, language) for start, end in extract_bash_function_ranges(cleaned_code)]
    if language in {"c", "cpp", "csharp"}:
        return extract_c_like_functions(cleaned_code, lines, language)
    return []


def _estimate_simple_type_size(type_text: str, language: str) -> int:
    raw = " ".join(type_text.replace("&", " ").replace("*", " * ").split())
    if "*" in raw or "&" in type_text:
        return 8
    if raw in POINTER_LIKE_TYPES:
        return 8
    if raw in SCALAR_TYPE_SIZES:
        return SCALAR_TYPE_SIZES[raw]
    if raw.startswith("struct "):
        return 16
    if raw.startswith("enum "):
        return 4
    if raw.startswith("class ") or raw.startswith("record "):
        return 16 if language in {"cpp", "csharp"} else 8
    if raw.startswith("std::"):
        return 24
    if raw.startswith("System.") or raw.endswith("[]"):
        return 8
    return 8


def _split_declarators(text: str) -> List[str]:
    declarators: List[str] = []
    current: List[str] = []
    bracket_depth = 0
    angle_depth = 0
    paren_depth = 0
    for ch in text:
        if ch == "," and bracket_depth == 0 and angle_depth == 0 and paren_depth == 0:
            chunk = "".join(current).strip()
            if chunk:
                declarators.append(chunk)
            current = []
            continue
        current.append(ch)
        if ch == "[":
            bracket_depth += 1
        elif ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif ch == "<":
            angle_depth += 1
        elif ch == ">":
            angle_depth = max(0, angle_depth - 1)
        elif ch == "(":
            paren_depth += 1
        elif ch == ")":
            paren_depth = max(0, paren_depth - 1)
    chunk = "".join(current).strip()
    if chunk:
        declarators.append(chunk)
    return declarators



KNOWN_DECLARATION_TYPE_NAMES = {
    "bool", "_Bool", "char", "signed char", "unsigned char", "short", "short int",
    "unsigned short", "unsigned short int", "int", "unsigned", "unsigned int", "long",
    "long int", "unsigned long", "unsigned long int", "long long", "unsigned long long",
    "float", "double", "long double", "wchar_t", "char16_t", "char32_t", "byte", "sbyte",
    "ushort", "uint", "ulong", "decimal", "nint", "nuint", "string", "object", "dynamic",
    "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t", "FILE", "DIR", "var",
}


def looks_like_declared_type(type_text: str, language: str) -> bool:
    raw = " ".join(type_text.split())
    if not raw:
        return False
    if raw in KNOWN_DECLARATION_TYPE_NAMES or raw in SCALAR_TYPE_SIZES or raw in POINTER_LIKE_TYPES:
        return True
    if raw.startswith(("struct ", "enum ", "class ", "record ")):
        return True
    if raw.startswith(("unsigned ", "signed ", "short ", "long ")):
        return True
    tail = raw.split()[-1]
    if tail in KNOWN_DECLARATION_TYPE_NAMES or tail in SCALAR_TYPE_SIZES:
        return True
    if tail.endswith("_t") or tail.endswith("_type"):
        return True
    if any(token in tail for token in ("::", ".", "<", ">", "?")):
        return True
    if tail[:1].isupper():
        return True
    return False


def _parse_c_like_declaration_line(line: str, language: str) -> List[Dict[str, Any]]:
    stripped = line.strip().rstrip(";")
    if not stripped:
        return []
    if stripped.startswith("#"):
        return []
    stripped = re.sub(r"^(?:return|break|continue)\b.*$", "", stripped)
    if not stripped:
        return []
    if language == "csharp":
        stripped = re.sub(r"^\[[^\]]+\]\s*", "", stripped)
    if re.match(r"^(?:if|for|while|switch|catch|foreach|using|lock)\b", stripped):
        inner = re.search(r"\(([^;]+);", stripped)
        if not inner:
            return []
        stripped = inner.group(1).strip()
    if "(" in stripped and not re.search(r"\[[^\]]+\]", stripped):
        if re.search(r"\b(?:sizeof|return|new|delete)\s*\(", stripped):
            return []
        if re.search(r"\)\s*$", stripped) and "=" not in stripped and language in {"c", "cpp", "csharp"}:
            return []
    stripped = re.sub(r"\b(?:const|static|register|volatile|mutable|inline|extern|constexpr|readonly|ref|out|in|unsafe|fixed)\b", " ", stripped)
    stripped = re.sub(r"\s+", " ", stripped).strip()
    tokens = stripped.split()
    split_index = None
    for index in range(1, len(tokens)):
        type_candidate = " ".join(tokens[:index]).strip()
        decl_candidate = " ".join(tokens[index:]).strip()
        if not looks_like_declared_type(type_candidate, language):
            continue
        if re.match(r"^(?:[*&]+\s*)?[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]*\])?(?:\s*(?:=.*|\{.*\}))?$", decl_candidate):
            split_index = index
            continue
        if re.match(r"^(?:[*&]+\s*)?[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]*\])?\s*,", decl_candidate):
            split_index = index
            continue
    if split_index is None:
        return []
    type_text = " ".join(tokens[:split_index]).strip()
    decls_text = " ".join(tokens[split_index:]).strip()
    declarations: List[Dict[str, Any]] = []
    for declarator in _split_declarators(decls_text):
        array_match = re.search(r"\[([^\]]+)\]", declarator)
        name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)", declarator)
        if not name_match:
            continue
        name = name_match.group(1)
        declarator_base = declarator.split("=", 1)[0].strip()
        pointer = "*" in declarator_base or "&" in declarator_base or declarator_base.endswith("[]")
        base_size = 8 if pointer else _estimate_simple_type_size(type_text, language)
        count = 1
        vla = False
        if array_match:
            bound = array_match.group(1).strip()
            if bound.isdigit():
                count = max(1, int(bound))
            else:
                count = 1
                vla = True
        size = base_size * count
        declarations.append(
            {
                "name": name,
                "type": type_text,
                "pointer": pointer,
                "array": bool(array_match),
                "vla": vla,
                "count": count,
                "size": size,
            }
        )
    return declarations



def function_inner_region(function: FunctionInfo) -> Tuple[str, int]:
    body = function.body
    start = body.find("{")
    end = body.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return body, 0
    inner = body[start + 1 : end]
    line_offset = body[: start + 1].count("\n")
    return inner, line_offset


def _split_declaration_fragments(line: str) -> List[str]:
    fragments: List[str] = []
    current: List[str] = []
    bracket_depth = 0
    angle_depth = 0
    paren_depth = 0
    for ch in line:
        if ch == ";" and bracket_depth == 0 and angle_depth == 0 and paren_depth == 0:
            chunk = "".join(current).strip()
            if chunk:
                fragments.append(chunk)
            current = []
            continue
        if ch in "{}":
            if current and current[-1] != " ":
                current.append(" ")
            continue
        current.append(ch)
        if ch == "[":
            bracket_depth += 1
        elif ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif ch == "<":
            angle_depth += 1
        elif ch == ">":
            angle_depth = max(0, angle_depth - 1)
        elif ch == "(":
            paren_depth += 1
        elif ch == ")":
            paren_depth = max(0, paren_depth - 1)
    chunk = "".join(current).strip()
    if chunk:
        fragments.append(chunk)
    return fragments


def extract_local_declarations(function: FunctionInfo, language: str) -> List[Dict[str, Any]]:
    declarations: List[Dict[str, Any]] = []
    inner_text, line_offset = function_inner_region(function)
    body_lines = inner_text.split("\n")
    for offset, line in enumerate(body_lines, start=1):
        fragments = _split_declaration_fragments(line)
        if not fragments:
            continue
        for fragment in fragments:
            for decl in _parse_c_like_declaration_line(fragment, language):
                decl["relative_line"] = offset
                decl["absolute_line"] = function.lineno + line_offset + offset - 1
                declarations.append(decl)
    return declarations




def _identifier_occurrences(lines: Sequence[str], identifier: str) -> List[int]:
    pattern = re.compile(rf"\b{re.escape(identifier)}\b")
    return [index for index, line in enumerate(lines, start=1) if pattern.search(line)]



def register_pressure_profile(function: FunctionInfo, language: str) -> Dict[str, Any]:
    inner_text, _ = function_inner_region(function)
    body_lines = inner_text.split("\n")
    declarations = extract_local_declarations(function, language)
    live_ranges: List[Tuple[str, int, int]] = []
    scalar_names: List[str] = []
    for decl in declarations:
        if decl.get("array"):
            continue
        name = decl["name"]
        scalar_names.append(name)
        occurrences = _identifier_occurrences(body_lines, name)
        if not occurrences:
            continue
        decl_line = max(1, decl["relative_line"])
        last_use = max(occurrences)
        live_ranges.append((name, decl_line, max(last_use, decl_line)))
    peak = 0
    peak_line = 0
    for line_index in range(1, len(body_lines) + 1):
        live_count = sum(1 for _, start, end in live_ranges if start <= line_index <= end)
        if live_count > peak:
            peak = live_count
            peak_line = line_index
    ratio = safe_div(peak, DEFAULT_REGISTERS_X64, default=0.0)
    return {"peak_live": peak, "peak_line": peak_line, "ratio": ratio, "locals": len(scalar_names)}





def stack_frame_profile(function: FunctionInfo, language: str) -> Dict[str, Any]:
    declarations = extract_local_declarations(function, language)
    frame_bytes = int(sum(int(item["size"]) for item in declarations))
    large_arrays = [item for item in declarations if item.get("array") and item.get("size", 0) >= 1024]
    vla_items = [item for item in declarations if item.get("vla")]
    inner_text, _ = function_inner_region(function)
    recursive = bool(re.search(rf"\b{re.escape(function.name)}\s*\(", inner_text))
    return {
        "frame_bytes": frame_bytes,
        "large_arrays": large_arrays,
        "vla_items": vla_items,
        "recursive": recursive,
        "locals": len(declarations),
    }





def redundant_memory_profile(function: FunctionInfo, language: str) -> Dict[str, Any]:
    body, _ = function_inner_region(function)
    memory_patterns = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\]|\*\s*[A-Za-z_][A-Za-z0-9_]*|\b[A-Za-z_][A-Za-z0-9_]*->\s*[A-Za-z_][A-Za-z0-9_]*", body)
    normalised_memory = [re.sub(r"\s+", "", item) for item in memory_patterns]
    repeated_memory = sum(max(0, count - 1) for count in Counter(normalised_memory).values() if count > 1)

    loop_blocks: List[str] = []
    for match in re.finditer(r"\b(?:for|while)\s*\([^)]*\)\s*\{", body):
        brace_index = body.find("{", match.start())
        end_index = _match_braces(body, brace_index)
        if end_index != -1:
            loop_blocks.append(body[brace_index + 1 : end_index])
    invariant_duplicates = 0
    for block in loop_blocks:
        expressions = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\s*(?:[+\-*/]\s*[A-Za-z_0-9]+)+", block)
        expressions = [re.sub(r"\s+", "", item) for item in expressions]
        counter = Counter(expressions)
        invariant_duplicates += sum(max(0, count - 1) for count in counter.values() if count > 1)

    missing_qualifiers = 0
    for param in function.parameters:
        if "*" not in param and "[" not in param:
            continue
        name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[\s*\])?\s*$", param)
        if not name_match:
            continue
        name = name_match.group(1)
        writes = re.search(rf"(?:\*\s*{re.escape(name)}\s*=|{re.escape(name)}\s*\[[^\]]+\]\s*=)", body)
        if writes:
            continue
        if "const" not in param and not (language == "c" and "restrict" in param):
            missing_qualifiers += 1

    total_patterns = repeated_memory + invariant_duplicates + missing_qualifiers
    density = safe_div(total_patterns, max(function.length, 1) / 20.0, default=0.0)
    return {
        "repeated_memory": repeated_memory,
        "invariant_duplicates": invariant_duplicates,
        "missing_qualifiers": missing_qualifiers,
        "density": density,
    }




def preprocessor_profile(context: AnalysisContext) -> Dict[str, Any]:
    include_lines: List[str] = []
    macro_lines: List[str] = []
    conditional_depth = 0
    max_conditional_depth = 0
    for line in context.lines:
        stripped = line.strip()
        if re.match(r"^#\s*include\b", stripped):
            include_lines.append(stripped)
        elif re.match(r"^#\s*define\b", stripped):
            macro_lines.append(stripped)
        elif re.match(r"^#\s*(?:if|ifdef|ifndef)\b", stripped):
            conditional_depth += 1
            max_conditional_depth = max(max_conditional_depth, conditional_depth)
        elif re.match(r"^#\s*endif\b", stripped):
            conditional_depth = max(0, conditional_depth - 1)

    system_before_project = True
    seen_project = False
    for line in include_lines:
        is_system = "<" in line and ">" in line
        is_project = '"' in line
        if is_project:
            seen_project = True
        elif is_system and seen_project:
            system_before_project = False

    macro_abuse = 0
    for line in macro_lines:
        if re.match(r"^#\s*define\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", line):
            macro_abuse += 1
        elif re.match(r"^#\s*define\s+[A-Z_][A-Z0-9_]*\s+\d", line):
            macro_abuse += 1

    has_guard = False
    ext = context.file_extension.lower()
    if ext in {"h", "hpp", "hxx", "hh"}:
        joined = "\n".join(context.lines[:20])
        has_guard = bool(re.search(r"#\s*pragma\s+once\b", joined))
        has_guard = has_guard or bool(re.search(r"#\s*ifndef\b.*\n\s*#\s*define\b", joined))
    else:
        has_guard = True

    return {
        "include_count": len(include_lines),
        "macro_abuse": macro_abuse,
        "conditional_depth": max_conditional_depth,
        "system_before_project": system_before_project,
        "has_guard": has_guard,
    }


def import_organisation_score(context: AnalysisContext) -> Optional[Tuple[float, str]]:
    if context.language != "python":
        return None
    import_lines: List[Tuple[int, str]] = []
    for index, line in enumerate(context.lines, start=1):
        stripped = line.strip()
        if re.match(r"^(?:import|from)\b", stripped):
            import_lines.append((index, stripped))
    if len(import_lines) < 2:
        return None

    first_real_code = None
    in_module_docstring = False
    triple_quote = None
    for index, line in enumerate(context.lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        opening = stripped[:3]
        if index == 1 and opening in {'"' * 3, "'" * 3}:
            if stripped.count(opening) < 2:
                in_module_docstring = True
                triple_quote = opening
            continue
        if in_module_docstring:
            if triple_quote and triple_quote in stripped:
                in_module_docstring = False
                triple_quote = None
            continue
        first_real_code = index
        break

    top_aligned = True
    if first_real_code is not None:
        top_aligned = not any(index > first_real_code for index, _ in import_lines)

    import_names = []
    for _, stripped in import_lines:
        if stripped.startswith("import "):
            import_names.append(stripped.replace("import ", "", 1).split(" as ")[0].strip())
        elif stripped.startswith("from "):
            import_names.append(stripped.split()[1])
    sorted_ok = import_names == sorted(import_names, key=str.lower)
    grouped = any(import_lines[i + 1][0] - import_lines[i][0] > 1 for i in range(len(import_lines) - 1))
    score = statistics.mean([1.0 if top_aligned else 0.0, 1.0 if sorted_ok else 0.0, 1.0 if grouped else 0.0])
    detail = f"top_aligned={top_aligned}, sorted={sorted_ok}, grouped={grouped}, imports={len(import_lines)}"
    return score, detail

def build_analysis_context(code: str, filename: str, language_hint: Optional[str] = None) -> AnalysisContext:
    normalised_code = normalise_newlines(code)
    language = detect_language(filename, normalised_code, language_hint)
    lines = normalised_code.split("\n") if normalised_code else []
    notes: List[str] = []
    file_extension = filename.lower().rsplit(".", 1)[-1] if "." in (filename or "") else ""

    ast_tree: Optional[ast.AST] = None
    ast_error = ""
    functions: List[FunctionInfo] = []
    imported_names: Dict[str, str] = {}
    used_names: Set[str] = set()
    token_error = ""
    markdown_info = MarkdownInfo()

    if language == "python":
        scan = scan_python(normalised_code)
        identifiers, operators, operands, token_error = python_tokens_and_identifiers(normalised_code)
        ast_tree, ast_error, parse_warnings = python_parse(normalised_code)
        notes.extend(parse_warnings)
        if ast_tree is not None:
            collector = PythonStructureCollector(lines)
            collector.visit(ast_tree)
            functions = sorted(collector.functions, key=lambda item: item.lineno)
            imported_names = collector.imported_names
            used_names = collector.used_names
    elif language == "javascript":
        scan = scan_javascript(normalised_code)
        identifiers, operators, operands = generic_tokens_and_identifiers(scan.cleaned_code, language)
        functions = extract_generic_functions(lines, scan.cleaned_code, language)
    elif language == "bash":
        scan = scan_bash(normalised_code)
        identifiers, operators, operands = generic_tokens_and_identifiers(scan.cleaned_code, language)
        functions = extract_generic_functions(lines, scan.cleaned_code, language)
    elif language in {"c", "cpp", "csharp"}:
        scan = scan_c_like(normalised_code, language)
        identifiers, operators, operands = generic_tokens_and_identifiers(scan.cleaned_code, language)
        functions = extract_generic_functions(lines, scan.cleaned_code, language)
    elif language == "markdown":
        scan = scan_markdown(normalised_code)
        identifiers, operators, operands = generic_tokens_and_identifiers(scan.cleaned_code, language)
        markdown_info = parse_markdown(normalised_code)
    else:
        scan = ScanResult(normalised_code, set(), {index for index, line in enumerate(lines, start=1) if line.strip()}, [], "")
        identifiers, operators, operands = generic_tokens_and_identifiers(normalised_code, "generic")
        notes.append("The language could not be detected with strong confidence.")

    if scan.tokenizer_error:
        notes.append(f"Tokenizer warning: {scan.tokenizer_error}")
    if token_error:
        notes.append(f"Tokenizer warning: {token_error}")
    if ast_error:
        notes.append(f"AST warning: {ast_error}")

    non_blank_lines = [line for line in lines if line.strip()]
    comment_lines = [
        lines[index - 1]
        for index in sorted(scan.comment_line_numbers)
        if 1 <= index <= len(lines) and lines[index - 1].strip()
    ]
    code_lines = [
        lines[index - 1]
        for index in sorted(scan.code_line_numbers)
        if 1 <= index <= len(lines) and lines[index - 1].strip()
    ]

    line_categories: Dict[int, str] = {}
    declarative = 0
    control = 0
    executable = 0
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            category = "blank"
        elif index in scan.comment_line_numbers and index not in scan.code_line_numbers:
            category = "comment"
        else:
            category = line_category(language, line)
        line_categories[index] = category
        if category == "declarative":
            declarative += 1
        elif category == "control":
            control += 1
        elif category == "executable":
            executable += 1

    indentation_widths, indentation_kinds = indentation_profile(lines)

    return AnalysisContext(
        filename=filename,
        language=language,
        code=normalised_code,
        lines=lines,
        non_blank_lines=non_blank_lines,
        comment_lines=comment_lines,
        code_lines=code_lines,
        comment_texts=scan.comment_texts,
        cleaned_code=scan.cleaned_code,
        line_categories=line_categories,
        identifiers=identifiers,
        tokens_operators=operators,
        tokens_operands=operands,
        blank_runs=blank_runs_from_lines(lines),
        indentation_widths=indentation_widths,
        indentation_kinds=indentation_kinds,
        declarative_line_count=declarative,
        control_line_count=control,
        executable_line_count=executable,
        commented_out_code_lines=count_commented_out_code(scan.comment_texts),
        ast_tree=ast_tree,
        ast_error=ast_error,
        functions=functions,
        imported_names=imported_names,
        used_names=used_names,
        notes=notes,
        tokenizer_error=scan.tokenizer_error or token_error,
        markdown=markdown_info,
        file_extension=file_extension,
    )

class MetricRegistry:
    """Registry of metric classes in insertion order."""

    _metrics: Dict[str, Type["BaseMetric"]] = {}

    @classmethod
    def register(cls, metric_class: Type["BaseMetric"]) -> Type["BaseMetric"]:
        name = getattr(metric_class, "name", "")
        if not name:
            raise ValueError("Metric classes must define a non-empty 'name'.")
        cls._metrics[name] = metric_class
        return metric_class

    @classmethod
    def metric_classes(cls) -> List[Type["BaseMetric"]]:
        return list(cls._metrics.values())


class BaseMetric(ABC):
    """Base class for a single metric."""

    name = "base"
    display_name = "Base metric"
    supported_languages: Set[str] = set(SUPPORTED_LANGUAGES)
    references: List[str] = []
    group = "stylometry"
    contributes_to_overall = True

    def __init__(self, config: Dict[str, Dict[str, Any]]) -> None:
        self._config = config

    @property
    def config(self) -> Dict[str, Any]:
        return self._config.get(self.name, {})

    @property
    def weight(self) -> float:
        return float(self.config.get("weight", 0.0))

    @property
    def enabled(self) -> bool:
        return bool(self.config.get("enabled", True))

    def threshold(self, key: str, default: Any = None) -> Any:
        return self.config.get("thresholds", {}).get(key, default)

    def note(self) -> str:
        return str(self.config.get("notes", ""))

    def supports(self, language: str) -> bool:
        return language in self.supported_languages

    def result(
        self,
        value: Optional[float],
        score: float,
        explanation: str,
        detail: str = "",
        applicable: bool = True,
        digits: int = 3,
    ) -> MetricResult:
        return MetricResult(
            name=self.name,
            display_name=self.display_name,
            value=value,
            value_display=format_float(value, digits=digits),
            score=clamp(score),
            weight=self.weight,
            applicable=applicable,
            explanation=explanation,
            detail=detail,
            references=list(self.references),
            group=self.group,
            contributes_to_overall=self.contributes_to_overall,
        )

    def not_applicable(self, explanation: str, detail: str = "") -> MetricResult:
        return self.result(None, 0.0, explanation, detail=detail, applicable=False)

    @abstractmethod
    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        raise NotImplementedError


def code_languages() -> Set[str]:
    return {"python", "javascript", "bash", "c", "cpp", "csharp"}


def prose_languages() -> Set[str]:
    return {"markdown"}


def boilerplate_indicators(code: str, lang: str, context: AnalysisContext) -> Tuple[int, int]:
    indicators = 0
    total = 0
    if lang == "python":
        total = 5
        indicators += int(bool(re.search(r"if\s+__name__\s*==\s*['\"]__main__['\"]", code)))
        indicators += int(bool(re.search(r"^#!\/usr\/bin\/env\s+python", code)))
        indicators += int(bool(re.search(r"from\s+__future__\s+import", code)))
        indicators += int(bool(context.ast_tree is not None and ast.get_docstring(context.ast_tree, clean=False)))
        indicators += int(bool(re.search(r"^#.*coding[:=]\s*(?:utf-8|ascii)", code, re.M)))
    elif lang == "javascript":
        total = 5
        indicators += int(bool(re.search(r"['\"]use strict['\"]", code)))
        indicators += int(bool(re.search(r"\bmodule\.exports\b|^export\s", code, re.M)))
        indicators += int(bool(re.search(r"/\*\*", code)))
        indicators += int(bool(re.search(r"process\.exit\b", code)))
        indicators += int(bool(re.search(r"^#!\/usr\/bin\/env\s+(?:node|deno)", code)))
    elif lang == "bash":
        total = 4
        indicators += int(bool(re.search(r"^#!\/bin\/(?:ba)?sh", code)))
        indicators += int(bool(re.search(r"\bset\s+-[^ \n]*[euo]", code)))
        indicators += int(bool(re.search(r"^#\s*(?:Description|Usage|Author)\b", code, re.M)))
        indicators += int(bool(re.search(r"\breadonly\b|\bdeclare\s+-r\b", code)))
    elif lang in {"c", "cpp"}:
        total = 5
        indicators += int(bool(re.search(r"^#\s*include\b", code, re.M)))
        indicators += int(bool(re.search(r"\bint\s+main\s*\(", code)))
        indicators += int(bool(re.search(r"^#\s*ifdef\b|^#\s*ifndef\b", code, re.M)))
        indicators += int(bool(re.search(r"\b(?:printf|std::cout|cout)\b", code)))
        indicators += int(bool(re.search(r"/\*\*", code)))
    elif lang == "csharp":
        total = 5
        indicators += int(bool(re.search(r"\busing\s+System\b", code)))
        indicators += int(bool(re.search(r"\bnamespace\s+[A-Za-z_][A-Za-z0-9_.]*", code)))
        indicators += int(bool(re.search(r"\bstatic\s+void\s+Main\s*\(", code)))
        indicators += int(bool(re.search(r"^\s*///", code, re.M)))
        indicators += int(bool(re.search(r"\[[A-Za-z_][A-Za-z0-9_]*\]", code)))
    return indicators, total


def python_structural_similarity(functions: Sequence[FunctionInfo]) -> Optional[float]:
    if len(functions) < 3:
        return None
    similarities: List[float] = []
    ordered = sorted(functions, key=lambda item: item.lineno)
    for left, right in zip(ordered, ordered[1:]):
        similarities.append(cosine_similarity(left.ast_signature, right.ast_signature))
    return statistics.mean(similarities) if similarities else None


def duplicate_block_density(lines: Sequence[str], language: str) -> float:
    code_only = [line.strip() for line in lines if line.strip()]
    if len(code_only) < 8:
        return 0.0
    windows: List[Set[str]] = []
    max_windows = min(len(code_only) - 3, 60)
    keywords_set = LANGUAGE_KEYWORDS.get(language, set())
    for start in range(max_windows):
        block = "\n".join(code_only[start : start + 4])
        tokens = []
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*|::|->|==|!=|<=|>=|&&|\|\||[{}()\[\];,.*+\-/<>#]", block):
            if re.match(r"[A-Za-z_]", token) and token not in keywords_set:
                tokens.append("ID")
            else:
                tokens.append(token)
        windows.append(set(tokens))
    duplicates = 0
    for i in range(len(windows)):
        for j in range(i + 1, len(windows)):
            union = windows[i] | windows[j]
            if not union:
                continue
            similarity = safe_div(len(windows[i] & windows[j]), len(union), default=0.0)
            if similarity >= 0.8:
                duplicates += 1
    return safe_div(duplicates, max(len(code_only), 1) / 20.0, default=0.0)


def guard_clause_profile(context: AnalysisContext) -> Tuple[int, int]:
    guards = 0
    deep_nested = 0
    if context.language == "python" and context.ast_tree is not None:
        parent_stack: List[ast.AST] = []

        class GuardVisitor(ast.NodeVisitor):
            def generic_visit(self, node: ast.AST) -> None:
                parent_stack.append(node)
                super().generic_visit(node)
                parent_stack.pop()

            def visit_If(self, node: ast.If) -> None:
                nonlocal guards, deep_nested
                if node.body and isinstance(node.body[0], (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                    guards += 1
                if sum(1 for parent in parent_stack if isinstance(parent, ast.If)) >= 1:
                    deep_nested += 1
                self.generic_visit(node)

        GuardVisitor().visit(context.ast_tree)
        return guards, deep_nested

    text = context.cleaned_code
    if context.language in {"javascript", "c", "cpp", "csharp"}:
        guards += len(re.findall(r"\bif\s*\([^)]*\)\s*(?:return|throw|continue|break)\b", text))
        guards += len(re.findall(r"\bif\s*\([^)]*\)\s*\{\s*(?:return|throw|continue|break)\b", text))
        deep_nested += len(re.findall(r"\bif\s*\([^)]*\)\s*\{[^{}]{0,200}\bif\s*\(", text, re.S))
    elif context.language == "bash":
        guards += len(re.findall(r"\bif\b[^\n]*\bthen\b[^\n]*(?:return|exit)\b", text))
        deep_nested += len(re.findall(r"\bif\b[^\n]*\bthen\b[^\n]*\n(?:[ \t]+.*\n){0,4}[ \t]+if\b", text))
    return guards, deep_nested


def meaningful_identifier_score(identifiers: Sequence[str]) -> Tuple[float, int, float]:
    cleaned = [item for item in identifiers if item and not item.startswith("__")]
    if not cleaned:
        return 0.0, 0, 0.0
    discouraged_single = sum(1 for item in cleaned if len(item) == 1 and item not in {"i", "j", "k", "n", "x", "y"})
    meaningful = 0
    total_parts = 0
    for item in cleaned:
        parts = split_identifier(item)
        if not parts:
            continue
        total_parts += len(parts)
        meaningful += sum(1 for part in parts if part in COMMON_IDENTIFIER_WORDS or len(part) > 3)
    dictionary_ratio = safe_div(meaningful, total_parts, default=0.0)
    score = statistics.mean([1.0 - safe_div(discouraged_single, len(cleaned), default=0.0), dictionary_ratio])
    return clamp(score), discouraged_single, dictionary_ratio

@MetricRegistry.register
class LineLengthUniformityMetric(BaseMetric):
    name = "line_length_uniformity"
    display_name = "Line-length uniformity"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["buse_weimer"], REFERENCE_LIBRARY["pep8"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        lengths = [len(line.rstrip("\n")) for line in context.non_blank_lines]
        if len(lengths) < 5:
            return self.not_applicable("Too few non-blank lines for stable dispersion.")
        cv = coefficient_of_variation(lengths)
        score = low_value_score(cv, float(self.threshold("ai_low", 0.22)), float(self.threshold("human_high", 0.70)))
        detail = f"cv={cv:.3f}, analysed_lines={len(lengths)}"
        return self.result(cv, score, "Very low variation can indicate templated structure, although formatters and disciplined authors can look similar.", detail)


@MetricRegistry.register
class CommentDensityMetric(BaseMetric):
    name = "comment_density"
    display_name = "Comment density"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["buse_weimer"], REFERENCE_LIBRARY["rahman_detection"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        if not context.non_blank_lines:
            return self.not_applicable("The file has no non-blank lines.")
        density = safe_div(len(context.comment_lines), len(context.non_blank_lines))
        human_low = float(self.threshold("human_low", 0.03))
        ai_low = float(self.threshold("ai_low", 0.12))
        ai_high = float(self.threshold("ai_high", 0.32))
        score = 0.0 if density < human_low else bell_score(density, ai_low, (ai_low + ai_high) / 2.0, ai_high)
        detail = f"comments={len(context.comment_lines)}, non_blank={len(context.non_blank_lines)}, ratio={density:.3f}"
        return self.result(density, score, "A moderate density of comments can align with generated scaffolding, but it is not reliable on its own.", detail)


@MetricRegistry.register
class CommentGenericnessMetric(BaseMetric):
    name = "comment_genericness"
    display_name = "Comment genericness"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["rahman_detection"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        cleaned_comments = [strip_comment_prefix(text) for text in context.comment_texts if text.strip()]
        if len(cleaned_comments) < 3:
            return self.not_applicable("Too few comments for a stable typological profile.")
        generic_count = 0
        human_markers = 0
        for comment in cleaned_comments:
            if any(pattern.match(comment) for pattern in GENERIC_COMMENT_PATTERNS):
                generic_count += 1
            if any(pattern.match(comment) for pattern in HUMAN_COMMENT_MARKERS):
                human_markers += 1
        generic_ratio = safe_div(generic_count, len(cleaned_comments))
        human_ratio = safe_div(human_markers, len(cleaned_comments))
        score = clamp(high_ratio_score(generic_ratio, float(self.threshold("ai_low", 0.20)), float(self.threshold("ai_high", 0.50))) * (1.0 - human_ratio))
        detail = f"comments={len(cleaned_comments)}, generic={generic_count}, human_markers={human_markers}"
        return self.result(generic_ratio, score, "Formulaic explanatory comments occur frequently in LLM output.", detail)


@MetricRegistry.register
class BlankLineRegularityMetric(BaseMetric):
    name = "blank_line_regularity"
    display_name = "Blank-line regularity"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["buse_weimer"], REFERENCE_LIBRARY["rahman_detection"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        if len(context.blank_runs) < 3:
            return self.not_applicable("Too few blank-line runs for a useful regularity estimate.")
        cv = coefficient_of_variation([float(item) for item in context.blank_runs])
        score = low_value_score(cv, float(self.threshold("ai_low", 0.18)), float(self.threshold("ai_high", 0.55)))
        detail = f"runs={context.blank_runs}, cv={cv:.3f}"
        return self.result(cv, score, "Very regular separation can indicate mechanical generation.", detail)


@MetricRegistry.register
class LexicalEntropyMetric(BaseMetric):
    name = "lexical_entropy"
    display_name = "Lexical entropy"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["rahman_detection"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        tokens = context.identifiers + context.tokens_operators + context.tokens_operands
        if len(tokens) < 20:
            return self.not_applicable("Too few tokens for a stable entropy estimate.")
        entropy = shannon_entropy(" ".join(tokens))
        score = band_score(entropy, float(self.threshold("ai_low", 3.8)), float(self.threshold("ai_high", 4.5)), softness=0.7)
        detail = f"entropy={entropy:.3f}, tokens={len(tokens)}"
        return self.result(entropy, score, "Moderate lexical entropy can reflect repetitive token choice, but the signal is exploratory.", detail)


@MetricRegistry.register
class ErrorHandlingDensityMetric(BaseMetric):
    name = "error_handling_density"
    display_name = "Error-handling density"
    supported_languages = {"python", "javascript", "bash", "c", "cpp", "csharp"}
    references = [REFERENCE_LIBRARY["rahman_detection"], REFERENCE_LIBRARY["buse_weimer"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        code_lines = max(len(context.code_lines), 1)
        if code_lines < 8:
            return self.not_applicable("Too few effective code lines for a stable density estimate.")
        if lang == "python":
            count = python_error_count(context.ast_tree)
        elif lang == "javascript":
            count = len(re.findall(r"\b(?:try|catch|finally|throw)\b", context.cleaned_code))
        elif lang == "bash":
            count = 0
            count += len(re.findall(r"\btrap\b", context.cleaned_code))
            count += len(re.findall(r"\bset\s+-[^ \n]*e\b", context.cleaned_code))
            count += len(re.findall(r"\|\|\s*(?:exit|return)\b", context.cleaned_code))
        elif lang in {"c", "cpp"}:
            count = 0
            count += len(re.findall(r"\bassert\s*\(", context.cleaned_code))
            count += len(re.findall(r"\b(?:try|catch|throw)\b", context.cleaned_code))
            count += len(re.findall(r"\bgoto\s+\w*cleanup\b", context.cleaned_code))
        else:
            count = 0
            count += len(re.findall(r"\b(?:try|catch|finally|throw)\b", context.cleaned_code))
            count += len(re.findall(r"\bArgumentNullException\b|\bDebug\.Assert\b", context.cleaned_code))
        density = safe_div(count, code_lines / 20.0)
        ai_low = float(self.threshold("ai_low", 0.4))
        ai_high = float(self.threshold("ai_high", 1.8))
        score = 0.0 if density < ai_low else band_score(density, ai_low, ai_high, softness=1.0)
        detail = f"patterns={count}, density_per_20={density:.3f}"
        return self.result(density, score, "Generated code often adds explicit safety wrappers and error paths more consistently than student code does.", detail)


@MetricRegistry.register
class BoilerplatePresenceMetric(BaseMetric):
    name = "boilerplate_presence"
    display_name = "Boilerplate presence"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["pep8"], REFERENCE_LIBRARY["c99"], REFERENCE_LIBRARY["csharp_spec"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        indicators, total = boilerplate_indicators(code, lang, context)
        if total == 0:
            return self.not_applicable("No language-specific boilerplate profile is defined for this language.")
        ratio = safe_div(indicators, total)
        score = high_ratio_score(ratio, float(self.threshold("ai_low", 0.20)), float(self.threshold("ai_high", 0.80)))
        detail = f"indicators={indicators}/{total}"
        return self.result(ratio, score, "Reusable wrapper patterns are common in generated code, but disciplined human code can look identical.", detail)


@MetricRegistry.register
class IdentifierStyleMetric(BaseMetric):
    name = "identifier_style"
    display_name = "Identifier style"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["buse_weimer"], REFERENCE_LIBRARY["pep8"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        identifiers = [item for item in context.identifiers if item and not item.startswith("__")]
        if len(identifiers) < 5:
            return self.not_applicable("Too few relevant identifiers.")
        lengths = [len(item) for item in identifiers]
        mean_length = statistics.mean(lengths)
        cv = coefficient_of_variation(lengths)
        short_ratio = safe_div(sum(1 for item in identifiers if len(item) <= 2), len(identifiers))
        style_counts = Counter(identifier_style_kind(item) for item in identifiers)
        dominant_ratio = safe_div(max(style_counts.values()), len(identifiers))
        semantic_score, discouraged_single, dictionary_ratio = meaningful_identifier_score(identifiers)
        score = statistics.mean(
            [
                band_score(mean_length, 5.0, 12.0, softness=1.5),
                low_value_score(cv, 0.20, 0.90),
                low_value_score(short_ratio, 0.05, 0.35),
                high_ratio_score(dominant_ratio, 0.55, 0.85),
                semantic_score,
            ]
        )
        detail = (
            f"identifiers={len(identifiers)}, mean_length={mean_length:.2f}, cv={cv:.2f}, "
            f"short_ratio={short_ratio:.1%}, dominant_style={dominant_ratio:.1%}, "
            f"discouraged_single={discouraged_single}, dictionary_ratio={dictionary_ratio:.1%}"
        )
        return self.result(mean_length, score, "Consistent naming, moderate identifier length and semantically legible names often accompany carefully scaffolded code.", detail)

@MetricRegistry.register
class FunctionLengthMetric(BaseMetric):
    name = "function_length"
    display_name = "Function length"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["mccabe"], REFERENCE_LIBRARY["buse_weimer"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        lengths = function_lengths(context)
        if len(lengths) < 2:
            return self.not_applicable("Too few functions for a stable length distribution.")
        mean_length = statistics.mean(lengths)
        cv = coefficient_of_variation([float(item) for item in lengths])
        score = statistics.mean(
            [
                band_score(mean_length, float(self.threshold("ai_low", 8.0)), float(self.threshold("ai_high", 24.0)), softness=1.2),
                low_value_score(cv, 0.20, float(self.threshold("cv_high", 0.55))),
            ]
        )
        detail = f"functions={len(lengths)}, mean={mean_length:.2f}, cv={cv:.2f}"
        return self.result(mean_length, score, "Moderate function sizes and reduced spread are common in template-driven output.", detail)


@MetricRegistry.register
class CyclomaticComplexityMetric(BaseMetric):
    name = "cyclomatic_complexity"
    display_name = "Cyclomatic complexity"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["mccabe"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        if lang == "python":
            if not context.functions:
                return self.not_applicable("No parsable Python functions are available for exact complexity.")
            values = [item.cyclomatic for item in context.functions]
            mean_value = statistics.mean(values)
            score = band_score(mean_value, float(self.threshold("ai_low", 1.5)), float(self.threshold("ai_high", 4.5)), softness=1.5)
            detail = f"functions={len(values)}, mean_complexity={mean_value:.2f}, values={values}"
            return self.result(mean_value, score, "Moderate McCabe complexity is more typical than either extreme in generic generated code.", detail)
        if context.functions:
            values = [item.cyclomatic for item in context.functions]
            mean_value = statistics.mean(values)
            score = band_score(mean_value, float(self.threshold("ai_low", 1.5)), float(self.threshold("ai_high", 4.5)), softness=1.5)
            detail = f"functions={len(values)}, mean_complexity={mean_value:.2f}, values={values}"
            return self.result(mean_value, score, "Approximate control-flow complexity is derived from language-specific structural cues.", detail)
        line_count = max(len(context.code_lines), 1)
        count = len(re.findall(r"\b(?:if|for|while|case|catch|switch|elif|except)\b|&&|\|\||\?", context.cleaned_code))
        density = safe_div(count, line_count / 20.0)
        score = band_score(density, float(self.threshold("ai_low", 1.5)), float(self.threshold("density_high", 2.6)), softness=1.2)
        detail = f"approximate_branches={count}, density_per_20={density:.2f}"
        return self.result(density, score, "Approximate complexity is used when reliable function extraction is not available.", detail)


@MetricRegistry.register
class HalsteadDifficultyMetric(BaseMetric):
    name = "halstead_difficulty"
    display_name = "Halstead difficulty"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["halstead"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        operators = context.tokens_operators
        operands = context.tokens_operands
        if len(operators) + len(operands) < 20:
            return self.not_applicable("Too few tokens for a stable Halstead vocabulary.")
        n1 = len(set(operators))
        n2 = len(set(operands))
        N1 = len(operators)
        N2 = len(operands)
        if n1 == 0 or n2 == 0:
            return self.not_applicable("There are not enough operators and operands for Halstead estimation.")
        difficulty = (n1 / 2.0) * safe_div(N2, n2, default=0.0)
        vocabulary = n1 + n2
        volume = (N1 + N2) * math.log2(vocabulary) if vocabulary > 1 else 0.0
        score = band_score(difficulty, float(self.threshold("ai_low", 8.0)), float(self.threshold("ai_high", 24.0)), softness=1.2)
        detail = f"n1={n1}, n2={n2}, N1={N1}, N2={N2}, volume={volume:.2f}, difficulty={difficulty:.2f}"
        return self.result(difficulty, score, "Halstead difficulty is treated as an auxiliary software-science signal.", detail)


@MetricRegistry.register
class MagicNumbersMetric(BaseMetric):
    name = "magic_numbers"
    display_name = "Magic-number density"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["buse_weimer"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        line_count = max(len(context.code_lines), 1)
        numbers = RE_NUMBER.findall(context.cleaned_code)
        whitelist = {"0", "1", "2", "-1", "+1", "0.0", "1.0", "0x0"}
        magic = [item for item in numbers if item not in whitelist]
        density = safe_div(len(magic), line_count / 20.0)
        score = low_value_score(density, float(self.threshold("ai_low", 0.3)), float(self.threshold("ai_high", 1.4)))
        detail = f"numbers={len(numbers)}, magic_candidates={len(magic)}, density={density:.2f}"
        return self.result(density, score, "Near absence of unexplained literals is more common in carefully scaffolded or polished code.", detail)


@MetricRegistry.register
class DeadCodeResidueMetric(BaseMetric):
    name = "dead_code_residue"
    display_name = "Dead-code residue"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["buse_weimer"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        line_count = max(len(context.code_lines), 1)
        density = safe_div(context.commented_out_code_lines, line_count)
        score = low_value_score(density, float(self.threshold("ai_low", 0.00)), float(self.threshold("ai_high", 0.04)))
        detail = f"commented_out_code_lines={context.commented_out_code_lines}, ratio={density:.3f}"
        return self.result(density, score, "Commented-out code and debugging residue are more typical of incremental human drafting.", detail)


@MetricRegistry.register
class NestingDepthMetric(BaseMetric):
    name = "nesting_depth"
    display_name = "Maximum nesting depth"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["mccabe"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        if lang == "python":
            depth = float(python_max_nesting(context.ast_tree))
        elif lang == "bash":
            depth = float(approx_bash_nesting(context.lines))
        else:
            depth = float(approx_brace_nesting(context.cleaned_code))
        score = 0.15 if depth <= 1.0 else band_score(depth, float(self.threshold("ai_low", 2.0)), float(self.threshold("ai_high", 4.0)), softness=0.8)
        detail = f"max_depth={depth:.0f}"
        return self.result(depth, score, "Intermediate nesting is more typical than either extreme in generic generated code.", detail)


@MetricRegistry.register
class DefensiveProgrammingMetric(BaseMetric):
    name = "defensive_programming"
    display_name = "Defensive programming"
    supported_languages = {"python", "javascript", "bash", "c", "cpp", "csharp"}
    references = [REFERENCE_LIBRARY["rahman_detection"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        line_count = max(len(context.code_lines), 1)
        if lang == "python":
            count = python_guard_count(context.ast_tree)
            count += len(re.findall(r"\bif\s+not\b", code))
        elif lang == "javascript":
            count = 0
            count += len(re.findall(r"\btypeof\b", context.cleaned_code))
            count += len(re.findall(r"===?\s*null|===?\s*undefined|!==?\s*null|!==?\s*undefined", context.cleaned_code))
            count += len(re.findall(r"\bthrow\s+new\s+[A-Za-z_$][A-Za-z0-9_$]*Error", context.cleaned_code))
            count += len(re.findall(r"\?\.|\?\?", context.cleaned_code))
        elif lang == "bash":
            count = 0
            count += len(re.findall(r"\bset\s+-[^ \n]*(?:e|u|o)\b", context.cleaned_code))
            count += len(re.findall(r"\[\s+-[A-Za-z]", context.cleaned_code))
            count += len(re.findall(r"\btest\s+-[A-Za-z]", context.cleaned_code))
        elif lang in {"c", "cpp"}:
            count = 0
            count += len(re.findall(r"\bassert\s*\(", context.cleaned_code))
            count += len(re.findall(r"\bif\s*\([^)]*NULL[^)]*\)\s*(?:return|goto|break)", context.cleaned_code))
            count += len(re.findall(r"\bif\s*\([^)]*!\s*[A-Za-z_][A-Za-z0-9_]*[^)]*\)\s*(?:return|goto|break)", context.cleaned_code))
            count += len(re.findall(r"\b(?:try|catch|throw)\b", context.cleaned_code))
        else:
            count = 0
            count += len(re.findall(r"\b(?:ArgumentNullException|InvalidOperationException|Debug\.Assert)\b", context.cleaned_code))
            count += len(re.findall(r"\bif\s*\([^)]*null[^)]*\)\s*(?:throw|return)", context.cleaned_code))
            count += len(re.findall(r"\b(?:try|catch|finally)\b", context.cleaned_code))
        density = safe_div(count, line_count / 20.0)
        ai_low = float(self.threshold("ai_low", 0.4))
        ai_high = float(self.threshold("ai_high", 2.0))
        score = 0.0 if density < ai_low else band_score(density, ai_low, ai_high, softness=1.0)
        detail = f"guards={count}, density={density:.2f}/20 lines"
        return self.result(density, score, "Generated code often introduces guards and validations more conspicuously than spontaneous student code.", detail)


@MetricRegistry.register
class CommentCodeRatioMetric(BaseMetric):
    name = "comment_to_code_ratio"
    display_name = "Comment-to-code ratio (universal) [A]"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["rahman_detection"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        if len(context.code_lines) < 8:
            return self.not_applicable("Too few code lines for a stable comment-to-code ratio.")
        ratio = safe_div(len(context.comment_lines), len(context.code_lines))
        score = bell_score(ratio, float(self.threshold("ai_low", 0.10)), float(self.threshold("ai_peak", 0.24)), float(self.threshold("ai_high", 0.40)))
        if ratio < float(self.threshold("human_low", 0.03)):
            score = 0.0
        detail = f"comment_lines={len(context.comment_lines)}, code_lines={len(context.code_lines)}, ratio={ratio:.3f}"
        return self.result(ratio, score, "This remains the strongest default stylometric signal in the bundled configuration.", detail)


@MetricRegistry.register
class DeclarativeRatioMetric(BaseMetric):
    name = "declarative_ratio"
    display_name = "Declarative-line ratio"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["buse_weimer"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        total = context.declarative_line_count + context.control_line_count + context.executable_line_count
        if total < 5:
            return self.not_applicable("Too few active lines for declarative structure analysis.")
        ratio = safe_div(context.declarative_line_count, total)
        score = band_score(ratio, float(self.threshold("ai_low", 0.10)), float(self.threshold("ai_high", 0.28)), softness=1.2)
        detail = f"declarative={context.declarative_line_count}, control={context.control_line_count}, executable={context.executable_line_count}"
        return self.result(ratio, score, "A moderate declarative share can reflect generated scaffolding, imports and helper setup.", detail)

@MetricRegistry.register
class ControlRatioMetric(BaseMetric):
    name = "control_ratio"
    display_name = "Control-line ratio"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["mccabe"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        total = context.declarative_line_count + context.control_line_count + context.executable_line_count
        if total < 5:
            return self.not_applicable("Too few active lines for control-structure analysis.")
        ratio = safe_div(context.control_line_count, total)
        score = band_score(ratio, float(self.threshold("ai_low", 0.10)), float(self.threshold("ai_high", 0.24)), softness=1.2)
        detail = f"control={context.control_line_count}, total_active={total}, ratio={ratio:.3f}"
        return self.result(ratio, score, "Intermediate control density is more typical than either extreme.", detail)


@MetricRegistry.register
class TypeTokenRatioMetric(BaseMetric):
    name = "type_token_ratio"
    display_name = "Code vocabulary diversity (LTTR)"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["rahman_detection"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        tokens = [item for item in context.identifiers if item]
        if len(tokens) < 20:
            return self.not_applicable("Too few identifiers for a stable logarithmic type-token ratio.")
        types = len(set(tokens))
        lttr = safe_div(math.log(max(types, 2)), math.log(max(len(tokens), 2)), default=0.0)
        score = band_score(lttr, float(self.threshold("ai_low", 0.82)), float(self.threshold("ai_high", 0.92)), softness=0.25)
        detail = f"identifiers={len(tokens)}, unique={types}, lttr={lttr:.3f}"
        return self.result(lttr, score, "The logarithmic type-token ratio reduces the length sensitivity of the raw TTR.", detail)


@MetricRegistry.register
class IndentationConsistencyMetric(BaseMetric):
    name = "indentation_consistency"
    display_name = "Indentation consistency"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["pep8"], REFERENCE_LIBRARY["buse_weimer"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        widths = context.indentation_widths
        if len(widths) < 5:
            return self.not_applicable("Too few indented lines for a consistency estimate.")
        positive_widths = [width for width in widths if width > 0]
        if not positive_widths:
            return self.not_applicable("There are no indented lines.")
        steps: List[int] = []
        previous = 0
        for width in positive_widths:
            if width > previous:
                steps.append(width - previous)
            previous = width
        dominant_step_ratio = 1.0
        if steps:
            counter = Counter(steps)
            dominant_step_ratio = safe_div(counter.most_common(1)[0][1], len(steps))
        kind_total = sum(context.indentation_kinds.values())
        space_ratio = safe_div(context.indentation_kinds.get("spaces", 0), kind_total)
        mixed_ratio = safe_div(context.indentation_kinds.get("mixed", 0), kind_total)
        tab_ratio = safe_div(context.indentation_kinds.get("tabs", 0), kind_total)
        consistency = statistics.mean([space_ratio, dominant_step_ratio, 1.0 - mixed_ratio, 1.0 - min(tab_ratio, 1.0)])
        score = high_ratio_score(consistency, float(self.threshold("ai_low", 0.85)), float(self.threshold("ai_high", 0.99)))
        detail = f"spaces={space_ratio:.1%}, tabs={tab_ratio:.1%}, mixed={mixed_ratio:.1%}, dominant_step={dominant_step_ratio:.1%}"
        return self.result(consistency, score, "Very regular indentation can be AI-like, but auto-formatters create the same effect.", detail)


@MetricRegistry.register
class UsedImportRatioMetric(BaseMetric):
    name = "used_import_ratio"
    display_name = "Used-import ratio"
    supported_languages = {"python", "javascript"}
    references = [REFERENCE_LIBRARY["buse_weimer"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        if lang == "python":
            if not context.imported_names:
                return self.not_applicable("There are no explicit Python imports.")
            imported = set(context.imported_names)
            used = imported & context.used_names
            ratio = safe_div(len(used), len(imported))
            detail = f"imported={len(imported)}, used={len(used)}"
        else:
            ratio = approx_js_import_use_ratio(context)
            if ratio is None:
                return self.not_applicable("There are no JavaScript imports with explicit bindings.")
            detail = f"usage_ratio={ratio:.3f}"
        score = high_ratio_score(float(ratio), float(self.threshold("ai_low", 0.80)), float(self.threshold("ai_high", 1.00)))
        return self.result(ratio, score, "Using nearly all imported symbols suggests a tidier draft with less experimental residue.", detail)


@MetricRegistry.register
class StructuralSelfSimilarityMetric(BaseMetric):
    name = "structural_self_similarity"
    display_name = "Structural self-similarity"
    supported_languages = {"python"}
    references = [REFERENCE_LIBRARY["rahman_detection"], REFERENCE_LIBRARY["mccabe"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        similarity = python_structural_similarity(context.functions)
        if similarity is None:
            return self.not_applicable("At least three Python functions are needed for structural self-similarity.")
        score = high_ratio_score(similarity, float(self.threshold("ai_low", 0.55)), float(self.threshold("ai_high", 0.82)))
        detail = f"adjacent_similarity={similarity:.3f}"
        return self.result(similarity, score, "Strongly similar adjacent function structures can suggest serial generation from repeated prompts.", detail)


@MetricRegistry.register
class FunctionComplexityUniformityMetric(BaseMetric):
    name = "function_complexity_uniformity"
    display_name = "Function-complexity uniformity"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["mccabe"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        if len(context.functions) < 3:
            return self.not_applicable("At least three functions are needed for complexity dispersion.")
        complexities = [float(item.cyclomatic) for item in context.functions]
        cv = coefficient_of_variation(complexities)
        score = low_value_score(cv, float(self.threshold("ai_low", 0.18)), float(self.threshold("ai_high", 0.48)))
        detail = f"complexities={complexities}, cv={cv:.3f}"
        return self.result(cv, score, "Low variance in per-function complexity can indicate templated generation.", detail)


@MetricRegistry.register
class DocstringCoverageMetric(BaseMetric):
    name = "docstring_coverage"
    display_name = "Docstring coverage"
    supported_languages = {"python"}
    references = [REFERENCE_LIBRARY["pep257"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        documented, total = python_docstring_coverage(context.ast_tree)
        if total < 2:
            return self.not_applicable("Too few Python classes or functions for docstring coverage.")
        ratio = safe_div(documented, total)
        score = high_ratio_score(ratio, float(self.threshold("ai_low", 0.35)), float(self.threshold("ai_high", 0.80)))
        detail = f"documented={documented}, entities={total}, ratio={ratio:.3f}"
        return self.result(ratio, score, "High docstring coverage is common in well-instructed LLM output, but it also appears in advanced student work.", detail)


@MetricRegistry.register
class TypeHintCoverageMetric(BaseMetric):
    name = "type_hint_coverage"
    display_name = "Type-hint coverage"
    supported_languages = {"python"}
    references = [REFERENCE_LIBRARY["pep484"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        if len(context.functions) < 2:
            return self.not_applicable("Too few Python functions for type-hint coverage.")
        hinted = sum(1 for item in context.functions if item.has_type_hints)
        ratio = safe_div(hinted, len(context.functions))
        score = high_ratio_score(ratio, float(self.threshold("ai_low", 0.25)), float(self.threshold("ai_high", 0.75)))
        detail = f"annotated_functions={hinted}, total={len(context.functions)}, ratio={ratio:.3f}"
        return self.result(ratio, score, "Type hints are most informative where the course does not require them.", detail)


@MetricRegistry.register
class JavaScriptModernSyntaxMetric(BaseMetric):
    name = "javascript_modern_syntax"
    display_name = "Modern JavaScript syntax"
    supported_languages = {"javascript"}
    references = [REFERENCE_LIBRARY["rahman_detection"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        modern = 0
        modern += len(re.findall(r"=>", code))
        modern += len(re.findall(r"\b(?:const|let)\b", code))
        modern += len(re.findall(r"`[^`]*\$\{", code))
        modern += len(re.findall(r"(?:const|let|var)\s*[{[]", code))
        modern += len(re.findall(r"\.\.\.", code))
        modern += len(re.findall(r"\?\.|\?\?", code))
        legacy = len(re.findall(r"\bvar\b", code)) + 1
        ratio = safe_div(modern, modern + legacy)
        score = high_ratio_score(ratio, float(self.threshold("ai_low", 0.55)), float(self.threshold("ai_high", 0.92)))
        detail = f"modern={modern}, legacy={legacy - 1}, ratio={ratio:.3f}"
        return self.result(ratio, score, "Current generators almost always prefer modern JavaScript syntax.", detail)


@MetricRegistry.register
class BashQuotingConsistencyMetric(BaseMetric):
    name = "bash_quoting_consistency"
    display_name = "Bash variable-quoting consistency"
    supported_languages = {"bash"}
    references = [REFERENCE_LIBRARY["pep8"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        refs = re.findall(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]+\})", code)
        if len(refs) < 5:
            return self.not_applicable("Too few variable references for a stable quoting estimate.")
        quoted = len(re.findall(r'"[^"\n]*\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]+\})[^"\n]*"', code))
        ratio = safe_div(quoted, len(refs))
        score = high_ratio_score(ratio, float(self.threshold("ai_low", 0.55)), float(self.threshold("ai_high", 0.98)))
        detail = f"references={len(refs)}, double_quoted={quoted}, ratio={ratio:.3f}"
        return self.result(ratio, score, "Generated shell scripts often quote variables more consistently to avoid expansion surprises.", detail)


@MetricRegistry.register
class ImportOrganizationMetric(BaseMetric):
    name = "import_organization"
    display_name = "Import organisation"
    supported_languages = {"python"}
    references = [REFERENCE_LIBRARY["pep8"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        outcome = import_organisation_score(context)
        if outcome is None:
            return self.not_applicable("Too few Python imports for organisation analysis.")
        ratio, detail = outcome
        score = high_ratio_score(ratio, float(self.threshold("ai_low", 0.50)), float(self.threshold("ai_high", 1.00)))
        return self.result(ratio, score, "Ordered and grouped imports are useful, but this remains a low-weight style signal.", detail)

def preferred_naming_ratio(identifiers: Sequence[str], language: str) -> Tuple[float, float]:
    styles = Counter(identifier_style_kind(item) for item in identifiers if item)
    total = sum(styles.values())
    dominant_ratio = safe_div(max(styles.values()) if styles else 0, total, default=0.0)
    if language in {"c", "python", "bash"}:
        preferred_ratio = safe_div(styles.get("snake", 0) + styles.get("upper", 0), total, default=0.0)
    else:
        preferred_ratio = safe_div(styles.get("camel", 0) + styles.get("pascal", 0), total, default=0.0)
    return dominant_ratio, preferred_ratio


def function_cohesion_ratio(context: AnalysisContext) -> Optional[float]:
    if not context.functions:
        return None
    cohesive = sum(1 for item in context.functions if item.length <= 30 and item.cyclomatic <= 8)
    return safe_div(cohesive, len(context.functions), default=0.0)


def magic_number_absence_score(context: AnalysisContext) -> float:
    line_count = max(len(context.code_lines), 1)
    numbers = RE_NUMBER.findall(context.cleaned_code)
    whitelist = {"0", "1", "2", "-1", "+1", "0.0", "1.0", "0x0"}
    magic = [item for item in numbers if item not in whitelist]
    density = safe_div(len(magic), line_count / 20.0)
    return low_value_score(density, 0.3, 1.4)


def code_elegance_components(context: AnalysisContext) -> Dict[str, float]:
    identifiers = [item for item in context.identifiers if item and not item.startswith("__")]
    dominant_ratio, preferred_ratio = preferred_naming_ratio(identifiers, context.language) if identifiers else (0.0, 0.0)
    naming = statistics.mean([dominant_ratio, preferred_ratio]) if identifiers else 0.0

    cohesion = function_cohesion_ratio(context)
    cohesion_score = cohesion if cohesion is not None else 0.5

    dry_density = duplicate_block_density(context.code_lines, context.language)
    dry_score = low_value_score(dry_density, 0.2, 1.0)

    magic_absence = magic_number_absence_score(context)

    guards, deep_nested = guard_clause_profile(context)
    guard_score = safe_div(guards, guards + deep_nested + 1.0, default=0.0)

    return {
        "naming": naming,
        "cohesion": cohesion_score,
        "dry": dry_score,
        "magic": magic_absence,
        "guards": guard_score,
    }


@MetricRegistry.register
class RegisterPressureMetric(BaseMetric):
    name = "register_pressure"
    display_name = "Register pressure estimation"
    supported_languages = {"c", "cpp"}
    references = [REFERENCE_LIBRARY["chaitin"], REFERENCE_LIBRARY["poletto"]]
    group = "quality"
    contributes_to_overall = False

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        if not context.functions:
            return self.not_applicable("No C or C++ functions were recognised.")
        ratios: List[float] = []
        peaks: List[int] = []
        flagged: List[str] = []
        for function in context.functions:
            profile = register_pressure_profile(function, lang)
            ratios.append(profile["ratio"])
            peaks.append(profile["peak_live"])
            if profile["peak_live"] > DEFAULT_REGISTERS_X64:
                flagged.append(function.name)
        mean_ratio = statistics.mean(ratios) if ratios else 0.0
        max_ratio = max(ratios) if ratios else 0.0
        quality_score = 1.0
        if max_ratio >= float(self.threshold("moderate", 0.85)):
            quality_score = low_value_score(max_ratio, float(self.threshold("moderate", 0.85)), 1.25)
        else:
            quality_score = high_ratio_score(1.0 - max_ratio, 1.0 - float(self.threshold("moderate", 0.85)), 1.0 - float(self.threshold("low", 0.50)))
        detail = f"mean_ratio={mean_ratio:.3f}, max_ratio={max_ratio:.3f}, peak_live={max(peaks) if peaks else 0}, flagged={flagged[:5]}"
        return self.result(max_ratio, quality_score, "Lower estimated pressure indicates cleaner local allocation and less likelihood of register spilling.", detail)


@MetricRegistry.register
class StackFrameDepthMetric(BaseMetric):
    name = "stack_frame_depth"
    display_name = "Stack frame depth estimation"
    supported_languages = {"c", "cpp", "csharp"}
    references = [REFERENCE_LIBRARY["aho"], REFERENCE_LIBRARY["muchnick"]]
    group = "quality"
    contributes_to_overall = False

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        if not context.functions:
            return self.not_applicable("No functions or methods were recognised.")
        frames: List[int] = []
        recursive: List[str] = []
        large_arrays: List[str] = []
        for function in context.functions:
            profile = stack_frame_profile(function, lang)
            frames.append(profile["frame_bytes"])
            if profile["recursive"]:
                recursive.append(function.name)
            if profile["large_arrays"] or profile["vla_items"]:
                large_arrays.append(function.name)
        mean_frame = statistics.mean(frames) if frames else 0.0
        max_frame = max(frames) if frames else 0.0
        small = float(self.threshold("small", 256.0))
        medium = float(self.threshold("medium", 4096.0))
        quality_score = 1.0 if max_frame <= small else low_value_score(max_frame, small, medium * 1.5)
        detail = f"mean_frame={mean_frame:.1f}B, max_frame={max_frame}B, recursive={recursive[:5]}, large_local_arrays={large_arrays[:5]}"
        return self.result(max_frame, quality_score, "Smaller local stack frames are safer and more typical of robust low-level code.", detail)


@MetricRegistry.register
class RedundantMemoryAccessMetric(BaseMetric):
    name = "redundant_memory_access"
    display_name = "Redundant memory access patterns"
    supported_languages = {"c", "cpp"}
    references = [REFERENCE_LIBRARY["aho"], REFERENCE_LIBRARY["muchnick"], REFERENCE_LIBRARY["c99"]]
    group = "quality"
    contributes_to_overall = False

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        if not context.functions:
            return self.not_applicable("No C or C++ functions were recognised.")
        densities: List[float] = []
        repeated = 0
        invariants = 0
        qualifiers = 0
        for function in context.functions:
            profile = redundant_memory_profile(function, lang)
            densities.append(profile["density"])
            repeated += profile["repeated_memory"]
            invariants += profile["invariant_duplicates"]
            qualifiers += profile["missing_qualifiers"]
        mean_density = statistics.mean(densities) if densities else 0.0
        quality_score = low_value_score(mean_density, float(self.threshold("low", 0.40)), float(self.threshold("high", 1.60)))
        detail = f"mean_density={mean_density:.3f}, repeated={repeated}, loop_invariants={invariants}, missing_const_or_restrict={qualifiers}"
        return self.result(mean_density, quality_score, "Fewer repeated memory expressions and clearer aliasing intent improve low-level quality.", detail)


@MetricRegistry.register
class CodeEleganceMetric(BaseMetric):
    name = "code_elegance"
    display_name = "Code elegance composite"
    supported_languages = code_languages()
    references = [REFERENCE_LIBRARY["buse_weimer"], REFERENCE_LIBRARY["pep8"], REFERENCE_LIBRARY["mccabe"]]
    group = "quality"
    contributes_to_overall = False

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        identifiers = [item for item in context.identifiers if item]
        if len(identifiers) < 5:
            return self.not_applicable("Too few identifiers for the elegance composite.")
        components = code_elegance_components(context)
        score = statistics.mean(list(components.values()))
        detail = ", ".join(f"{key}={value:.3f}" for key, value in components.items())
        return self.result(score, score, "This composite summarises naming consistency, cohesion, duplication, literal discipline and guard-clause style.", detail)


@MetricRegistry.register
class PreprocessorHygieneMetric(BaseMetric):
    name = "preprocessor_hygiene"
    display_name = "Preprocessor hygiene"
    supported_languages = {"c", "cpp"}
    references = [REFERENCE_LIBRARY["c99"], REFERENCE_LIBRARY["cpp_core"]]
    group = "quality"
    contributes_to_overall = False

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        profile = preprocessor_profile(context)
        score = statistics.mean(
            [
                1.0 if profile["has_guard"] else 0.0,
                low_value_score(float(profile["macro_abuse"]), 0.0, 4.0),
                low_value_score(float(profile["conditional_depth"]), 1.0, 5.0),
                1.0 if profile["system_before_project"] else 0.0,
            ]
        )
        detail = (
            f"include_count={profile['include_count']}, macro_abuse={profile['macro_abuse']}, "
            f"conditional_depth={profile['conditional_depth']}, has_guard={profile['has_guard']}, "
            f"system_before_project={profile['system_before_project']}"
        )
        return self.result(score, score, "Cleaner preprocessor usage usually means lower configuration complexity and better maintainability.", detail)


@MetricRegistry.register
class MarkdownHeadingStructureMetric(BaseMetric):
    name = "markdown_heading_structure"
    display_name = "Heading-structure regularity"
    supported_languages = prose_languages()
    references = [REFERENCE_LIBRARY["commonmark"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        headings = context.markdown.headings
        if len(headings) < 2:
            return self.not_applicable("Too few headings for hierarchy analysis.")
        jumps = 0
        repeats = 0
        previous_level = headings[0][0]
        for level, _, _ in headings[1:]:
            if level > previous_level + 1:
                jumps += 1
            if level == previous_level:
                repeats += 1
            previous_level = level
        penalty = safe_div(jumps + max(0, repeats - 1), len(headings), default=0.0)
        score = clamp(1.0 - penalty)
        detail = f"headings={len(headings)}, large_jumps={jumps}, repeated_levels={repeats}"
        return self.result(score, score, "A regular heading hierarchy usually reflects deliberate document structure.", detail)


@MetricRegistry.register
class MarkdownCodeFenceDensityMetric(BaseMetric):
    name = "markdown_code_fence_density"
    display_name = "Code-fence density"
    supported_languages = prose_languages()
    references = [REFERENCE_LIBRARY["commonmark"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        loc = max(context.loc, 1)
        density = safe_div(context.markdown.code_fence_count, loc / 100.0, default=0.0)
        score = band_score(density, float(self.threshold("low", 0.5)), float(self.threshold("high", 4.0)), softness=1.0)
        detail = f"code_fence_blocks={context.markdown.code_fence_count}, code_fence_lines={context.markdown.code_fence_line_count}, density_per_100_lines={density:.2f}"
        return self.result(density, score, "A moderate density of fenced code often suits technical Markdown documents.", detail)


@MetricRegistry.register
class MarkdownLinkDensityMetric(BaseMetric):
    name = "markdown_link_density"
    display_name = "Link density"
    supported_languages = prose_languages()
    references = [REFERENCE_LIBRARY["commonmark"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        words = max(context.markdown.prose_word_count, 1)
        density = safe_div(context.markdown.link_count, words / 100.0, default=0.0)
        score = band_score(density, float(self.threshold("low", 0.5)), float(self.threshold("high", 8.0)), softness=1.0)
        detail = f"links={context.markdown.link_count}, prose_words={context.markdown.prose_word_count}, density_per_100_words={density:.2f}"
        return self.result(density, score, "Moderate linking is typical of reference-rich technical prose.", detail)


@MetricRegistry.register
class MarkdownProseEntropyMetric(BaseMetric):
    name = "markdown_prose_entropy"
    display_name = "Prose entropy"
    supported_languages = prose_languages()
    references = [REFERENCE_LIBRARY["commonmark"], REFERENCE_LIBRARY["rahman_detection"]]

    def compute(self, code: str, lang: str, context: AnalysisContext) -> MetricResult:
        if context.markdown.prose_word_count < 40:
            return self.not_applicable("Too little prose for a stable entropy estimate.")
        entropy = shannon_entropy(context.markdown.prose_text)
        score = band_score(entropy, float(self.threshold("low", 3.5)), float(self.threshold("high", 4.8)), softness=0.7)
        detail = f"entropy={entropy:.3f}, prose_words={context.markdown.prose_word_count}"
        return self.result(entropy, score, "Prose entropy gives a narrow view of textual variability outside code fences.", detail)

class AnalysisEngine:
    """Run all enabled metrics on a shared analysis context."""

    def __init__(self, config: Dict[str, Dict[str, Any]]) -> None:
        self.config = config

    def analyse(
        self,
        code: str,
        filename: str,
        language_hint: Optional[str] = None,
        profile: str = DEFAULT_PROFILE,
    ) -> AnalysisReport:
        start = time.perf_counter()
        context = build_analysis_context(code, filename, language_hint)
        metrics: List[MetricResult] = []
        warnings: List[str] = list(context.notes)

        for metric_class in MetricRegistry.metric_classes():
            metric = metric_class(self.config)
            if not metric.enabled:
                continue
            if not metric.supports(context.language):
                metrics.append(metric.not_applicable("This metric does not apply to the detected language."))
                continue
            try:
                metrics.append(metric.compute(context.code, context.language, context))
            except Exception as exc:
                warnings.append(f"Metric {metric.name} failed: {exc}")
                metrics.append(
                    metric.not_applicable(
                        "The metric could not be computed because of an internal analysis error.",
                        detail=str(exc),
                    )
                )

        ai_metrics = [item for item in metrics if item.applicable and item.weight > 0 and item.contributes_to_overall]
        total_weight = sum(item.weight for item in ai_metrics)
        overall = safe_div(
            sum(item.score * item.weight for item in ai_metrics),
            total_weight,
            default=0.0,
        )

        verdict_class = "insufficient"
        verdict = VERDICTS["insufficient"]
        confidence = "Limited"

        if context.sloc < 5 or len(ai_metrics) < 4 or total_weight == 0.0:
            verdict_class = "insufficient"
            verdict = VERDICTS["insufficient"]
            confidence = "Limited"
        else:
            if overall < 0.28:
                verdict_class = "low"
            elif overall < 0.48:
                verdict_class = "moderate"
            elif overall < 0.68:
                verdict_class = "elevated"
            else:
                verdict_class = "high"
            verdict = VERDICTS[verdict_class]

            metric_coverage = safe_div(len(ai_metrics), len([m for m in metrics if m.weight > 0 and m.contributes_to_overall]), default=0.0)
            if context.sloc >= 80 and metric_coverage >= 0.75 and len(warnings) <= 2:
                confidence = "High"
            elif context.sloc >= 25 and metric_coverage >= 0.55:
                confidence = "Moderate"
            else:
                confidence = "Limited"

        duration = time.perf_counter() - start
        notes = [
            f"Detected language: {LANGUAGE_LABELS.get(context.language, context.language)}.",
            f"Total lines: {context.loc}; non-blank lines: {context.sloc}; comment lines: {len(context.comment_lines)}.",
            f"Applicable metrics: {len([m for m in metrics if m.applicable])} of {len(metrics)}; profile: {profile}.",
            "The result is probabilistic and should be read alongside oral examination, version history and assignment context.",
        ]
        if context.language == "markdown":
            notes.append("Markdown uses a narrower metric set because code-centric metrics do not transfer directly to prose-oriented documents.")
        if any(m.group == "quality" and m.applicable for m in metrics):
            notes.append("Quality metrics are reported separately from the AI-style aggregate so that low-level code quality does not distort the authorship signal.")

        return AnalysisReport(
            filename=filename,
            language=context.language,
            loc=context.loc,
            sloc=context.sloc,
            metrics=metrics,
            overall_score=overall,
            confidence=confidence,
            verdict=verdict,
            verdict_class=verdict_class,
            notes=notes,
            warnings=warnings,
            profile=profile,
            duration_seconds=duration,
        )


def report_to_dict(report: AnalysisReport) -> Dict[str, Any]:
    return {
        "filename": report.filename,
        "language": report.language,
        "loc": report.loc,
        "sloc": report.sloc,
        "overall_score": round(report.overall_score, 4),
        "overall_percent": round(report.overall_score * 100.0, 1),
        "confidence": report.confidence,
        "verdict": report.verdict,
        "verdict_class": report.verdict_class,
        "profile": report.profile,
        "duration_seconds": round(report.duration_seconds, 4),
        "notes": report.notes,
        "warnings": report.warnings,
        "metrics": [
            {
                "name": item.name,
                "display_name": item.display_name,
                "value": item.value,
                "value_display": item.value_display,
                "score": round(item.score, 4),
                "score_percent": round(item.score * 100.0, 1),
                "weight": round(item.weight, 4),
                "applicable": item.applicable,
                "explanation": item.explanation,
                "detail": item.detail,
                "references": item.references,
                "group": item.group,
                "contributes_to_overall": item.contributes_to_overall,
            }
            for item in report.metrics
        ],
    }


def format_report_text(report: AnalysisReport) -> str:
    lines = [
        APP_TITLE,
        "=" * len(APP_TITLE),
        f"File: {report.filename}",
        f"Language: {LANGUAGE_LABELS.get(report.language, report.language)}",
        f"Total lines: {report.loc}",
        f"Non-blank lines: {report.sloc}",
        f"Overall AI-style score: {report.overall_score * 100:.1f}%",
        f"Confidence: {report.confidence}",
        f"Verdict: {report.verdict}",
        f"Profile: {report.profile}",
        "",
        "Metrics:",
    ]
    for metric in report.metrics:
        state = "Applicable" if metric.applicable else "N/A"
        suffix = " [quality]" if metric.group == "quality" else ""
        lines.append(
            f"- {metric.display_name}{suffix}: value={metric.value_display}, score={metric.score * 100:.1f}%, "
            f"weight={metric.weight:.2f}, {state}"
        )
        if metric.detail:
            lines.append(f"    {metric.detail}")
        if metric.explanation:
            lines.append(f"    {metric.explanation}")
    if report.notes:
        lines.extend(["", "Notes:"])
        lines.extend(f"- {note}" for note in report.notes)
    if report.warnings:
        lines.extend(["", "Warnings:"])
        lines.extend(f"- {warning}" for warning in report.warnings)
    return "\n".join(lines)


def codeprobe_analyze(payload_json: str) -> str:
    payload = json.loads(payload_json)
    profile = payload.get("profile") or "default"
    config = merged_metric_config(profile)
    override = payload.get("config_override")
    if override:
        for metric_name, metric_data in override.items():
            config.setdefault(metric_name, {})
            if isinstance(metric_data, dict):
                if "thresholds" in metric_data and isinstance(metric_data["thresholds"], dict):
                    thresholds = config[metric_name].setdefault("thresholds", {})
                    thresholds.update(metric_data["thresholds"])
                for key, value in metric_data.items():
                    if key == "thresholds" and isinstance(value, dict):
                        continue
                    config[metric_name][key] = value
    engine = AnalysisEngine(config)
    language_hint = payload.get("language_hint")
    if language_hint == "auto":
        language_hint = None
    report = engine.analyse(
        payload.get("code", ""),
        payload.get("filename", "fragment.py"),
        language_hint=language_hint,
        profile=profile,
    )
    return json.dumps(
        {
            "report": report_to_dict(report),
            "text": format_report_text(report),
        },
        ensure_ascii=False,
    )

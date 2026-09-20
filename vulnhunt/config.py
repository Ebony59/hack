"""Configuration: language adapters (sink patterns, taint hints, build/test/lint
commands) and per-target definitions. This is what makes the harness general:
adding a target or a language is a data change, not a code change.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional, Union

import yaml


@dataclass
class SinkPattern:
    """A regex that flags a potentially dangerous code location."""
    name: str
    regex: str
    vuln_class: str          # e.g. "command-injection", "sql-injection"
    severity_hint: str       # Critical | High | Medium | Low


@dataclass
class LanguageAdapter:
    name: str
    extensions: List[str]                 # file suffixes, e.g. [".rs"]
    sink_patterns: List[SinkPattern]
    input_sources: List[str]              # regexes marking untrusted-input sources (taint hints)
    build_cmd: Optional[List[str]] = None
    test_cmd: Optional[List[str]] = None
    lint_cmd: Optional[List[str]] = None


# --------------------------------------------------------------------------- #
# Language adapters
# --------------------------------------------------------------------------- #

_RUST = LanguageAdapter(
    name="rust",
    extensions=[".rs"],
    sink_patterns=[
        SinkPattern("command_exec",
                    r"Command::new|process::Command|\.args?\(|\.spawn\(|\.output\(|\.status\(",
                    "command-injection", "High"),
        SinkPattern("sql",
                    r"sqlx::query|query!|query_as|\.execute\(|format!\s*\(\s*\"[^\"]*(SELECT|INSERT|UPDATE|DELETE)",
                    "sql-injection", "High"),
        SinkPattern("crypto_compare",
                    r"verify\(|constant_time|ct_eq|hmac|signature|\bmac\b|digest",
                    "auth-bypass", "High"),
        SinkPattern("path",
                    r"Path::new|PathBuf::from|std::fs::|File::open|File::create|\.join\(",
                    "path-traversal", "Medium"),
        SinkPattern("deserialize",
                    r"serde_json::from_|serde_yaml::from_|bincode::deserialize|from_str::<",
                    "deserialization", "Medium"),
        SinkPattern("unsafe",
                    r"\bunsafe\b|from_utf8_unchecked|::transmute|get_unchecked",
                    "memory-safety", "Medium"),
        SinkPattern("panic_on_input",
                    r"\.unwrap\(\)|\.expect\(|panic!|unreachable!|\[\s*\.\.",
                    "denial-of-service", "Low"),
    ],
    input_sources=[
        r"req|request|payload|body|header|socket|stream|TcpStream|read_to_string",
        r"argv|args\(\)|env::var|from_utf8|conf|config|Deserialize",
    ],
    build_cmd=["cargo", "build", "--offline"],
    test_cmd=["cargo", "test", "--offline"],
    lint_cmd=["cargo", "clippy", "--offline", "--", "-W", "clippy::all"],
)

_JS = LanguageAdapter(
    name="js",
    extensions=[".js", ".jsx", ".mjs", ".cjs"],
    sink_patterns=[
        SinkPattern("command_exec",
                    r"child_process|\bexec\(|execSync|\bspawn\(|\.exec\(",
                    "command-injection", "High"),
        SinkPattern("code_eval",
                    r"\beval\(|new Function\(|setTimeout\(\s*[\"'`]|setInterval\(\s*[\"'`]",
                    "code-injection", "High"),
        SinkPattern("dom_xss",
                    r"innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write|insertAdjacentHTML",
                    "xss", "High"),
        SinkPattern("message_passing",
                    r"onMessage|\.addListener\(|postMessage|runtime\.sendMessage|addEventListener\(\s*[\"']message",
                    "message-passing", "Medium"),
        SinkPattern("sql",
                    r"\.query\(\s*[`\"'].*(SELECT|INSERT|UPDATE|DELETE)|knex\.raw|sequelize\.query",
                    "sql-injection", "High"),
        SinkPattern("prototype_pollution",
                    r"__proto__|\bprototype\[|Object\.assign\(\s*\{\s*\}",
                    "prototype-pollution", "Medium"),
        SinkPattern("path",
                    r"fs\.(readFile|writeFile|createReadStream|createWriteStream)|path\.join\(|\.\./",
                    "path-traversal", "Medium"),
        SinkPattern("ssrf",
                    r"\bfetch\(|axios\.|http\.request|https\.request|\bgot\(",
                    "ssrf", "Low"),
        SinkPattern("redos",
                    r"new RegExp\(",
                    "regex-dos", "Low"),
    ],
    input_sources=[
        r"req\.|request\.|params|\.query|\.body|message|sender|event\.data",
        r"location|\.url|process\.argv|process\.env|dataTransfer|searchParams",
    ],
    build_cmd=["npm", "run", "build"],
    test_cmd=["npm", "test"],
    lint_cmd=["npx", "--no-install", "eslint", "."],
)

# TypeScript reuses the JS sinks/sources with .ts/.tsx extensions.
_TS = LanguageAdapter(
    name="ts",
    extensions=[".ts", ".tsx"],
    sink_patterns=_JS.sink_patterns,
    input_sources=_JS.input_sources,
    build_cmd=["npm", "run", "build"],
    test_cmd=["npm", "test"],
    lint_cmd=["npx", "--no-install", "eslint", "."],
)

_PY = LanguageAdapter(
    name="python",
    extensions=[".py"],
    sink_patterns=[
        SinkPattern("command_exec",
                    r"os\.system|subprocess\.|popen|\bexec\(|\beval\(",
                    "command-injection", "High"),
        SinkPattern("deserialize",
                    r"pickle\.loads?|yaml\.load\(|marshal\.loads",
                    "deserialization", "High"),
        SinkPattern("sql",
                    r"execute\(\s*[f\"'].*(SELECT|INSERT|UPDATE|DELETE)|\.raw\(",
                    "sql-injection", "High"),
        SinkPattern("path",
                    r"open\(|os\.path\.join|shutil\.|\.\./",
                    "path-traversal", "Medium"),
        SinkPattern("ssrf",
                    r"requests\.(get|post)|urllib|httpx\.",
                    "ssrf", "Low"),
    ],
    input_sources=[r"request|params|args|form|json|sys\.argv|os\.environ|input\("],
    build_cmd=None,
    test_cmd=["pytest", "-q"],
    lint_cmd=["ruff", "check", "."],
)

ADAPTERS = {a.name: a for a in (_RUST, _JS, _TS, _PY)}

# Directories never worth scanning.
EXCLUDE_DIRS = {
    ".git", "target", "node_modules", "dist", "build", ".venv", "venv",
    "__pycache__", "vendor", ".next", "coverage", "assets", "docs",
}


def get_adapter(language: str) -> LanguageAdapter:
    if language not in ADAPTERS:
        raise KeyError(f"Unknown language adapter: {language!r}. Known: {list(ADAPTERS)}")
    return ADAPTERS[language]


# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #

@dataclass
class Target:
    name: str
    path: str                       # folder name under repos_root, OR an absolute path
    languages: List[str]            # one or more adapter names
    notes: str = ""

    def adapters(self) -> List[LanguageAdapter]:
        return [get_adapter(l) for l in self.languages]


@dataclass
class Config:
    repos_root: str                 # where the (external) target repos live
    targets: List[Target] = field(default_factory=list)

    def target(self, name: str) -> Target:
        for t in self.targets:
            if t.name == name:
                return t
        raise KeyError(f"No target named {name!r}. Known: {[t.name for t in self.targets]}")

    def abs_path(self, t: Target) -> str:
        # An absolute per-target path wins; otherwise join under repos_root.
        if os.path.isabs(t.path):
            return t.path
        return os.path.abspath(os.path.join(self.repos_root, t.path))


# Project root = the folder that holds config.local.yaml (parent of the package).
def _project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _read_local_repos_root() -> Optional[str]:
    """Read repos_root from a gitignored config.local.yaml at the project root."""
    local = os.path.join(_project_root(), "config.local.yaml")
    if os.path.isfile(local):
        try:
            with open(local) as fh:
                data = yaml.safe_load(fh) or {}
            return data.get("repos_root")
        except (OSError, yaml.YAMLError):
            return None
    return None


def resolve_repos_root(cli_value: Optional[str] = None) -> str:
    """Where the target repos live, resolved by precedence:
    --repos-root  >  $VULNHUNT_REPOS_ROOT  >  config.local.yaml  >  error.
    A relative value is resolved against the project root.
    """
    root = (cli_value
            or os.environ.get("VULNHUNT_REPOS_ROOT")
            or _read_local_repos_root())
    if not root:
        raise SystemExit(
            "repos_root is not set. Do one of:\n"
            "  * copy config.example.yaml to config.local.yaml and set repos_root, or\n"
            "  * pass --repos-root /path/to/repos, or\n"
            "  * export VULNHUNT_REPOS_ROOT=/path/to/repos\n"
            "It should point at the folder that CONTAINS the target repos "
            "(snare, pizauth, ...), which lives outside this git repo.")
    if not os.path.isabs(root):
        root = os.path.abspath(os.path.join(_project_root(), root))
    return root


def load_config(targets_file: str, repos_root: Optional[str] = None) -> Config:
    with open(targets_file) as fh:
        raw = yaml.safe_load(fh)
    root = resolve_repos_root(repos_root)
    targets = []
    for item in raw.get("targets", []):
        langs: Union[str, List[str]] = item.get("languages") or item.get("language")
        if isinstance(langs, str):
            langs = [langs]
        targets.append(Target(
            name=item["name"],
            path=item["path"],
            languages=list(langs),
            notes=item.get("notes", ""),
        ))
    return Config(repos_root=root, targets=targets)

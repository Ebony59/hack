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
    path: str                       # ABSOLUTE path to the repo (resolved at load time)
    languages: List[str]            # one or more adapter names
    notes: str = ""

    def adapters(self) -> List[LanguageAdapter]:
        return [get_adapter(l) for l in self.languages]


@dataclass
class Config:
    targets: List[Target] = field(default_factory=list)

    def target(self, name: str) -> Target:
        key = name.lower()
        for t in self.targets:
            if t.name.lower() == key or os.path.basename(t.path).lower() == key:
                return t
        raise KeyError(f"No target named {name!r}. Known: {[t.name for t in self.targets]}")

    def abs_path(self, t: Target) -> str:
        return t.path               # already absolute


# Project root = the folder that holds config.local.yaml (parent of the package).
def _project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _read_local_config() -> dict:
    """Read the gitignored config.local.yaml at the project root."""
    local = os.path.join(_project_root(), "config.local.yaml")
    if os.path.isfile(local):
        try:
            with open(local) as fh:
                return yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError):
            return {}
    return {}


def _abspath(p: str) -> str:
    """Expand ~ and resolve a relative path against the project root."""
    p = os.path.expanduser(p)
    if not os.path.isabs(p):
        p = os.path.join(_project_root(), p)
    return os.path.abspath(p)


def detect_languages(repo_path: str, max_files: int = 6000) -> List[str]:
    """Infer which language adapters apply by scanning file extensions."""
    ext_to_lang = {e: a.name for a in ADAPTERS.values() for e in a.extensions}
    counts: dict = {}
    seen = 0
    for dp, dns, fns in os.walk(repo_path):
        dns[:] = [d for d in dns if d not in EXCLUDE_DIRS and not d.startswith(".")]
        for fn in fns:
            lang = ext_to_lang.get(os.path.splitext(fn)[1])
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
            seen += 1
            if seen >= max_files:
                break
        if seen >= max_files:
            break
    return [lang for lang, _ in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)]


def _load_profiles(targets_file: str) -> dict:
    """targets.yaml as a metadata overlay: name(lower) -> {languages, notes, path}."""
    profiles = {}
    if not os.path.isfile(targets_file):
        return profiles
    with open(targets_file) as fh:
        raw = yaml.safe_load(fh) or {}
    for item in raw.get("targets", []):
        langs = item.get("languages") or item.get("language")
        if isinstance(langs, str):
            langs = [langs]
        profiles[item["name"].lower()] = {
            "languages": list(langs) if langs else [],
            "notes": item.get("notes", ""),
            "path": item.get("path", item["name"]),
        }
    return profiles


def _target_from_repo_entry(entry, profiles: dict) -> Target:
    """Build a Target from one `repos:` entry (a path string or a mapping)."""
    if isinstance(entry, str):
        path, given_name, given_langs, given_notes = entry, None, None, None
    else:
        path = entry["path"]
        given_name = entry.get("name")
        given_langs = entry.get("languages") or entry.get("language")
        given_notes = entry.get("notes")
    if isinstance(given_langs, str):
        given_langs = [given_langs]

    abspath = _abspath(path)
    name = given_name or os.path.basename(abspath.rstrip("/"))
    prof = profiles.get(name.lower(), {})

    languages = given_langs or prof.get("languages")
    if not languages:
        languages = detect_languages(abspath) if os.path.isdir(abspath) else []
    notes = given_notes if given_notes is not None else prof.get("notes", "")

    if not os.path.isdir(abspath):
        print(f"[config] WARNING: repo path does not exist: {abspath}")
    elif not languages:
        print(f"[config] WARNING: no known source files detected in {abspath}; "
              f"set 'language' for this repo in config.local.yaml")
    return Target(name=name, path=abspath, languages=languages or [], notes=notes)


def load_config(targets_file: str, repos_root: Optional[str] = None) -> Config:
    """Build the target set. Two sources, in precedence order:

      1. An explicit repos_root override (--repos-root / $VULNHUNT_REPOS_ROOT):
         scan every target named in targets.yaml, resolved under that root.
      2. A `repos:` list in config.local.yaml (the default): scan exactly those
         paths; language/notes come from targets.yaml by name, else autodetect.
    """
    profiles = _load_profiles(targets_file)
    root_override = repos_root or os.environ.get("VULNHUNT_REPOS_ROOT")

    if root_override:
        root = _abspath(root_override)
        targets = []
        for low, prof in profiles.items():
            p = os.path.join(root, os.path.basename(prof["path"]))
            targets.append(Target(name=prof["path"], path=os.path.abspath(p),
                                  languages=prof["languages"], notes=prof["notes"]))
        return Config(targets=targets)

    local = _read_local_config()
    repos = local.get("repos")
    if repos:
        return Config(targets=[_target_from_repo_entry(e, profiles) for e in repos])

    # Back-compat: a plain repos_root in config.local.yaml still works.
    if local.get("repos_root"):
        return load_config(targets_file, repos_root=local["repos_root"])

    raise SystemExit(
        "No targets configured. In config.local.yaml, add a `repos:` list of "
        "repo paths (see config.example.yaml), or pass --repos-root /path.")

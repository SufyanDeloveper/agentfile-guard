from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .config import Config
from .models import SEVERITY_RANK, ScanResult, Severity
from .rules import ALL_RULE_METADATA
from .sarif import dumps_sarif
from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentfile-guard",
        description="Lint AI agent instruction files for security and correctness issues.",
    )
    parser.add_argument("paths", nargs="*", help="Files or directories to scan. Defaults to root.")
    parser.add_argument(
        "--root", default=".", help="Repository/project root (default: current directory)."
    )
    parser.add_argument("--config", default=None, help="Path to .agentfile-guard.toml config file.")
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif", "github"],
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument("--output", default=None, help="Write output to file instead of stdout.")
    parser.add_argument(
        "--fail-on",
        choices=["error", "warning", "info", "never"],
        default=None,
        help=(
            "Exit non-zero when findings at or above this severity exist. "
            "Default: config fail_on or error."
        ),
    )
    parser.add_argument(
        "--disable-rule",
        action="append",
        default=[],
        help="Disable a rule ID (can be repeated).",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    parser.add_argument("--list-rules", action="store_true", help="List available rules and exit.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        out = format_rules()
        _write_output(out, args.output)
        return 0

    root = Path(args.root).resolve()
    config_path = Path(args.config).resolve() if args.config else None
    try:
        config = Config.load(root, config_path)
    except Exception as exc:
        print(f"agentfile-guard: config error: {exc}", file=sys.stderr)
        return 2

    for rule_id in args.disable_rule:
        config.disable_rules.add(rule_id)

    fail_on = args.fail_on or config.fail_on
    paths = [Path(p) for p in args.paths]

    result = scan(root, paths, config)
    use_color = _use_color(args)
    rendered = render(result, args.format, use_color=use_color)
    _write_output(rendered, args.output)

    return exit_code(result, fail_on)


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GREEN = "\033[32m"
MAGENTA = "\033[35m"
GRAY = "\033[90m"


def _use_color(args: argparse.Namespace) -> bool:
    if getattr(args, "no_color", False):
        return False
    if os.environ.get("NO_COLOR"):
        return False
    fmt = getattr(args, "format", "text")
    if fmt != "text":
        return False
    out = getattr(args, "output", None)
    if out:
        return False
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def _c(text: str, *styles: str, use_color: bool) -> str:
    if not use_color or not styles:
        return text
    return "".join(styles) + text + RESET


def render(result: ScanResult, fmt: str, use_color: bool = False) -> str:
    if fmt == "json":
        return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"
    if fmt == "sarif":
        return dumps_sarif(result)
    if fmt == "github":
        return render_github(result)
    return render_text(result, use_color=use_color)


def _unicode_ok() -> bool:
    enc = (sys.stdout.encoding or "utf-8").lower()
    return "utf" in enc


def render_text(result: ScanResult, use_color: bool = False) -> str:
    lines: list[str] = []
    fancy = _unicode_ok()
    sev_style = {
        "error": (RED, BOLD),
        "warning": (YELLOW, BOLD),
        "info": (CYAN, BOLD),
    }
    sev_icon = (
        {"error": "\u2716", "warning": "\u25b2", "info": "\u25cf"}
        if fancy
        else {"error": "X", "warning": "!", "info": "i"}
    )
    hr = "\u2500" * 72 if fancy else "-" * 72
    bar = "\u2502" if fancy else "|"
    ok_mark = "\u2714" if fancy else "OK"

    header = _c("agentfile-guard", BOLD, MAGENTA, use_color=use_color)
    subtitle = _c("agent instruction security & correctness lint", DIM, use_color=use_color)
    lines.append(f"{header}  {subtitle}")
    lines.append(_c(hr, GRAY, use_color=use_color))

    if not result.findings:
        lines.append(
            _c(
                f"{ok_mark} No findings. Agent instruction files look clean.",
                GREEN,
                BOLD,
                use_color=use_color,
            )
        )
    else:
        for f in result.findings:
            rel = _rel(f.path, result.root)
            sev = f.severity.value
            icon = sev_icon.get(sev, "i")
            styles = sev_style.get(sev, (CYAN, BOLD))
            sev_label = _c(f"{icon} {sev.upper():7}", *styles, use_color=use_color)
            rule = _c(f.rule.id, BOLD, use_color=use_color)
            location = _c(f"{rel}:{f.line}:{f.column}", CYAN, use_color=use_color)
            lines.append(f"{sev_label} {rule}  {location}")
            lines.append(f"  {f.message}")
            if f.snippet:
                snippet = f.snippet.replace("\t", "    ")
                lines.append(_c(f"  {bar} {snippet}", GRAY, use_color=use_color))
            lines.append("")

    err = _c(str(result.errors), RED, BOLD, use_color=use_color)
    warn = _c(str(result.warnings), YELLOW, BOLD, use_color=use_color)
    info = _c(str(result.infos), CYAN, BOLD, use_color=use_color)
    files = _c(str(len(result.files_scanned)), BOLD, use_color=use_color)
    total = _c(str(len(result.findings)), BOLD, use_color=use_color)
    lines.append(_c(hr, GRAY, use_color=use_color))
    lines.append(
        f"Files scanned: {files}  Findings: {total}  "
        f"Errors: {err}  Warnings: {warn}  Info: {info}"
    )
    if result.errors:
        status = _c("FAIL", RED, BOLD, use_color=use_color)
    elif result.warnings or result.infos:
        status = _c("PASS WITH WARNINGS", YELLOW, BOLD, use_color=use_color)
    else:
        status = _c("PASS", GREEN, BOLD, use_color=use_color)
    lines.append(f"Status: {status}")
    return "\n".join(lines).rstrip() + "\n\n\n"
def render_github(result: ScanResult) -> str:
    # GitHub Actions workflow commands.
    # https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions
    lines: list[str] = []
    level_map = {"error": "error", "warning": "warning", "info": "notice"}
    for f in result.findings:
        rel = _rel(f.path, result.root)
        level = level_map.get(f.severity.value, "notice")
        msg = _escape_github(f"{f.rule.id} {f.message}")
        file = _escape_github_prop(rel)
        lines.append(f"::{level} file={file},line={f.line},col={f.column},title={f.rule.id}::{msg}")
    lines.append(render_text(result).rstrip("\n"))
    return "\n".join(lines) + "\n"


def format_rules() -> str:
    lines = []
    for rule in ALL_RULE_METADATA:
        lines.append(f"{rule.id}\t{rule.severity.value}\t{rule.name}\t{rule.description}")
    return "\n".join(lines) + "\n"


def exit_code(result: ScanResult, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    threshold = {
        "error": SEVERITY_RANK[Severity.ERROR],
        "warning": SEVERITY_RANK[Severity.WARNING],
        "info": SEVERITY_RANK[Severity.INFO],
    }[fail_on]
    for f in result.findings:
        if SEVERITY_RANK[f.severity] >= threshold:
            return 1
    return 0


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return path.as_posix()


def _write_output(text: str, output: str | None) -> None:
    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
    else:
        try:
            sys.stdout.write(text)
        except UnicodeEncodeError:
            encoding = sys.stdout.encoding or "utf-8"
            sys.stdout.buffer.write(text.encode(encoding, errors="replace"))


def _escape_github(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_github_prop(value: str) -> str:
    return _escape_github(value).replace(":", "%3A").replace(",", "%2C")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

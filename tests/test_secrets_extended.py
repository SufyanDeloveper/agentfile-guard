from __future__ import annotations

from pathlib import Path

from agentfile_guard.config import Config
from agentfile_guard.scanner import scan_file


def _scan_text(tmp_path: Path, name: str, content: str, config: Config | None = None):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return scan_file(p, tmp_path, config or Config())


def test_detects_github_tokens(tmp_path: Path):
    # Fake tokens with correct prefixes/formats, not real.
    cases = [
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",  # 36 chars
        "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    ]
    for token in cases:
        findings = _scan_text(tmp_path, "AGENTS.md", f"token={token}\n")
        assert any(f.rule.id == "AFG001" for f in findings), token
        assert all(token not in f.snippet for f in findings if f.rule.id == "AFG001")


def test_detects_gitlab_npm_pypi_tokens(tmp_path: Path):
    cases = [
        "glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
        "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
        "pypi-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdEFGH",
    ]
    for token in cases:
        findings = _scan_text(tmp_path, "AGENTS.md", f"{token}\n")
        assert any(f.rule.id == "AFG001" for f in findings), token


def test_detects_stripe_and_sendgrid(tmp_path: Path):
    stripe = "sk_live_" + "A1b2C3d4E5f6G7h8I9j0"
    sendgrid = "SG." + "ABCDEFGHIJKLMNopqrstuv." + "ABCDEFGHIJKLMNopqrstuvwx123456"
    for token in [stripe, sendgrid]:
        findings = _scan_text(tmp_path, "AGENTS.md", f"{token}\n")
        assert any(f.rule.id == "AFG001" for f in findings), token


def test_detects_anthropic_key(tmp_path: Path):
    token = "sk-ant-api03-" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N4"
    findings = _scan_text(tmp_path, "AGENTS.md", f"{token}\n")
    assert any(f.rule.id == "AFG001" for f in findings)


def test_detects_connection_string_password(tmp_path: Path):
    findings = _scan_text(
        tmp_path,
        "AGENTS.md",
        "DB=postgres://appuser:Sup3rS3cretP@ss@db.example.com:5432/app\n",
    )
    afg1 = [f for f in findings if f.rule.id == "AFG001"]
    assert afg1
    assert any(
        "connection string" in f.message.lower() or "credential" in f.message.lower() for f in afg1
    )
    assert all("Sup3rS3cretP@ss" not in f.snippet for f in afg1)


def test_detects_generic_secret_assignment(tmp_path: Path):
    findings = _scan_text(
        tmp_path,
        "AGENTS.md",
        'api_key = "A9fK3mP2qR7sT1vW5xY8zB4cD6eH0jL2"\n',
    )
    assert any(f.rule.id == "AFG001" for f in findings)


def test_ignores_generic_placeholder_assignment(tmp_path: Path):
    findings = _scan_text(
        tmp_path,
        "AGENTS.md",
        'api_key = "<YOUR_API_KEY>"\npassword = "changeme"\n',
    )
    # Generic detector should not flag obvious placeholders.
    generic = [f for f in findings if f.rule.id == "AFG001" and "assigned to" in f.message]
    assert not generic


def test_ignores_env_var_reference(tmp_path: Path):
    findings = _scan_text(
        tmp_path,
        "AGENTS.md",
        'api_key = "${OPENAI_API_KEY}"\ntoken = "$MY_TOKEN"\n',
    )
    generic = [f for f in findings if f.rule.id == "AFG001" and "assigned to" in f.message]
    assert not generic


def test_detects_bearer_token(tmp_path: Path):
    token = "Bearer " + "A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6"
    findings = _scan_text(tmp_path, "AGENTS.md", f"Authorization: {token}\n")
    assert any(f.rule.id == "AFG001" for f in findings)
    assert all(
        "A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6" not in f.snippet
        for f in findings
        if f.rule.id == "AFG001"
    )


def test_detects_https_basic_auth(tmp_path: Path):
    findings = _scan_text(
        tmp_path,
        "AGENTS.md",
        "clone https://user:Sup3rS3cretTok3n@git.example.com/repo.git\n",
    )
    assert any(f.rule.id == "AFG001" for f in findings)

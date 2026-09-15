"""Regression tests for #109902: repeated dotenv reloads must be idempotent."""
from __future__ import annotations

from pathlib import Path

from hermes_cli import env_loader


def test_reloading_self_referential_path_does_not_accumulate_prefix(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("PATH=/opt/hermes/bin:${PATH}\n", encoding="utf-8")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")

    env_loader._load_dotenv_with_fallback(env_file, override=True)
    first = env_loader.os.environ["PATH"]
    env_loader._load_dotenv_with_fallback(env_file, override=True)

    assert first == "/opt/hermes/bin:/usr/bin:/bin"
    assert env_loader.os.environ["PATH"] == first

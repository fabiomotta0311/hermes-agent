"""Only canonical once/session/always strings count as consent at the final gate.

Gateway/TUI resolver answers and direct embedding callbacks need this fail-closed
boundary. Host-owned approval transports already validate allowed choices and request
binding, so this is defense in depth for transport plugins, not their first validator.
Cosmetic spelling is normalized here; WhatsApp's legacy Approve button is translated
at its own ingress. Commands below are detector input only, never executed.
"""

from __future__ import annotations

import pytest

import tools.approval as approval_module
from tools import approval_context
from tools.approval import CONSENT_ANSWERS, check_all_command_guards
from tools.terminal_tool import set_approval_callback


DANGEROUS = "rm -rf /tmp/approval-allowlist-testdir"

# Values an unvalidated resolver or embedding callback could send that are NOT consent.
NOT_CONSENT = [
    "yes",
    "ok",
    "true",
    "accept",
    "",             # empty payload
    "null",
    "1",
    "denied",       # near-miss on the refusal word
]

# Cosmetic normalization does not introduce new semantic consent words.
ALIASES_TO_CANONICAL = {
    "ONCE": "once",
    "once ": "once",
    "  Session  ": "session",
    "ALWAYS": "always",
}


@pytest.fixture(autouse=True)
def _clean_approval_env(monkeypatch):
    """Neutral approval environment: no yolo, manual mode, tirith quiet, no leftover grants."""
    for key in ("HERMES_EXEC_ASK", "HERMES_GATEWAY_SESSION", "HERMES_SESSION_PLATFORM",
                "HERMES_CRON_SESSION", "HERMES_YOLO_MODE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", False)
    monkeypatch.setattr(approval_context, "_get_approval_mode", lambda: "manual")
    monkeypatch.setattr(
        "tools.tirith_security.check_command_security",
        lambda _command: {"action": "allow", "findings": [], "summary": ""},
    )
    approval_module._session_approved.clear()
    approval_module._permanent_approved.clear()
    approval_module._pending.clear()
    approval_module._denial_tally.clear()
    set_approval_callback(None)
    yield
    approval_module._session_approved.clear()
    approval_module._permanent_approved.clear()
    approval_module._pending.clear()
    approval_module._denial_tally.clear()
    set_approval_callback(None)


def _drive_gateway(monkeypatch, answer):
    """Run the command gate through the gateway branch with ``answer`` as the user's reply."""
    monkeypatch.setenv("HERMES_EXEC_ASK", "1")
    monkeypatch.setattr(approval_module, "_gateway_notify_cb", lambda _sk: (lambda *a, **k: True))
    monkeypatch.setattr(
        approval_module, "_await_gateway_decision",
        lambda *a, **k: {"resolved": True, "choice": answer, "reason": None},
    )
    return check_all_command_guards(DANGEROUS, "local")


@pytest.mark.parametrize("answer", [[], {}, ["once"], {"choice": "once"}, 1, True, b"once"])
@pytest.mark.parametrize("surface", ["gateway", "callback"])
def test_non_string_answers_fail_closed(monkeypatch, answer, surface):
    if surface == "gateway":
        result = _drive_gateway(monkeypatch, answer)
    else:
        set_approval_callback(lambda *a, **k: answer)
        result = check_all_command_guards(DANGEROUS, "local")
    assert result["approved"] is False
    assert result["outcome"] == "unrecognized_answer"
    assert result["user_consent"] is False
    assert not any(approval_module._session_approved.values())
    assert not approval_module._permanent_approved


@pytest.mark.parametrize("surface", ["gateway", "callback"])
def test_rejected_payload_is_not_logged(monkeypatch, caplog, surface):
    secret = "sk-test-invalid-approval-secret-sentinel"
    if surface == "gateway":
        result = _drive_gateway(monkeypatch, secret)
    else:
        set_approval_callback(lambda *a, **k: secret)
        result = check_all_command_guards(DANGEROUS, "local")
    assert result["approved"] is False
    assert result["outcome"] == "unrecognized_answer"
    assert "unrecognized approval answer" in caplog.text
    assert secret not in caplog.text
    assert all(secret not in repr(record.args) for record in caplog.records)


def test_whatsapp_tap_round_trip_is_one_shot(monkeypatch, tmp_path):
    """Real adapter -> resolver -> waiting guard; only network delivery is replaced."""
    import asyncio
    from unittest.mock import AsyncMock
    from gateway.config import PlatformConfig
    from gateway.platforms.whatsapp_cloud import WhatsAppCloudAdapter

    session = "consent-integration"
    monkeypatch.setenv("HERMES_EXEC_ASK", "1")
    monkeypatch.setenv("HERMES_SESSION_KEY", session)
    adapter = WhatsAppCloudAdapter(PlatformConfig(extra={"dm_policy": "allowlist", "allow_from": ["15551234567"]}))
    adapter._reply_best_effort = AsyncMock()
    decisions = iter(["approve", "deny"])
    prompts = []

    def notify(data):
        prompts.append(data)
        adapter._exec_approval_state["integration"] = session
        choice = next(decisions)
        raw = {"from": "15551234567", "type": "interactive", "interactive": {
            "type": "button_reply", "button_reply": {"id": f"appr:integration:{choice}", "title": choice}
        }}
        assert asyncio.run(adapter._dispatch_interactive_reply(raw, {})) is True
        return True

    approval_module.register_gateway_notify(session, notify)
    try:
        result = check_all_command_guards(DANGEROUS, "local")
        assert result["approved"] is True
        assert not any(approval_module._session_approved.values())
        assert not approval_module._permanent_approved
        assert not (tmp_path / "hermes_test" / "config.yaml").exists()
        second = check_all_command_guards(DANGEROUS, "local")
        assert second["approved"] is False
        assert second["outcome"] == "denied"
        assert len(prompts) == 2
        assert adapter._reply_best_effort.await_count == 2
        assert not approval_module.has_blocking_approval(session)
    finally:
        approval_module.unregister_gateway_notify(session)


class TestGatewayAnswersMustBeConsentWords:
    @pytest.mark.parametrize("answer", NOT_CONSENT)
    def test_unrecognized_gateway_answer_is_refused(self, monkeypatch, answer):
        result = _drive_gateway(monkeypatch, answer)

        assert result.get("approved") is False, f"{answer!r} was treated as consent"
        assert result.get("outcome") == "unrecognized_answer"
        assert result.get("user_consent") is False
        assert "not a recognized decision" in (result.get("message") or "")

    @pytest.mark.parametrize("answer", sorted(CONSENT_ANSWERS))
    def test_the_three_consent_words_still_approve(self, monkeypatch, answer):
        result = _drive_gateway(monkeypatch, answer)

        assert result.get("approved") is True, f"{answer!r} should still approve"
        assert result.get("user_approved") is True

    def test_deny_still_reports_denied_not_unrecognized(self, monkeypatch):
        """"deny" has its own branch ahead of grant(); it keeps its own outcome label."""
        result = _drive_gateway(monkeypatch, "deny")

        assert result.get("approved") is False
        assert result.get("outcome") == "denied"

    def test_unrecognized_answer_grants_nothing_for_later_calls(self, monkeypatch):
        """A refused answer must not leave a grant behind that approves the next call."""
        _drive_gateway(monkeypatch, "always")  # the word that WOULD persist, spelled correctly
        approval_module._session_approved.clear()
        approval_module._permanent_approved.clear()

        _drive_gateway(monkeypatch, "yes")
        assert not approval_module._session_approved, "an unrecognized answer left a session grant"
        assert not approval_module._permanent_approved, "an unrecognized answer left a permanent grant"


class TestAliasesNormalizeRatherThanWidenTheAllowList:
    """Normalization happens before the allow-list, so the allow-list itself stays exact."""

    @pytest.mark.parametrize("sent,canonical", sorted(ALIASES_TO_CANONICAL.items()))
    def test_alias_is_accepted(self, monkeypatch, sent, canonical):
        result = _drive_gateway(monkeypatch, sent)

        assert result.get("approved") is True, f"{sent!r} should normalize to {canonical!r}"
        assert result.get("user_approved") is True

    @pytest.mark.parametrize("answer", ["approve", "Approve", "approved", "allow"])
    @pytest.mark.parametrize("surface", ["gateway", "callback"])
    def test_semantic_aliases_are_not_global_consent(self, monkeypatch, answer, surface):
        if surface == "gateway":
            result = _drive_gateway(monkeypatch, answer)
        else:
            set_approval_callback(lambda *a, **k: answer)
            result = check_all_command_guards(DANGEROUS, "local")
        assert result["approved"] is False
        assert result["outcome"] == "unrecognized_answer"
        assert not any(approval_module._session_approved.values())
        assert not approval_module._permanent_approved

    def test_session_spelling_variant_still_persists(self, monkeypatch):
        """A real 'session' answer must still persist despite rejecting semantic aliases."""
        _drive_gateway(monkeypatch, "  Session  ")

        assert any(approval_module._session_approved.values()), \
            "a normalized 'session' answer did not persist a session grant"


class TestCliCallbackAnswersMustBeConsentWords:
    """The interactive prompt normalizes keystrokes, but the callback seam it sits behind does
    not — an embedding client or plugin supplies that function directly."""

    def test_unrecognized_callback_answer_is_refused(self, monkeypatch):
        set_approval_callback(lambda command, description, **kwargs: "yes")

        result = check_all_command_guards(DANGEROUS, "local")

        assert result.get("approved") is False
        assert result.get("outcome") == "unrecognized_answer"

    def test_none_from_callback_is_refused(self, monkeypatch):
        """``None`` reaches grant() unguarded on the CLI path; it used to read as a yes."""
        set_approval_callback(lambda command, description, **kwargs: None)

        result = check_all_command_guards(DANGEROUS, "local")

        assert result.get("approved") is False
        assert result.get("outcome") == "unrecognized_answer"

    def test_once_from_callback_still_approves(self, monkeypatch):
        set_approval_callback(lambda command, description, **kwargs: "once")

        result = check_all_command_guards(DANGEROUS, "local")

        assert result.get("approved") is True

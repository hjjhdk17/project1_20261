"""Phase 8: Telegram notify sau khi convert đã ghi file."""

from __future__ import annotations

import io
import json
import logging
import urllib.error
import urllib.parse
from pathlib import Path

import pytest

from sigma2wazuh.cli import main
from sigma2wazuh.telegram_notifier import CHAT_ENV, TOKEN_ENV, notify_summary

ROOT = Path(__file__).resolve().parents[1]
FIELD_MAPPING = ROOT / "config" / "field_mapping.yaml"
GOOD = ROOT / "tests" / "fixtures" / "phase3" / "eligible_endswith.yml"
BAD_YAML = ROOT / "tests" / "fixtures" / "phase2" / "bad_yaml.yml"
CHAT_ID = "-1004242424242"


def _fake_token() -> str:
    digits = "123456789"
    tail = "A" * 35
    return digits + ":" + tail


class _Body:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> _Body:
        return self

    def __exit__(self, *args: object) -> bool:
        return False


def _report() -> dict:
    return {
        "tool_version": "0.8.0",
        "elapsed_ms": 12,
        "summary": {
            "total": 1,
            "success": 1,
            "unsupported": 0,
            "failed": 0,
            "skipped": 0,
        },
        "records": [{"Image": r"\cmd.exe", "note": "IGNORE_ME_COMMANDLINE"}],
    }


def _set_env(monkeypatch: pytest.MonkeyPatch, *, token: str | None, chat: str | None) -> None:
    if token is None:
        monkeypatch.delenv(TOKEN_ENV, raising=False)
    else:
        monkeypatch.setenv(TOKEN_ENV, token)
    if chat is None:
        monkeypatch.delenv(CHAT_ENV, raising=False)
    else:
        monkeypatch.setenv(CHAT_ENV, chat)


def _patch_urlopen(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    monkeypatch.setattr(
        "sigma2wazuh.telegram_notifier.urllib.request.urlopen",
        handler,
    )


def _assert_secret_hidden(text: str, token: str, chat: str | None = None) -> None:
    assert token not in text
    if chat is not None:
        assert chat not in text


def test_success_posts_plain_summary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    token = _fake_token()
    seen: dict = {}

    def handler(request, timeout=None):
        seen["url"] = request.full_url
        seen["data"] = request.data
        seen["timeout"] = timeout
        return _Body(b'{"ok": true, "result": {}}')

    _set_env(monkeypatch, token=token, chat=CHAT_ID)
    _patch_urlopen(monkeypatch, handler)
    notify_summary(_report(), ok=True, xml_path=Path("/tmp/rules.xml"), report_path=Path("/tmp/report.json"))
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""

    assert seen["timeout"] == 10
    assert token in seen["url"]
    parsed = urllib.parse.parse_qs(seen["data"].decode("utf-8"))
    assert list(parsed) == ["chat_id", "text"]
    assert "parse_mode" not in parsed
    text = parsed["text"][0]
    assert text.startswith("✅ sigma2wazuh convert OK\n")
    assert "Tool 0.8.0 · 12 ms" in text
    assert "1 rule\n" in text
    assert "✅ success 1" in text
    assert "⚪ unsupported 0" in text
    assert "❌ failed 0" in text
    assert "⏭ skipped 0" in text
    assert "xml rules.xml" in text
    assert "report report.json" in text
    assert "IGNORE_ME_COMMANDLINE" not in text
    assert "cmd.exe" not in text
    assert "/tmp/" not in text


def test_http_200_ok_false_warns_without_body(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    token = _fake_token()
    caplog.set_level(logging.DEBUG)
    body = json.dumps({"ok": False, "description": f"{token} chat {CHAT_ID}"}).encode()

    def handler(request, timeout=None):
        return _Body(body)

    _set_env(monkeypatch, token=token, chat=CHAT_ID)
    _patch_urlopen(monkeypatch, handler)
    notify_summary(_report(), ok=True, xml_path=Path("rules.xml"), report_path=Path("report.json"))
    captured = capsys.readouterr()
    assert captured.err.strip() == "Telegram notify failed: ok false"
    assert captured.out == ""
    _assert_secret_hidden(captured.err + captured.out + caplog.text, token, CHAT_ID)


def test_http_401_hides_token_and_chat(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    token = _fake_token()
    caplog.set_level(logging.DEBUG)

    def handler(request, timeout=None):
        raise urllib.error.HTTPError(
            url=request.full_url,
            code=401,
            msg=f"Unauthorized {token} {CHAT_ID}",
            hdrs=None,
            fp=io.BytesIO(b'{"ok": false}'),
        )

    _set_env(monkeypatch, token=token, chat=CHAT_ID)
    _patch_urlopen(monkeypatch, handler)
    notify_summary(_report(), ok=True, xml_path=Path("rules.xml"), report_path=Path("report.json"))
    captured = capsys.readouterr()
    assert captured.err.strip() == "Telegram notify failed: HTTPError 401"
    _assert_secret_hidden(captured.err + captured.out + caplog.text, token, CHAT_ID)


def test_urlerror_and_timeout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    token = _fake_token()
    _set_env(monkeypatch, token=token, chat=CHAT_ID)

    def network(request, timeout=None):
        raise urllib.error.URLError(f"down {token} {CHAT_ID}")

    _patch_urlopen(monkeypatch, network)
    notify_summary(_report(), ok=True, xml_path=Path("a.xml"), report_path=Path("a.json"))
    first = capsys.readouterr()
    assert first.err.strip() == "Telegram notify failed: URLError"
    _assert_secret_hidden(first.err + first.out, token, CHAT_ID)

    def timed_out(request, timeout=None):
        raise urllib.error.URLError(TimeoutError(f"timed out {token}"))

    _patch_urlopen(monkeypatch, timed_out)
    notify_summary(_report(), ok=True, xml_path=Path("a.xml"), report_path=Path("a.json"))
    second = capsys.readouterr()
    assert second.err.strip() == "Telegram notify failed: TimeoutError"
    _assert_secret_hidden(second.err + second.out, token, CHAT_ID)

    def bare_timeout(request, timeout=None):
        raise TimeoutError(token)

    _patch_urlopen(monkeypatch, bare_timeout)
    notify_summary(_report(), ok=True, xml_path=Path("a.xml"), report_path=Path("a.json"))
    third = capsys.readouterr()
    assert third.err.strip() == "Telegram notify failed: TimeoutError"
    _assert_secret_hidden(third.err + third.out, token, CHAT_ID)


def test_missing_env_names_variable_not_value(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    token = _fake_token()
    calls = {"n": 0}

    def handler(request, timeout=None):
        calls["n"] += 1
        raise AssertionError("network")

    _patch_urlopen(monkeypatch, handler)
    _set_env(monkeypatch, token=None, chat=CHAT_ID)
    notify_summary(_report(), ok=True, xml_path=Path("a.xml"), report_path=Path("a.json"))
    missing_token = capsys.readouterr()
    assert missing_token.err.strip() == "Telegram notify failed: missing TELEGRAM_BOT_TOKEN"
    assert calls["n"] == 0

    _set_env(monkeypatch, token=token, chat=None)
    notify_summary(_report(), ok=True, xml_path=Path("a.xml"), report_path=Path("a.json"))
    missing_chat = capsys.readouterr()
    assert missing_chat.err.strip() == "Telegram notify failed: missing TELEGRAM_CHAT_ID"
    _assert_secret_hidden(missing_chat.err + missing_chat.out, token)
    assert calls["n"] == 0

    _set_env(monkeypatch, token="   ", chat="  ")
    notify_summary(_report(), ok=True, xml_path=Path("a.xml"), report_path=Path("a.json"))
    blank = capsys.readouterr()
    assert blank.err.strip() == (
        "Telegram notify failed: missing TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID"
    )
    assert calls["n"] == 0


def _convert_args(tmp_path: Path, source: Path, *, notify: bool, force: bool = False) -> list[str]:
    args = [
        "convert",
        "--field-mapping",
        str(FIELD_MAPPING),
        "--input",
        str(source),
        "--output-xml",
        str(tmp_path / "rules.xml"),
        "--output-report",
        str(tmp_path / "report.json"),
    ]
    if notify:
        args.append("--notify")
    if force:
        args.append("--force")
    return args


def test_cli_notify_failure_keeps_exit_and_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    token = _fake_token()
    caplog.set_level(logging.DEBUG)
    _set_env(monkeypatch, token=token, chat=CHAT_ID)

    def handler(request, timeout=None):
        raise urllib.error.HTTPError(
            url=request.full_url,
            code=401,
            msg="Unauthorized",
            hdrs=None,
            fp=io.BytesIO(b""),
        )

    _patch_urlopen(monkeypatch, handler)
    code = main(_convert_args(tmp_path, GOOD, notify=True))
    captured = capsys.readouterr()
    report_path = tmp_path / "report.json"
    assert code == 0
    assert "Convert OK:" in captured.out
    assert "Telegram notify failed: HTTPError 401" in captured.err
    assert report_path.is_file()
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["summary"]["success"] == 1
    assert "telegram" not in data
    _assert_secret_hidden(captured.out + captured.err + caplog.text, token, CHAT_ID)


def test_cli_ok_false_keeps_exit_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    token = _fake_token()
    _set_env(monkeypatch, token=token, chat=CHAT_ID)

    def handler(request, timeout=None):
        body = json.dumps({"ok": False, "description": CHAT_ID}).encode()
        return _Body(body)

    _patch_urlopen(monkeypatch, handler)
    code = main(_convert_args(tmp_path, GOOD, notify=True))
    captured = capsys.readouterr()
    assert code == 0
    assert (tmp_path / "report.json").is_file()
    assert "Telegram notify failed: ok false" in captured.err.splitlines()
    _assert_secret_hidden(captured.out + captured.err, token, CHAT_ID)


def test_cli_failed_batch_stays_exit_3(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    token = _fake_token()
    seen: dict[str, str] = {}
    _set_env(monkeypatch, token=token, chat=CHAT_ID)

    def handler(request, timeout=None):
        seen["text"] = urllib.parse.parse_qs(request.data.decode())["text"][0]
        raise urllib.error.URLError("down")

    _patch_urlopen(monkeypatch, handler)
    code = main(_convert_args(tmp_path, BAD_YAML, notify=True))
    captured = capsys.readouterr()
    assert code == 3
    assert "Convert finished:" in captured.out
    assert "OK" not in captured.out
    assert "Telegram notify failed: URLError" in captured.err
    assert seen["text"].startswith("⚠️ sigma2wazuh convert finished (exit 3)\n")
    assert "convert OK" not in seen["text"]
    assert (tmp_path / "report.json").is_file()
    _assert_secret_hidden(captured.out + captured.err, token, CHAT_ID)


def test_env_without_flag_does_not_call_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}

    def handler(request, timeout=None):
        calls["n"] += 1
        raise AssertionError("urlopen")

    _set_env(monkeypatch, token=_fake_token(), chat=CHAT_ID)
    _patch_urlopen(monkeypatch, handler)
    code = main(_convert_args(tmp_path, GOOD, notify=False))
    assert code == 0
    assert calls["n"] == 0
    assert (tmp_path / "report.json").is_file()


def test_output_refused_does_not_notify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = {"n": 0}
    xml_path = tmp_path / "rules.xml"
    xml_path.write_text("keep", encoding="utf-8")

    def handler(request, timeout=None):
        calls["n"] += 1
        raise AssertionError("urlopen")

    _set_env(monkeypatch, token=_fake_token(), chat=CHAT_ID)
    _patch_urlopen(monkeypatch, handler)
    code = main(_convert_args(tmp_path, GOOD, notify=True))
    captured = capsys.readouterr()
    assert code == 1
    assert calls["n"] == 0
    assert xml_path.read_text(encoding="utf-8") == "keep"
    assert "Telegram" not in captured.err
    assert not (tmp_path / "report.json").exists()


def test_notify_flag_only_on_convert(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as convert_help:
        main(["convert", "--help"])
    assert convert_help.value.code == 0
    assert "--notify" in capsys.readouterr().out

    for command in ("parse", "analyze", "map"):
        with pytest.raises(SystemExit) as help_exit:
            main([command, "--help"])
        assert help_exit.value.code == 0
        assert "--notify" not in capsys.readouterr().out
        with pytest.raises(SystemExit) as usage:
            main([command, "--input", "x.yml", "--notify"])
        assert usage.value.code == 2


def test_mapper_and_generator_do_not_import_notifier() -> None:
    package = ROOT / "src" / "sigma2wazuh"
    for name in (
        "mapper.py",
        "wazuh_generator.py",
        "parsing.py",
        "support_analyzer.py",
        "evaluator.py",
    ):
        text = (package / name).read_text(encoding="utf-8")
        assert "telegram_notifier" not in text

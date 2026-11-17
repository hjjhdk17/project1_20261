"""Gửi summary của convert qua Telegram Bot API.

Token và chat ID chỉ đọc từ biến môi trường lúc gọi. Module này không đọc file
``.env`` và không ghi lại JSON.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

TIMEOUT_SECONDS = 10
TOKEN_ENV = "TELEGRAM_BOT_TOKEN"
CHAT_ENV = "TELEGRAM_CHAT_ID"


def notify_summary(
    report: dict[str, Any],
    *,
    xml_path: Path,
    report_path: Path,
    ok: bool,
) -> None:
    """Gửi một tin text sau khi file đã ghi.

    Mọi lỗi (thiếu biến, HTTP, mạng, body ``ok`` khác true) in một dòng stderr
    và return. Không raise ``Exception``.
    """
    token = ""
    try:
        token = _env_value(TOKEN_ENV)
        chat_id = _env_value(CHAT_ENV)
        missing = [
            name
            for name, value in ((TOKEN_ENV, token), (CHAT_ENV, chat_id))
            if not value
        ]
        if missing:
            _warn("missing " + ", ".join(missing), token=token)
            return

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode(
            {
                "chat_id": chat_id,
                "text": _message(
                    report, xml_path=xml_path, report_path=report_path, ok=ok
                ),
            }
        ).encode("utf-8")
        request = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read()
        _require_ok(raw, token=token)
    except urllib.error.HTTPError as exc:
        _warn(f"HTTPError {exc.code}", token=token)
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            _warn("TimeoutError", token=token)
        else:
            _warn("URLError", token=token)
    except TimeoutError:
        _warn("TimeoutError", token=token)
    except Exception:
        _warn("Error", token=token)


def _env_value(name: str) -> str:
    raw = os.environ.get(name)
    if not isinstance(raw, str):
        return ""
    return raw.strip()


def _message(
    report: dict[str, Any],
    *,
    xml_path: Path,
    report_path: Path,
    ok: bool,
) -> str:
    """Text thuần, không parse_mode. Dòng đầu nói ngay lệnh và kết quả."""
    summary = report["summary"]
    total = summary["total"]
    rule_word = "rule" if total == 1 else "rules"
    if ok:
        headline = "✅ sigma2wazuh convert OK"
    else:
        headline = "⚠️ sigma2wazuh convert finished (exit 3)"
    return "\n".join(
        [
            headline,
            "",
            f"Tool {report['tool_version']} · {report['elapsed_ms']} ms",
            f"{total} {rule_word}",
            "",
            f"✅ success {summary['success']}",
            f"⚪ unsupported {summary['unsupported']}",
            f"❌ failed {summary['failed']}",
            f"⏭ skipped {summary['skipped']}",
            "",
            f"xml {xml_path.name}",
            f"report {report_path.name}",
        ]
    )


def _require_ok(raw: bytes, *, token: str) -> None:
    """HTTP 200 với ``ok`` khác true vẫn là gửi thất bại."""
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _warn("invalid response", token=token)
        return
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        _warn("ok false", token=token)


def _warn(detail: str, *, token: str) -> None:
    """Một dòng stderr. Không in token, chat ID, URL, hay body."""
    print(_redact(f"Telegram notify failed: {detail}", token), file=sys.stderr)


def _redact(text: str, token: str) -> str:
    if not token:
        return text
    hidden = text.replace(token, "***")
    quoted = urllib.parse.quote(token, safe="")
    if quoted and quoted != token:
        hidden = hidden.replace(quoted, "***")
    return hidden

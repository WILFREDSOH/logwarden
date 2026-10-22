"""Dashboard helpers that do not need Streamlit (so they can be unit-tested)."""

from __future__ import annotations

import re

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~$])")


def md_escape(text: object) -> str:
    """Escape Markdown so log-derived text is displayed literally, never as a link or image."""
    return _MD_SPECIAL.sub(r"\\\1", "" if text is None else str(text))

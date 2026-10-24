"""Public demo entry point (Streamlit Community Cloud, GitHub Codespaces).

Builds the synthetic demo database on first start, then shows the dashboard.
"""

import os
from pathlib import Path

import streamlit as st

from logwarden.cli import main as logwarden_cli

DEMO_DB = Path("data/generated/demo.db")


@st.cache_resource(show_spinner="Preparing demo data...")
def build_demo_db() -> str:
    if not DEMO_DB.exists():
        logwarden_cli(["demo", "--out", "reports/demo"])
    return str(DEMO_DB.resolve())


os.environ["LOGWARDEN_DB"] = build_demo_db()

from logwarden.dashboard.app import main  # noqa: E402

main()

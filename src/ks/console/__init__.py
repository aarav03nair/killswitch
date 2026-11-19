"""ks.console: the read-only incident console (ADR-07 §4, B3-28). Owner: ishaan."""
from .html import render_html, write_html
from .live import beat_ticks, frame, run_live
from .model import BEATS, build_model

__all__ = ["BEATS", "build_model", "render_html", "write_html", "frame", "run_live", "beat_ticks"]

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import os
import shutil
import tempfile

from model_loader import load_all_models
from feature_extractor import extract_features, HeuristicResult
from hash_lookup import lookup_file, ThreatIntel
import utils

def safe_bool_check(val):
    if isinstance(val, np.ndarray):
        return bool(val.any())
    return bool(val)

st.set_page_config(
    page_title="Android Malware Detector",
    page_icon="≡ƒ¢í∩╕Å",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600&display=swap');

    :root {
        --bg-primary: #0A0E1A;
        --bg-secondary: #0F1629;
        --surface: #131D35;
        --surface-raised: #1A2542;
        --border: rgba(56, 189, 248, 0.12);
        --border-bright: rgba(56, 189, 248, 0.35);
        --text-primary: #E2E8F0;
        --text-secondary: #94A3B8;
        --text-muted: #475569;
        --accent: #38BDF8;
        --accent-dim: rgba(56, 189, 248, 0.1);
        --success: #34D399;
        --success-dim: rgba(52, 211, 153, 0.08);
        --error: #F87171;
        --error-dim: rgba(248, 113, 113, 0.08);
        --warning: #FBBF24;
        --warning-dim: rgba(251, 191, 36, 0.08);
        --glow-accent: 0 0 20px rgba(56, 189, 248, 0.15);
        --glow-success: 0 0 30px rgba(52, 211, 153, 0.2);
        --glow-error: 0 0 30px rgba(248, 113, 113, 0.2);
        --glow-warning: 0 0 30px rgba(251, 191, 36, 0.2);
    }

    html, body, .stApp {
        background-color: var(--bg-primary) !important;
        font-family: 'DM Sans', sans-serif;
        color: var(--text-primary);
    }

    [data-testid="stSidebar"] {
        background-color: var(--bg-secondary) !important;
        border-right: 1px solid var(--border) !important;
    }
    [data-testid="stSidebar"] > div { padding: 1.5rem 1.25rem; }

    .sidebar-header {
        display: flex; align-items: center; gap: 10px;
        padding-bottom: 1.25rem;
        border-bottom: 1px solid var(--border);
        margin-bottom: 1.5rem;
    }
    .shield-icon {
        width: 34px; height: 34px; flex-shrink: 0;
        background: linear-gradient(135deg, #0EA5E9, #38BDF8);
        border-radius: 8px; display: flex; align-items: center;
        justify-content: center; font-size: 16px;
        box-shadow: 0 0 16px rgba(56,189,248,0.25);
    }
    .brand-name {
        font-family: 'Space Mono', monospace;
        font-size: 0.65rem; font-weight: 700;
        color: var(--text-muted); letter-spacing: 0.18em;
        text-transform: uppercase; line-height: 1.4;
    }
    .brand-name span { color: var(--accent); display: block; font-size: 0.8rem; }

    .sidebar-section-label {
        font-family: 'Space Mono', monospace;
        font-size: 0.6rem; font-weight: 700;
        color: var(--text-muted); letter-spacing: 0.2em;
        text-transform: uppercase; margin-bottom: 0.75rem;
    }

    .models-pill {
        display: inline-flex; align-items: center; gap: 8px;
        background: var(--surface); border: 1px solid var(--border);
        border-radius: 8px; padding: 0.5rem 0.85rem;
        margin: 0.5rem 0 1.25rem 0;
    }
    .models-pill .pill-value {
        font-family: 'Space Mono', monospace;
        font-size: 1.1rem; font-weight: 700;
        color: var(--accent); line-height: 1;
    }
    .models-pill .pill-label {
        font-size: 0.7rem; color: var(--text-muted);
        text-transform: uppercase; letter-spacing: 0.08em;
    }

    .model-badge {
        background: var(--surface); border: 1px solid var(--border-bright);
        border-radius: 8px; padding: 0.6rem 1rem;
        font-family: 'Space Mono', monospace; font-size: 0.72rem;
        color: var(--accent); margin-top: 0.5rem;
        display: flex; align-items: center; gap: 8px;
    }
    .model-badge::before {
        content: ''; width: 7px; height: 7px;
        background: var(--success); border-radius: 50%;
        box-shadow: 0 0 6px var(--success); flex-shrink: 0;
    }

    .main-header {
        text-align: center; padding: 2.75rem 2rem 2rem;
        position: relative; overflow: hidden;
    }
    .main-header::before {
        content: '';
        position: absolute; top: 0; left: 50%; transform: translateX(-50%);
        width: 400px; height: 1px;
        background: linear-gradient(90deg, transparent, var(--accent), transparent);
    }
    .header-eyebrow {
        font-family: 'Space Mono', monospace;
        font-size: 0.65rem; font-weight: 700;
        color: var(--accent); letter-spacing: 0.25em;
        text-transform: uppercase; margin-bottom: 1rem;
    }
    .header-title {
        font-family: 'DM Sans', sans-serif;
        font-size: 2.6rem; font-weight: 600;
        color: var(--text-primary); margin: 0; line-height: 1.15;
        letter-spacing: -0.02em;
    }
    .header-title span { color: var(--accent); }
    .header-sub {
        font-size: 0.95rem; color: var(--text-secondary);
        margin-top: 0.75rem; font-weight: 300;
    }

    .step-row {
        display: flex; align-items: center; justify-content: center;
        gap: 0; margin: 1.5rem auto 2rem auto; max-width: 480px;
    }
    .step-item {
        display: flex; flex-direction: column; align-items: center;
        gap: 5px; flex: 1;
    }
    .step-dot {
        width: 28px; height: 28px; border-radius: 50%;
        border: 1.5px solid var(--border-bright);
        display: flex; align-items: center; justify-content: center;
        font-family: 'Space Mono', monospace; font-size: 0.6rem;
        color: var(--text-muted); background: var(--surface);
    }
    .step-dot.active { border-color: var(--accent); color: var(--accent); box-shadow: 0 0 10px rgba(56,189,248,0.3); }
    .step-dot.done   { border-color: var(--success); color: var(--success); background: rgba(52,211,153,0.08); box-shadow: 0 0 8px rgba(52,211,153,0.2); }
    .step-label { font-family: 'Space Mono', monospace; font-size: 0.52rem; color: var(--text-muted); letter-spacing: 0.1em; text-transform: uppercase; text-align: center; }
    .step-label.active { color: var(--accent); }
    .step-label.done   { color: var(--success); }
    .step-connector { height: 1px; flex: 1; max-width: 60px; background: var(--border); margin-bottom: 18px; }
    .step-connector.done { background: var(--success); opacity: 0.5; }

    .section-label {
        font-family: 'Space Mono', monospace;
        font-size: 0.62rem; letter-spacing: 0.2em;
        text-transform: uppercase; color: var(--text-muted);
        margin-bottom: 0.75rem;
    }

    [data-testid="stFileUploader"] {
        background: var(--surface) !important;
        border: 1px dashed var(--border-bright) !important;
        border-radius: 12px !important;
    }
    [data-testid="stFileUploader"]:hover {
        border-color: var(--accent) !important;
        box-shadow: var(--glow-accent) !important;
    }

    .file-info-bar {
        display: flex; align-items: center; gap: 10px;
        background: var(--surface); border: 1px solid var(--border);
        border-radius: 8px; padding: 0.65rem 1rem; margin: 0.75rem 0;
    }
    .file-info-bar .fi-icon { font-size: 1rem; flex-shrink: 0; }
    .file-info-bar .fi-name { font-family: 'Space Mono', monospace; font-size: 0.68rem; color: var(--text-secondary); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .file-info-bar .fi-size { font-family: 'Space Mono', monospace; font-size: 0.62rem; flex-shrink: 0; }

    .stButton > button {
        background: linear-gradient(135deg, #0EA5E9, #38BDF8) !important;
        color: #0A0E1A !important; font-family: 'Space Mono', monospace !important;
        font-size: 0.78rem !important; font-weight: 700 !important;
        letter-spacing: 0.12em !important; text-transform: uppercase !important;
        border: none !important; border-radius: 10px !important;
        padding: 0.8rem 1.5rem !important;
        box-shadow: 0 4px 20px rgba(56, 189, 248, 0.3) !important;
        transition: all 0.2s ease !important;
    }
    .stButton > button:hover { transform: translateY(-1px) !important; box-shadow: 0 6px 28px rgba(56, 189, 248, 0.45) !important; }
    .stButton > button:active { transform: translateY(0) !important; }

    /* ΓöÇΓöÇ Verdict cards ΓöÇΓöÇ */
    .results-heading { font-family: 'Space Mono', monospace; font-size: 0.62rem; letter-spacing: 0.2em; text-transform: uppercase; color: var(--text-muted); text-align: center; margin-bottom: 1.25rem; }

    .result-safe    { background: var(--success-dim); border: 1px solid rgba(52,211,153,0.3); border-radius: 14px; padding: 2rem; text-align: center; box-shadow: var(--glow-success); position: relative; overflow: hidden; }
    .result-safe::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; background:linear-gradient(90deg,transparent,var(--success),transparent); }

    .result-malware { background: var(--error-dim); border: 1px solid rgba(248,113,113,0.3); border-radius: 14px; padding: 2rem; text-align: center; box-shadow: var(--glow-error); position: relative; overflow: hidden; }
    .result-malware::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; background:linear-gradient(90deg,transparent,var(--error),transparent); }

    .result-threat  { background: var(--error-dim); border: 2px solid rgba(248,113,113,0.5); border-radius: 14px; padding: 2rem; text-align: center; box-shadow: var(--glow-error); position: relative; overflow: hidden; }
    .result-threat::before { content:''; position:absolute; top:0; left:0; right:0; height:3px; background:linear-gradient(90deg,transparent,var(--error),transparent); }

    .verdict { font-family: 'Space Mono', monospace; font-size: 2rem; font-weight: 700; letter-spacing: 0.05em; }
    .verdict.green  { color: var(--success); }
    .verdict.red    { color: var(--error); }
    .verdict-sub    { color: var(--text-secondary); font-size: 0.9rem; margin-top: 0.4rem; font-weight: 300; }

    /* ΓöÇΓöÇ Threat Intel panel ΓöÇΓöÇ */
    .intel-panel {
        background: var(--error-dim);
        border: 1px solid rgba(248,113,113,0.25);
        border-radius: 12px; padding: 1.25rem 1.5rem;
        margin-top: 1rem;
    }
    .intel-panel-header {
        font-family: 'Space Mono', monospace; font-size: 0.62rem;
        letter-spacing: 0.18em; text-transform: uppercase;
        color: var(--error); margin-bottom: 0.85rem;
        display: flex; align-items: center; gap: 8px;
    }
    .intel-panel-header::before { content:''; width:7px; height:7px; background:var(--error); border-radius:50%; box-shadow:0 0 6px var(--error); flex-shrink:0; }
    .intel-row { display:flex; gap:1rem; align-items:baseline; font-family:'Space Mono',monospace; font-size:0.68rem; line-height:2; }
    .intel-key { color:var(--text-muted); min-width:80px; flex-shrink:0; }
    .intel-val { color:var(--text-primary); word-break:break-all; }
    .intel-val.tag {
        display:inline-block; background:rgba(248,113,113,0.15);
        border:1px solid rgba(248,113,113,0.3);
        border-radius:4px; padding:1px 7px;
        font-size:0.6rem; margin:1px 2px;
        color:var(--error);
    }
    .intel-link { color:var(--accent); text-decoration:none; font-size:0.62rem; }
    .intel-link:hover { text-decoration:underline; }

    /* ΓöÇΓöÇ Warning panel (hash not found but model flagged) ΓöÇΓöÇ */
    .warning-panel {
        background: var(--warning-dim);
        border: 1px solid rgba(251,191,36,0.25);
        border-radius: 10px; padding: 0.9rem 1.25rem; margin-top: 0.75rem;
        font-family: 'Space Mono', monospace; font-size: 0.65rem;
        color: var(--warning); line-height: 1.6;
    }

    /* ΓöÇΓöÇ Source badges ΓöÇΓöÇ */
    .source-badge {
        display:inline-flex; align-items:center; gap:5px;
        background:rgba(248,113,113,0.1); border:1px solid rgba(248,113,113,0.3);
        border-radius:6px; padding:3px 10px;
        font-family:'Space Mono',monospace; font-size:0.6rem; color:var(--error);
        margin:2px;
    }

    /* ΓöÇΓöÇ Summary card ΓöÇΓöÇ */
    .summary-card { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:1rem 1.25rem; font-family:'Space Mono',monospace; font-size:0.7rem; color:var(--text-muted); line-height:2; }
    .summary-card .row { display:flex; gap:1rem; align-items:baseline; }
    .summary-card .row .key { color:var(--text-secondary); min-width:72px; }
    .summary-card .row .val { color:var(--text-primary); word-break:break-all; }
    .summary-card .row .val.clean   { color:var(--success); }
    .summary-card .row .val.malware { color:var(--error); }

    .stSelectbox > div > div { background:var(--surface) !important; border:1px solid var(--border) !important; border-radius:8px !important; color:var(--text-primary) !important; font-family:'Space Mono',monospace !important; font-size:0.78rem !important; }
    .stSpinner > div { border-top-color: var(--accent) !important; }
    hr { border-color: var(--border) !important; margin: 1.25rem 0 !important; }
    .stAlert { border-radius: 10px !important; }

    .footer-text { text-align:center; color:var(--text-muted); padding:2.5rem 0 1rem; font-size:0.75rem; font-family:'Space Mono',monospace; letter-spacing:0.08em; border-top:1px solid var(--border); margin-top:3rem; }

    /* ΓöÇΓöÇ Heuristics panel ΓöÇΓöÇ */
    .heuristic-panel {
        background: var(--surface); border: 1px solid var(--border);
        border-radius: 12px; padding: 1.25rem 1.5rem; margin-top: 1rem;
    }
    .heuristic-panel-header {
        font-family: 'Space Mono', monospace; font-size: 0.62rem;
        letter-spacing: 0.18em; text-transform: uppercase;
        color: var(--text-muted); margin-bottom: 1rem;
        display: flex; align-items: center; justify-content: space-between;
    }
    .heuristic-panel-header .h-title { color: var(--text-secondary); }
    .severity-badge {
        font-family: 'Space Mono', monospace; font-size: 0.58rem;
        font-weight: 700; letter-spacing: 0.1em;
        padding: 2px 8px; border-radius: 4px;
    }
    .severity-badge.critical { background: rgba(248,113,113,0.15); color: var(--error);   border: 1px solid rgba(248,113,113,0.3); }
    .severity-badge.high     { background: rgba(251,191,36,0.12);  color: var(--warning); border: 1px solid rgba(251,191,36,0.3); }
    .severity-badge.medium   { background: rgba(56,189,248,0.08);  color: var(--accent);  border: 1px solid rgba(56,189,248,0.2); }

    .rule-row {
        display: flex; align-items: center; gap: 10px;
        padding: 0.45rem 0; border-bottom: 1px solid var(--border);
        font-family: 'Space Mono', monospace; font-size: 0.65rem;
    }
    .rule-row:last-child { border-bottom: none; }
    .rule-id   { color: var(--text-muted); min-width: 32px; flex-shrink: 0; }
    .rule-label{ color: var(--text-secondary); flex: 1; }
    .rule-match{ color: var(--text-muted); font-size: 0.58rem; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    /* dimmed "not detected" rows */
    .rule-row-miss { opacity: 0.35; }
    .rule-id-miss   { color: var(--text-muted); }
    .rule-label-miss{ color: var(--text-muted); }
    .rule-match-miss{ color: var(--text-muted); font-size: 0.58rem; font-style: italic; }
    .severity-badge-miss {
        font-family: 'Space Mono', monospace; font-size: 0.58rem;
        font-weight: 700; letter-spacing: 0.1em;
        padding: 2px 8px; border-radius: 4px;
        background: rgba(71,85,105,0.15); color: var(--text-muted);
        border: 1px solid rgba(71,85,105,0.25);
    }
    .h-counts  { display: flex; gap: 6px; margin-top: 0.85rem; }
    .h-count-chip {
        font-family: 'Space Mono', monospace; font-size: 0.6rem;
        padding: 3px 10px; border-radius: 20px;
    }
    .h-count-chip.c { background:rgba(248,113,113,0.12); color:var(--error);   border:1px solid rgba(248,113,113,0.25); }
    .h-count-chip.h { background:rgba(251,191,36,0.10);  color:var(--warning); border:1px solid rgba(251,191,36,0.25); }
    .h-count-chip.m { background:rgba(56,189,248,0.07);  color:var(--accent);  border:1px solid rgba(56,189,248,0.18); }

    /* ΓöÇΓöÇ Confidence panel ΓöÇΓöÇ */
    .confidence-panel {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 1.25rem 1.5rem;
        margin-top: 1rem;
        position: relative;
        overflow: hidden;
    }
    .confidence-panel::before {
        content: '';
        position: absolute; top: 0; left: 0; right: 0; height: 1px;
        background: linear-gradient(90deg, transparent, var(--border-bright), transparent);
    }
    .conf-header {
        display: flex;
        align-items: baseline;
        justify-content: space-between;
        margin-bottom: 0.85rem;
    }
    .conf-title {
        font-family: 'Space Mono', monospace;
        font-size: 0.62rem; letter-spacing: 0.2em;
        text-transform: uppercase; color: var(--text-muted);
    }
    .conf-value {
        font-family: 'Space Mono', monospace;
        font-size: 1.5rem; font-weight: 700; line-height: 1;
    }
    .conf-track {
        position: relative;
        height: 8px; border-radius: 99px;
        overflow: visible;
        margin-bottom: 1.6rem;
    }
    .conf-fill {
        position: absolute; top: 0; left: 0;
        height: 100%; border-radius: 99px;
        transition: width 0.6s cubic-bezier(0.4,0,0.2,1);
    }
    .conf-glow-head {
        position: absolute; top: 50%;
        transform: translateY(-50%);
        width: 4px; height: 16px;
        border-radius: 2px;
    }
    .conf-tick {
        position: absolute; top: 14px;
        transform: translateX(-50%);
        display: flex; flex-direction: column; align-items: center;
    }
    .conf-tick::before {
        content: '';
        display: block; width: 1px; height: 5px;
        background: var(--text-muted); opacity: 0.4;
        margin-bottom: 3px;
    }
    .conf-tick-label {
        font-family: 'Space Mono', monospace;
        font-size: 0.5rem; color: var(--text-muted);
        opacity: 0.6;
    }
    .conf-sub {
        font-family: 'Space Mono', monospace;
        font-size: 0.6rem; color: var(--text-muted);
        letter-spacing: 0.05em; margin-top: 0.25rem;
    }
</style>
""", unsafe_allow_html=True)

# ΓöÇΓöÇ Session state ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
for key, default in [
    ("step", 1), ("result", None),
    ("result_filename", ""), ("result_model", ""),
    ("intel", None), ("sha256", ""), ("heuristic", None),
]:
    if key not in st.session_state:
        st.session_state[key] = default

# ΓöÇΓöÇ Step renderer ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
def render_steps():
    s = st.session_state
    done = {1: True, 2: s.step >= 2, 3: s.step >= 4, 4: s.result is not None}
    labels = ["Model", "Upload", "Scan", "Results"]
    html = '<div class="step-row">'
    for i, label in enumerate(labels):
        num = i + 1
        if done[num]:
            dot_cls, lbl_cls, inner = "done", "done", "Γ£ô"
        else:
            dot_cls, lbl_cls, inner = "", "", str(num)
        html += f'<div class="step-item"><div class="step-dot {dot_cls}">{inner}</div><div class="step-label {lbl_cls}">{label}</div></div>'
        if i < len(labels) - 1:
            conn_cls = "done" if done[num] and done[num + 1] else ""
            html += f'<div class="step-connector {conn_cls}"></div>'
    html += "</div>"
    st.markdown(html, unsafe_allow_html=True)

# ΓöÇΓöÇ Intel panel renderer ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
def render_intel_panel(intel: ThreatIntel):
    if not intel or not intel.found:
        return

    tags_html = "".join(f'<span class="intel-val tag">{t}</span>' for t in intel.mb_tags) if intel.mb_tags else '<span class="intel-val">ΓÇö</span>'
    sources_html = "".join(f'<span class="source-badge">ΓÜæ {s}</span>' for s in intel.sources)

    mb_link = f'<a class="intel-link" href="{intel.mb_url}" target="_blank">View on MalwareBazaar Γåù</a>' if intel.mb_url else ""
    vt_link  = f' &nbsp;┬╖&nbsp; <a class="intel-link" href="{intel.vt_url}" target="_blank">View on VirusTotal Γåù</a>' if intel.vt_url else ""

    vt_row = ""
    if intel.vt_total > 0:
        vt_row = f'<div class="intel-row"><span class="intel-key">VT DETECT</span><span class="intel-val" style="color:var(--error);">{intel.vt_malicious} / {intel.vt_total} engines</span></div>'

    sig = intel.mb_signature or "ΓÇö"
    reporter = intel.mb_reporter or "ΓÇö"
    first_seen = intel.mb_first_seen[:10] if intel.mb_first_seen else "ΓÇö"

    st.markdown(f"""
    <div class="intel-panel">
        <div class="intel-panel-header">Threat Intelligence Match</div>
        <div class="intel-row"><span class="intel-key">SHA256</span><span class="intel-val" style="font-size:0.6rem;">{intel.sha256}</span></div>
        <div class="intel-row"><span class="intel-key">SIGNATURE</span><span class="intel-val">{sig}</span></div>
        <div class="intel-row"><span class="intel-key">FIRST SEEN</span><span class="intel-val">{first_seen}</span></div>
        <div class="intel-row"><span class="intel-key">REPORTER</span><span class="intel-val">{reporter}</span></div>
        <div class="intel-row"><span class="intel-key">TAGS</span><span class="intel-val">{tags_html}</span></div>
        {vt_row}
        <div class="intel-row"><span class="intel-key">SOURCES</span><span class="intel-val">{sources_html}</span></div>
        <div class="intel-row" style="margin-top:0.5rem;"><span class="intel-key"></span><span class="intel-val">{mb_link}{vt_link}</span></div>
    </div>
    """, unsafe_allow_html=True)

# ΓöÇΓöÇ Heuristic panel renderer ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
def render_heuristic_panel(heuristic: HeuristicResult):
    from feature_extractor import HEURISTIC_RULES

    if heuristic is None:
        return

    overall_cls = heuristic.severity_summary.lower()

    # Build a lookup of triggered rule IDs ΓåÆ matched_on string
    triggered_map = {rule_id: matched_on for rule_id, label, severity, matched_on in heuristic.triggered_rules}

    rows_html = ""
    for rule_id, label, severity, patterns in HEURISTIC_RULES:
        if rule_id in triggered_map:
            safe_match = triggered_map[rule_id].replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
            rows_html += (
                f'<div class="rule-row rule-row-hit">'
                f'<span class="rule-id">{rule_id}</span>'
                f'<span class="rule-label">{label}</span>'
                f'<span class="severity-badge {severity}">{severity.upper()}</span>'
                f'<span class="rule-match" title="{safe_match}">&#8627; {safe_match}</span>'
                f'</div>'
            )
        else:
            rows_html += (
                f'<div class="rule-row rule-row-miss">'
                f'<span class="rule-id rule-id-miss">{rule_id}</span>'
                f'<span class="rule-label rule-label-miss">{label}</span>'
                f'<span class="severity-badge severity-badge-miss">{severity.upper()}</span>'
                f'<span class="rule-match rule-match-miss">&#8627; not detected</span>'
                f'</div>'
            )

    full_html = (
        '<div class="heuristic-panel">'
        '<div class="heuristic-panel-header">'
        '<span class="h-title">Rule-Based Heuristics</span>'
        f'<span class="severity-badge {overall_cls}">Overall: {heuristic.severity_summary}</span>'
        '</div>'
        + rows_html +
        '<div class="h-counts">'
        f'<span class="h-count-chip c">&#9899; {heuristic.critical_hits} Critical</span>'
        f'<span class="h-count-chip h">&#9899; {heuristic.high_hits} High</span>'
        f'<span class="h-count-chip m">&#9899; {heuristic.medium_hits} Medium</span>'
        '</div>'
        '</div>'
    )
    st.markdown(full_html, unsafe_allow_html=True)

# ΓöÇΓöÇ Results renderer ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
def render_results(prediction, confidence, filename, model_used, intel: ThreatIntel, sha256: str, heuristic: HeuristicResult):
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="results-heading">Analysis Results</div>', unsafe_allow_html=True)

    # ΓöÇΓöÇ Determine final verdict ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    hash_says_malware      = intel and intel.found and intel.malicious
    ml_says_malware        = prediction == 1
    heuristic_says_malware = heuristic and heuristic.flagged

    final_malware = hash_says_malware or ml_says_malware or heuristic_says_malware

    # ΓöÇΓöÇ Verdict card ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    if final_malware:
        st.markdown("""
        <div class="result-malware">
            <div class="verdict red">ΓÜá MALWARE DETECTED</div>
            <div class="verdict-sub">Malicious signatures have been detected in this application. Installation is strongly discouraged.</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="result-safe">
            <div class="verdict green">CLEAN</div>
            <div class="verdict-sub">No malicious signatures were detected. This application appears to be safe.</div>
        </div>
        """, unsafe_allow_html=True)

    # ΓöÇΓöÇ Threat intel panel (if hash found) ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    if hash_says_malware:
        render_intel_panel(intel)

    # ΓöÇΓöÇ Heuristics panel (always shown) ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    render_heuristic_panel(heuristic)

    # ΓöÇΓöÇ Confidence gauge ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    conf_pct   = round(confidence * 100, 1)
    bar_color  = "#F87171" if final_malware else "#34D399"
    glow_color = "rgba(248,113,113,0.35)" if final_malware else "rgba(52,211,153,0.35)"
    track_color = "rgba(248,113,113,0.12)" if final_malware else "rgba(52,211,153,0.10)"
    label_color = "#F87171" if final_malware else "#34D399"

    ticks_html = "".join(
        f'<div class="conf-tick" style="left:{v}%"><span class="conf-tick-label">{v}</span></div>'
        for v in [25, 50, 75, 100]
    )

    st.markdown(f"""
    <div class="confidence-panel">
        <div class="conf-header">
            <span class="conf-title">Model Confidence</span>
            <span class="conf-value" style="color:{label_color};">{conf_pct}%</span>
        </div>
        <div class="conf-track" style="background:{track_color};">
            <div class="conf-fill" style="
                width:{conf_pct}%;
                background:linear-gradient(90deg, {bar_color}88, {bar_color});
                box-shadow:0 0 12px {glow_color};
            "></div>
            <div class="conf-glow-head" style="
                left:calc({conf_pct}% - 2px);
                background:{bar_color};
                box-shadow:0 0 8px {glow_color};
            "></div>
            {ticks_html}
        </div>
        <div class="conf-sub">
            Classifier: <span style="color:var(--text-secondary);">{model_used}</span>
            &nbsp;┬╖&nbsp; Verdict: <span style="color:{label_color};">{'MALWARE' if final_malware else 'CLEAN'}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ΓöÇΓöÇ Header ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
st.markdown("""
<div class="main-header">
    <div class="header-eyebrow">Static Analysis + Threat Intelligence</div>
    <h1 class="header-title">Android <span>Malware</span> Detection</h1>
    <p class="header-sub">Upload an APK or XAPK to scan for malicious signatures using ensemble ML models</p>
</div>
""", unsafe_allow_html=True)

# ΓöÇΓöÇ Model loading ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
with st.spinner("Initializing detection engine..."):
    models, features = load_all_models()

# ΓöÇΓöÇ Sidebar ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
with st.sidebar:
    st.markdown("""
    <div class="sidebar-header">
        <div class="shield-icon">≡ƒ¢í∩╕Å</div>
        <div class="brand-name">Android<span>MALWARE DETECTOR</span></div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section-label">Detection Model</div>', unsafe_allow_html=True)
    model_names    = list(models.keys())
    selected_model = st.selectbox("", model_names, index=0 if model_names else None, label_visibility="collapsed")
    st.markdown(f'<div class="model-badge">{selected_model}</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="sidebar-section-label">System Status</div>', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="models-pill">
        <span class="pill-value">{len(models)}</span>
        <span class="pill-label">Models loaded</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<div class="sidebar-section-label">Available Models</div>', unsafe_allow_html=True)
    for name in model_names:
        active = "Γ£ª " if name == selected_model else "┬╖ "
        color  = "var(--accent)" if name == selected_model else "var(--text-muted)"
        st.markdown(f'<p style="font-family:Space Mono,monospace;font-size:0.7rem;color:{color};margin:4px 0;">{active}{name}</p>', unsafe_allow_html=True)

# ΓöÇΓöÇ Main content ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
_, center, _ = st.columns([1, 3, 1])
with center:

    render_steps()

    st.markdown('<div class="section-label">Upload APK or XAPK File</div>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader(
        "", type=['apk', 'xapk'],
        help="Select an Android APK or XAPK file to analyze (up to 700 MB)",
        label_visibility="collapsed"
    )

    if uploaded_file is None:
        if st.session_state.step >= 2:
            st.session_state.step      = 1
            st.session_state.result    = None
            st.session_state.intel     = None
            st.session_state.sha256    = ""
            st.session_state.heuristic = None
            st.rerun()

    if uploaded_file is not None:

        if st.session_state.step < 2:
            st.session_state.step = 2
            st.rerun()

        file_size_mb = uploaded_file.size / (1024 * 1024)
        size_color   = "#F87171" if file_size_mb > 600 else "#FBBF24" if file_size_mb > 200 else "#34D399"
        size_icon    = "ΓÜá" if file_size_mb > 200 else "Γ£ô"
        file_ext     = uploaded_file.name.rsplit(".", 1)[-1].upper() if "." in uploaded_file.name else "APK"
        st.markdown(f"""
        <div class="file-info-bar">
            <span class="fi-icon">≡ƒôª</span>
            <span class="fi-name">{uploaded_file.name}</span>
            <span style="font-family:Space Mono,monospace;font-size:0.58rem;color:var(--accent);background:var(--accent-dim);border:1px solid var(--border-bright);border-radius:4px;padding:1px 6px;flex-shrink:0;">{file_ext}</span>
            <span class="fi-size" style="color:{size_color};">{size_icon} {file_size_mb:.1f} MB</span>
        </div>
        """, unsafe_allow_html=True)

        if file_size_mb > 600:
            st.warning(f"ΓÜá Very large file: {file_size_mb:.1f} MB ΓÇö processing will take several minutes.")
        elif file_size_mb > 400:
            st.warning(f"ΓÜá Large file: {file_size_mb:.1f} MB ΓÇö processing may take a few minutes.")

        file_suffix = '.xapk' if uploaded_file.name.lower().endswith('.xapk') else '.apk'
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_suffix) as tmp_file:
            shutil.copyfileobj(uploaded_file, tmp_file)
            tmp_path = tmp_file.name

        st.markdown("<br>", unsafe_allow_html=True)

        if st.button("Run Analysis", use_container_width=True):
            error = None
            st.session_state.step      = 3
            st.session_state.result    = None
            st.session_state.intel     = None
            st.session_state.sha256    = ""
            st.session_state.heuristic = None

            with st.spinner("Step 1/2 ΓÇö Hashing file and querying threat databases..."):
                try:
                    from hash_lookup import sha256_of_file, lookup_hash
                    original_sha256 = sha256_of_file(tmp_path)
                    intel = lookup_hash(original_sha256)
                    if not intel.found and tmp_path.endswith('.xapk'):
                        try:
                            from feature_extractor import _extract_apk_from_xapk
                            inner_apk = _extract_apk_from_xapk(tmp_path)
                            if inner_apk:
                                inner_sha256 = sha256_of_file(inner_apk)
                                inner_intel  = lookup_hash(inner_sha256)
                                os.unlink(inner_apk)
                                if inner_intel.found and inner_intel.malicious:
                                    inner_intel.sha256 = original_sha256
                                    intel = inner_intel
                        except Exception as e2:
                            print(f"[hash_lookup] inner APK fallback error: {e2}")
                    st.session_state.sha256 = original_sha256
                    st.session_state.intel  = intel
                except Exception as e:
                    st.session_state.intel = None
                    print(f"[hash_lookup] error: {e}")

            with st.spinner("Step 2/2 ΓÇö Extracting features, running ML + heuristics..."):
                try:
                    feature_vector, matches, heuristic = extract_features(tmp_path, features)
                    model      = models[selected_model]
                    prediction = model.predict(feature_vector)[0]

                    if hasattr(model, 'predict_proba'):
                        proba      = model.predict_proba(feature_vector)[0]
                        confidence = proba[prediction] if len(proba) > 1 else proba[0]
                    else:
                        confidence = 0.5 + 0.4 * (prediction - 0.5)

                    st.session_state.result          = {"prediction": int(prediction), "confidence": float(confidence)}
                    st.session_state.result_filename = uploaded_file.name
                    st.session_state.result_model    = selected_model
                    st.session_state.heuristic       = heuristic
                    st.session_state.step            = 4

                except Exception as e:
                    st.session_state.step = 2
                    error = e
                finally:
                    utils.safe_file_cleanup(tmp_path)

            if error:
                st.error(f"Analysis failed: {error}")
            else:
                st.rerun()

        if st.session_state.step == 4 and st.session_state.result:
            render_results(
                st.session_state.result["prediction"],
                st.session_state.result["confidence"],
                st.session_state.result_filename,
                st.session_state.result_model,
                st.session_state.intel,
                st.session_state.sha256,
                st.session_state.heuristic,
            )

# ΓöÇΓöÇ Footer ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
st.markdown("""
<div class="footer-text">
    Android Malware Detection Engine
</div>
""", unsafe_allow_html=True)
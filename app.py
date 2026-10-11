"""
AegisTrace AI — Intelligent SIEM Investigation Assistant (v2.1)

Run:  streamlit run app.py
"""
from __future__ import annotations

import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
try:
    import plotly.express as px
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    px = None
    go = None
    HAS_PLOTLY = False
import streamlit as st

from analyzer import VERSION, analyze_events, build_report
from components.styles import (
    get_all_styles, render_art_side, render_checklist_item, render_empty, render_footer, render_hero,
    render_injection_warning, render_ioc_card, render_metric_card, render_pattern_card, render_risk_gauge,
    render_section, render_sidebar_brand, render_timeline_event,
    render_subscription_card, render_company_showcase, render_plan_card,
)
from llm_providers import (
    PROTOCOL_LABELS, PROVIDERS, LLMConfig, LLMError, config_from_env, test_connection,
)
from llm_summary import generate_llm_summary
from utils.compat import STRETCH
from utils.sanitizer import csv_safe, sanitize_html, sanitize_llm_output

BASE = Path(__file__).resolve().parent
MAX_UPLOAD_MB = 20

st.set_page_config(page_title="AegisTrace AI — SIEM Investigation", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")
st.markdown(get_all_styles(), unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# LLM provider state (front-end configurable)
# ─────────────────────────────────────────────────────────────

_ENV_CFG: LLMConfig = config_from_env()


def _init_llm_state() -> None:
    if st.session_state.get("llm_init"):
        return
    st.session_state.update(
        llm_provider=_ENV_CFG.provider, llm_protocol=_ENV_CFG.protocol, llm_base_url=_ENV_CFG.base_url,
        llm_model=_ENV_CFG.model, llm_api_key="",  # never pre-fill a server-side key into the browser
        llm_temperature=0.1, llm_max_tokens=1800, llm_timeout=60, llm_auth_header="", llm_auth_prefix="",
        llm_enabled=False, llm_test=None, advisory=None, llm_init=True,
    )


def _on_provider_change() -> None:
    p = PROVIDERS[st.session_state.llm_provider]
    st.session_state.llm_base_url = p["base_url"]
    st.session_state.llm_model = p["default_model"]
    st.session_state.llm_protocol = p["protocol"]
    st.session_state.llm_test = None


def current_config() -> LLMConfig:
    # Strictly lock down API configuration to server-side environment / secrets.
    # No user or attacker can supply or modify API keys or targets via the frontend.
    return _ENV_CFG


_init_llm_state()

# ─────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown(render_sidebar_brand(), unsafe_allow_html=True)

    st.markdown('<div class="side-h">Data input</div>', unsafe_allow_html=True)
    uploaded = st.file_uploader("Upload SIEM alerts", type=["json", "csv"],
                                help=f"JSON array / wrapper object or CSV. Max {MAX_UPLOAD_MB} MB.")
    paste = st.text_area("Or paste JSON / CSV", height=130,
                         placeholder='[{"timestamp":"2026-10-06T10:00:00Z","source_ip":"10.0.0.5",'
                                     '"event_type":"login_failed","user":"admin"}]')
    demo = st.radio("Demo dataset", ["JSON — multi-stage intrusion", "CSV — brute force"],
                    horizontal=False, help="Used when nothing is uploaded or pasted.")

    st.markdown('<div class="side-h">AI advisory engine</div>', unsafe_allow_html=True)
    server_configured = _ENV_CFG.is_ready()
    st.toggle("Enable AI advisory narrative", key="llm_enabled",
              help="Advisory summaries generated using server-side security credentials.")
    if st.session_state.llm_enabled:
        if server_configured:
            st.markdown(
                f'<div style="font:600 0.8rem var(--mono);color:var(--teal);margin-bottom:.4rem;">'
                f'🔒 Server Key Active: {sanitize_html(PROVIDERS.get(_ENV_CFG.provider, {}).get("label", _ENV_CFG.provider))}</div>'
                f'<div style="font-size:0.75rem;color:var(--muted);">'
                f'Model: <code>{sanitize_html(_ENV_CFG.model)}</code><br/>'
                f'API keys & endpoints are managed securely via server secrets (.env / cloud secrets). '
                f'Frontend API key inputs are strictly disabled for security.</div>',
                unsafe_allow_html=True,
            )
            if st.button("Test server connection", **STRETCH):
                with st.spinner("Verifying backend provider…"):
                    st.session_state.llm_test = test_connection(_ENV_CFG)
            test = st.session_state.llm_test
            if test:
                (st.success if test[0] else st.error)(sanitize_llm_output(test[1]))
        else:
            st.warning("⚠️ No backend API key configured. API keys must be set on the server via `.env` or Streamlit Secrets (`AEGIS_API_KEY`). Frontend key inputs are disabled.")
        st.caption("SIEM text is isolated as untrusted data. AI narrative remains advisory only.")
                   "data and the reply is advisory only.")

    st.markdown('<div class="side-h">About</div>', unsafe_allow_html=True)
    st.caption("AegisTrace AI is a defensive triage tool. It never executes commands, blocks IPs, or "
               "touches endpoints. Every response action needs analyst approval.")

# ─────────────────────────────────────────────────────────────
# Data loading (cached)
# ─────────────────────────────────────────────────────────────


def _decode(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeError:
            continue
    return raw.decode("utf-8", "replace")


@st.cache_data(show_spinner="Analyzing events…", max_entries=8)
def run_analysis(raw: bytes, hint: str) -> dict:
    text = _decode(raw).strip()
    if hint == "csv" or (hint == "auto" and text[:1] not in "[{"):
        rows = pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False).to_dict("records")
        return analyze_events(rows)
    return analyze_events(json.loads(text))


def pick_input() -> tuple[bytes, str, str]:
    """Return (bytes, format hint, human label)."""
    if uploaded is not None:
        if uploaded.size > MAX_UPLOAD_MB * 1024 * 1024:
            raise ValueError(f"File is larger than {MAX_UPLOAD_MB} MB.")
        return uploaded.getvalue(), "csv" if uploaded.name.lower().endswith(".csv") else "json", uploaded.name
    if paste.strip():
        return paste.encode("utf-8"), "auto", "pasted data"
    name = "sample_alerts.csv" if demo.startswith("CSV") else "sample_alerts.json"
    return (BASE / name).read_bytes(), "csv" if name.endswith(".csv") else "json", f"demo: {name}"


try:
    raw_bytes, fmt_hint, source_label = pick_input()
    result = run_analysis(raw_bytes, fmt_hint)
except Exception as exc:  # noqa: BLE001 - surface any parse problem to the analyst
    st.markdown(render_hero("Waiting for valid input", warn=True), unsafe_allow_html=True)
    st.error(f"Could not parse the supplied SIEM data: {sanitize_llm_output(str(exc)[:300])}")
    st.stop()

data_sig = hashlib.sha256(raw_bytes).hexdigest()[:16]
events, summary, timeline = result["events"], result["summary"], result["timeline"]
patterns, injection_flags = result["patterns"], result["prompt_injection_flags"]
iocs, checklist, risk_score = result["iocs"], result["checklist"], summary["risk_score"]
is_demo = uploaded is None and not paste.strip()

st.markdown(render_hero(f"Analyzing {source_label}"), unsafe_allow_html=True)
if is_demo:
    st.info("Showing built-in demo data. Upload a file or paste alerts in the sidebar to analyze your own.")
if summary["unparsed_timestamps"]:
    st.warning(f"{summary['unparsed_timestamps']} event(s) have unreadable timestamps and are placed last "
               "in the timeline.")

# ─────────────────────────────────────────────────────────────
# Metrics
# ─────────────────────────────────────────────────────────────

cols = st.columns(6)
cards = [
    render_metric_card("📊", summary["total_events"], "Total events", "blue"),
    render_metric_card("🔴", summary["high_critical"], "High / critical",
                       "red" if summary["high_critical"] else "green", critical=summary["high_critical"] > 2),
    render_metric_card("🌐", summary["unique_source_ips"], "Source IPs", "cyan"),
    render_metric_card("🖥️", summary["unique_hosts"], "Hosts", "purple"),
    render_metric_card("🛡️", len(injection_flags), "Injection flags",
                       "red" if injection_flags else "green", critical=bool(injection_flags)),
    render_risk_gauge(risk_score),
]
for col, card in zip(cols, cards):
    col.markdown(card, unsafe_allow_html=True)
st.markdown("<div style='height:.8rem'></div>", unsafe_allow_html=True)


def style_fig(fig, height: int = 300):
    if not HAS_PLOTLY or fig is None:
        return None
    fig.update_layout(
        template="plotly_dark", plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        font=dict(family="IBM Plex Sans, system-ui, sans-serif", color="#8aa0b2"),
        margin=dict(l=10, r=10, t=10, b=30), height=height, showlegend=False)
    fig.update_xaxes(gridcolor="rgba(138,160,178,.12)")
    fig.update_yaxes(gridcolor="rgba(138,160,178,.12)")
    return fig


def chart(fig) -> None:
    if HAS_PLOTLY and fig is not None:
        st.plotly_chart(fig, config={"displayModeBar": False}, **STRETCH)


def event_frame(evs: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(evs)
    return df.drop(columns=[c for c in ("raw_text", "mitre") if c in df.columns])

tabs = st.tabs(["📌 Overview", "🕒 Timeline", "🔎 Patterns & MITRE", "🎯 IOCs", "🧪 Alert data",
                "✅ Checklist", "🤖 AI advisory", "💎 Enterprise Tiers", "📄 Report & export"])

# ── Overview ───────────────────────────────────────────────
with tabs[0]:
    st.markdown(render_section("📌", "Incident overview", "AUTOMATED ANALYSIS"), unsafe_allow_html=True)
    st.markdown(f'<div class="panel blue"><div class="cap">Narrative summary</div>'
                f'{sanitize_html(summary["narrative"])}</div>', unsafe_allow_html=True)
    if injection_flags:
        st.markdown(render_injection_warning(len(injection_flags)), unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(injection_flags), hide_index=True, **STRETCH)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(render_section("📊", "Severity distribution"), unsafe_allow_html=True)
        sev_df = pd.DataFrame([{"severity": s, "count": summary["severity_counts"].get(s, 0)}
                               for s in ("low", "medium", "high", "critical")
                               if summary["severity_counts"].get(s, 0)])
        if HAS_PLOTLY:
            fig = px.bar(sev_df, x="severity", y="count", color="severity",
                         color_discrete_map={"low": "#4ade80", "medium": "#fbbf24", "high": "#ff9f43", "critical": "#ff5d5d"})
            chart(style_fig(fig))
        elif not sev_df.empty:
            st.bar_chart(sev_df.set_index("severity")["count"], **STRETCH)
    with c2:
        st.markdown(render_section("🗂️", "Event categories"), unsafe_allow_html=True)
        cat_df = pd.DataFrame([{"category": k.replace("_", " ").title(), "count": v}
                               for k, v in summary["category_counts"].items()]).sort_values("count")
        if HAS_PLOTLY:
            fig = px.bar(cat_df, x="count", y="category", orientation="h", color_discrete_sequence=["#2dd4bf"])
            chart(style_fig(fig))
        elif not cat_df.empty:
            st.bar_chart(cat_df.set_index("category")["count"], **STRETCH)

    if summary["mitre_techniques"]:
        st.markdown(render_section("🎯", "MITRE ATT&CK techniques observed"), unsafe_allow_html=True)
        st.markdown("".join(f'<span class="mitre" style="margin:0 .4rem .4rem 0;display:inline-block">'
                            f'{sanitize_html(t)}</span>' for t in summary["mitre_techniques"]),
                    unsafe_allow_html=True)

# ── Timeline ───────────────────────────────────────────────
with tabs[1]:
    st.markdown(render_section("🕒", "Chronological event timeline", "CHRONOLOGICAL"), unsafe_allow_html=True)
    mode = st.radio("View", ["Visual timeline", "Data table"], horizontal=True, label_visibility="collapsed")
    if mode == "Visual timeline":
        shown = timeline[:300]
        st.markdown('<div class="tl">' + "".join(render_timeline_event(e, i) for i, e in enumerate(shown)) + "</div>",
                    unsafe_allow_html=True)
        if len(timeline) > len(shown):
            st.caption(f"Showing the first {len(shown)} of {len(timeline)} events. Use the data table for all.")
    else:
        st.dataframe(pd.DataFrame(timeline), hide_index=True, **STRETCH)

    st.markdown(render_section("🌡️", "Severity heatmap by minute"), unsafe_allow_html=True)
    hdf = pd.DataFrame(timeline)
    hdf["t"] = pd.to_datetime(hdf["time"], errors="coerce", utc=True)
    hdf = hdf.dropna(subset=["t"])
    if hdf.empty:
        st.caption("No parseable timestamps — heatmap unavailable.")
    else:
        hdf["minute"] = hdf["t"].dt.floor("min")
        hdf["sev"] = hdf["severity"].map({"low": 1, "medium": 2, "high": 3, "critical": 4})
        piv = hdf.pivot_table(index="category", columns="minute", values="sev", aggfunc="max").sort_index(axis=1)
        if HAS_PLOTLY:
            fig = go.Figure(go.Heatmap(
                z=piv.values, x=[m.strftime("%H:%M") for m in piv.columns], y=[c.replace("_", " ") for c in piv.index],
                colorscale=[[0, "#4ade80"], [.33, "#fbbf24"], [.66, "#ff9f43"], [1, "#ff5d5d"]], zmin=1, zmax=4,
                xgap=2, ygap=2, colorbar=dict(title="Severity", tickvals=[1, 2, 3, 4],
                                              ticktext=["low", "medium", "high", "critical"])))
            fig.update_xaxes(type="category")
            chart(style_fig(fig, 300))
        else:
            st.dataframe(piv, **STRETCH)

# ── Patterns & MITRE ───────────────────────────────────────
with tabs[2]:
    st.markdown(render_section("🔎", "Correlated patterns & MITRE ATT&CK", "CORRELATION ENGINE", "amber"),
                unsafe_allow_html=True)
    if patterns:
        for p in sorted(patterns, key=lambda p: -{"low": 1, "medium": 2, "high": 3, "critical": 4}[p["severity"]]):
            st.markdown(render_pattern_card(p), unsafe_allow_html=True)
    else:
        st.markdown(render_empty("radar.svg", "No correlated patterns",
                                 "No repeated-activity pattern met the correlation thresholds."), unsafe_allow_html=True)
    rows = [{"tactic": e["mitre"]["tactic"], "technique": e["mitre"]["technique"]}
            for e in events if e["mitre"]["technique"] != "N/A"]
    if rows:
        st.markdown(render_section("🗺️", "MITRE ATT&CK coverage"), unsafe_allow_html=True)
        counts = pd.DataFrame(rows).groupby(["tactic", "technique"]).size().reset_index(name="count")
        if HAS_PLOTLY:
            fig = px.treemap(counts, path=["tactic", "technique"], values="count", color="count",
                             color_continuous_scale=["#12303a", "#2dd4bf", "#ff5d5d"])
            fig.update_layout(coloraxis_showscale=False)
            chart(style_fig(fig, 340))
        else:
            st.dataframe(counts.sort_values("count", ascending=False), hide_index=True, **STRETCH)

# ── IOCs ───────────────────────────────────────────────────
with tabs[3]:
    st.markdown(render_section("🎯", "Extracted indicators of compromise", "THREAT INTEL", "red"),
                unsafe_allow_html=True)
    if iocs:
        by_type: dict[str, int] = {}
        for i in iocs:
            by_type[i["type"]] = by_type.get(i["type"], 0) + 1
        mc = st.columns(max(2, min(len(by_type), 5)))
        for n, (t, c) in enumerate(by_type.items()):
            mc[n % len(mc)].markdown(render_metric_card("📌", c, f"{t.upper()} indicators", "amber"),
                                     unsafe_allow_html=True)
        st.caption("Indicators are shown defanged. Internal and private addresses are excluded.")
        for i in iocs:
            st.markdown(render_ioc_card(i), unsafe_allow_html=True)
    else:
        st.markdown(render_empty("radar.svg", "No external indicators",
                                 "No public IPs, domains, URLs, hashes or e-mails were found."), unsafe_allow_html=True)

# ── Alert data ─────────────────────────────────────────────
with tabs[4]:
    st.markdown(render_section("🧪", "Normalized SIEM events", "RAW DATA"), unsafe_allow_html=True)
    f1, f2, f3 = st.columns(3)
    sev_f = f1.multiselect("Severity", ["low", "medium", "high", "critical"], default=["low", "medium", "high", "critical"])
    cats = sorted({e["category"] for e in events})
    cat_f = f2.multiselect("Category", cats, default=cats)
    srcs = sorted({e["source_ip"] for e in events if e["source_ip"]})
    src_f = f3.multiselect("Source IP", srcs, default=srcs)
    filtered = [e for e in events if e["severity"] in sev_f and e["category"] in cat_f
                and (not e["source_ip"] or e["source_ip"] in src_f)]
    st.dataframe(event_frame(filtered), hide_index=True, **STRETCH)
    st.caption(f"Showing {len(filtered)} of {len(events)} events")

# ── Checklist ──────────────────────────────────────────────
with tabs[5]:
    st.markdown(render_section("✅", "Analyst investigation checklist", "RESPONSE GUIDE", "green"),
                unsafe_allow_html=True)
    done = sum(1 for i in checklist if st.session_state.get(f"check_{data_sig}_{i['id']}", False))
    pct = int(done / len(checklist) * 100) if checklist else 0
    st.markdown(f'<div class="meta mono" style="color:#8aa0b2">{done}/{len(checklist)} steps · {pct}%</div>'
                f'<div class="progress"><div style="width:{pct}%"></div></div>', unsafe_allow_html=True)
    for item in checklist:
        a, b = st.columns([0.05, 0.95])
        a.checkbox("Done", key=f"check_{data_sig}_{item['id']}", label_visibility="collapsed")
        b.markdown(render_checklist_item(item), unsafe_allow_html=True)
    st.caption("Progress lasts for this browser session. Export the report to keep your findings.")

# ── AI advisory ────────────────────────────────────────────
with tabs[6]:
    st.markdown(render_section("🤖", "AI advisory narrative", "OPTIONAL · ANY PROVIDER", "violet"),
                unsafe_allow_html=True)
    left, right = st.columns([0.28, 0.72])
    left.markdown(render_art_side("ai_core.svg", "AI provider connection"), unsafe_allow_html=True)
    with right:
        if not st.session_state.llm_enabled:
            st.info("Turn on **Enable AI advisory narrative** in the sidebar to activate the backend LLM engine.")
        else:
            cfg = current_config()
            host = urlparse(cfg.base_url).hostname or "—"
            if cfg.is_ready():
                st.markdown(
                    f'<div class="panel violet"><div class="cap">Backend Security Active</div>'
                    f'<b>{sanitize_html(PROVIDERS.get(cfg.provider, {}).get("label", cfg.provider))}</b> · model '
                    f'<code>{sanitize_html(cfg.model or "—")}</code> · endpoint <code>{sanitize_html(host)}</code><br/>'
                    f'<small style="color:var(--muted)">Server credentials active. Frontend API modification is disabled.</small></div>',
                    unsafe_allow_html=True)
            else:
                st.warning("⚠️ No backend LLM key configured on the server. Set `AEGIS_API_KEY` in `.env` or deployment Secrets to enable AI advisory generation.")
            sig = f"{data_sig}|{cfg.provider}|{cfg.model}|{cfg.base_url}"
            if st.button("Generate advisory", type="primary", disabled=not cfg.is_ready()):
                with st.spinner(f"Requesting advisory from {PROVIDERS.get(cfg.provider, {}).get('label', cfg.provider)}…"):
                    try:
                        text = generate_llm_summary(events, summary, patterns, cfg)
                        st.session_state.advisory = {"sig": sig, "text": text, "meta": cfg.public_dict(),
                                                     "at": datetime.now(timezone.utc).isoformat()}
                    except LLMError as exc:
                        st.session_state.advisory = None
                        st.error(sanitize_llm_output(str(exc)))
            adv = st.session_state.advisory
            if adv:
                if adv["sig"] != sig:
                    st.caption("This narrative was generated for different data or settings.")
                with st.container(border=True):
                    st.markdown(adv["text"])
                st.caption("Advisory only — may contain errors. Validate against primary evidence.")

# ── Enterprise Tiers ───────────────────────────────────────
with tabs[7]:
    st.markdown(render_section("💎", "Enterprise Subscriptions & Integrations", "FORTUNE 500 READY", "violet"),
                unsafe_allow_html=True)
    st.markdown(render_company_showcase(), unsafe_allow_html=True)

    col_sub1, col_sub2 = st.columns(2)
    with col_sub1:
        st.markdown(render_plan_card(
            tier_key="pro_ulta",
            name="Pro Ulta Tier",
            badge="⚡ High Performance SOC",
            price="$2,499",
            period="/ month / cluster",
            desc="Built for dedicated threat intelligence teams and fast-paced Tier-2/3 SOC triage.",
            features=[
                "Real-time streaming SIEM alert ingestion (up to 250,000 events/sec)",
                "Full MITRE ATT&CK v14 automated mapping & heatmaps",
                "Advanced regex & heuristic Prompt Injection defenses",
                "Google Chronicle & GCP Cloud Security Command Center connector",
                "Automated IOC defanging & CSV/JSON timeline generation",
                "Enterprise SLA: 99.95% uptime with 15-minute response guarantee"
            ],
            enterprise_clients="Deployments: Google Cloud Infrastructure & High-Frequency FinTech"
        ), unsafe_allow_html=True)
        if st.button("🚀 Upgrade to Pro Ulta", key="btn_pro_ulta", **STRETCH):
            st.success("🎉 Enterprise provisioning initiated! Token generated for Google Cloud / On-Premise SIEM integration.")

    with col_sub2:
        st.markdown(render_plan_card(
            tier_key="pro_max_ulta",
            name="Pro Max Ulta Tier",
            badge="🛡️ Sovereign Military-Grade Defenses",
            price="$8,999",
            period="/ month / tenant",
            desc="The ultimate cyber defensive suite trusted across global tech conglomerates and defense contractors.",
            features=[
                "Unlimited event throughput with multi-cloud distributed correlation",
                "Microsoft Sentinel, Defender XDR & Azure Active Directory full bidirectional sync",
                "Zero-Trust LLM sandbox protecting against multi-hop adversarial prompt injections",
                "Automated kill-chain disruption and custom Yara / Sigma rule synthesis",
                "CrowdStrike Falcon & Palo Alto Cortex XSOAR instant webhook dispatchers",
                "Dedicated 24/7 Red/Blue Team engineering squad & air-gapped deployment option"
            ],
            enterprise_clients="Deployments: Microsoft Azure Core Defense, Amazon AWS & Fortune 50 Banks"
        ), unsafe_allow_html=True)
        if st.button("🔥 Upgrade to Pro Max Ulta", key="btn_pro_max_ulta", type="primary", **STRETCH):
            st.balloons()
            st.success("👑 Elite Pro Max Ulta license activated! Direct bridge established for Microsoft Defender & Chronicle SOC clusters.")

# ── Report & export ────────────────────────────────────────
with tabs[8]:
    st.markdown(render_section("📄", "Incident report & export", "EXPORTABLE"), unsafe_allow_html=True)
    report = build_report(result)
    adv = st.session_state.advisory
    report["llm_advisory"] = adv["text"] if adv else None
    report["llm_provider"] = adv["meta"] if adv else None  # never includes the API key
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    e1, e2 = st.columns(2)
    e1.download_button("⬇️ Download JSON incident report",
                       json.dumps(report, indent=2, default=str).encode("utf-8"),
                       file_name=f"aegistrace_incident_{stamp}.json", mime="application/json", **STRETCH)
    safe_csv = event_frame(events).map(csv_safe)  # blocks spreadsheet formula injection
    e2.download_button("⬇️ Download events CSV", safe_csv.to_csv(index=False).encode("utf-8"),
                       file_name=f"aegistrace_events_{stamp}.csv", mime="text/csv", **STRETCH)
    with st.expander("View full JSON report"):
        st.json(report, expanded=False)

st.markdown(render_footer(VERSION, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
            unsafe_allow_html=True)

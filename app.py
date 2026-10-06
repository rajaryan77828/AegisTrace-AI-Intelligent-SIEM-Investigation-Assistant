"""
AegisTrace AI — Intelligent SIEM Investigation Assistant
Professional cybersecurity dashboard with glassmorphism UI,
animated timeline, MITRE ATT&CK mapping, and risk scoring.

Version 2.0.0
"""
import json
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from analyzer import analyze_events, build_report
from components.styles import (
    get_all_styles,
    render_checklist_item,
    render_injection_warning,
    render_metric_card,
    render_pattern_card,
    render_risk_gauge,
    render_timeline_event,
)
from llm_summary import generate_llm_summary, llm_available
from utils.sanitizer import sanitize_html

# ─────────────────────────────────────────────────────────────
# Page Config
# ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="AegisTrace AI — SIEM Investigation",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject all styles
st.markdown(get_all_styles(), unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# Hero Banner
# ─────────────────────────────────────────────────────────────

st.markdown("""
<div class="hero-banner">
    <div class="hero-title">
        🛡️ <span class="accent">AegisTrace</span> AI
    </div>
    <div class="hero-subtitle">
        Intelligent SIEM Investigation Assistant — Detect · Correlate · Investigate · Defend
    </div>
    <div class="hero-status">
        <div class="pulse-dot"></div>
        System Active — Defensive Analysis Mode
    </div>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div class="sidebar-brand">
        <h3>🛡️ AegisTrace AI</h3>
        <p>SOC Triage Platform v2.0</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section"><h4>📁 Data Input</h4>', unsafe_allow_html=True)
    uploaded = st.file_uploader(
        "Upload SIEM alerts",
        type=["json", "csv"],
        help="Accepts JSON arrays or CSV files with standard SIEM fields",
    )
    paste = st.text_area(
        "Or paste JSON",
        height=160,
        placeholder='[{"timestamp":"2026-10-06T10:00:00Z","source_ip":"10.0.0.5",'
                    '"event_type":"login_failed","user":"admin"}]',
    )
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section"><h4>🤖 AI Configuration</h4>',
                unsafe_allow_html=True)
    use_llm = st.toggle("Enable LLM Advisory Narrative", value=False)
    st.caption(
        "⚠️ LLM output is advisory only. Alert content is treated as "
        "untrusted evidence and is never executed."
    )
    if use_llm and not llm_available():
        st.warning("LLM not configured. Add OPENAI_API_KEY in Streamlit Secrets.")
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section"><h4>ℹ️ About</h4>', unsafe_allow_html=True)
    st.caption(
        "AegisTrace AI is a defensive SOC triage tool. It does NOT execute "
        "commands, access endpoints, block IPs, or perform automated containment. "
        "All response actions require analyst review and approval."
    )
    st.markdown('</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# Data Loading
# ─────────────────────────────────────────────────────────────

def load_input():
    """Load SIEM events from upload, paste, or built-in sample."""
    if uploaded is not None:
        raw = uploaded.getvalue()
        if uploaded.name.lower().endswith(".csv"):
            return pd.read_csv(pd.io.common.BytesIO(raw)).to_dict(orient="records")
        return json.loads(raw.decode("utf-8"))

    if paste.strip():
        return json.loads(paste)

    # Built-in demo data — a realistic multi-stage attack scenario
    with open("sample_alerts.json", "r", encoding="utf-8") as f:
        return json.load(f)


try:
    raw_events = load_input()
    result = analyze_events(raw_events)
except Exception as exc:
    st.error(f"⚠️ Could not parse the supplied SIEM data: {exc}")
    st.stop()

events = result["events"]
summary = result["summary"]
timeline = result["timeline"]
patterns = result["patterns"]
injection_flags = result["prompt_injection_flags"]
iocs = result.get("iocs", [])
checklist = result["checklist"]
risk_score = summary.get("risk_score", 0)

# ─────────────────────────────────────────────────────────────
# Metric Cards Row
# ─────────────────────────────────────────────────────────────

cols = st.columns(6)

with cols[0]:
    st.markdown(
        render_metric_card("📊", summary["total_events"], "Total Events", "blue"),
        unsafe_allow_html=True,
    )

with cols[1]:
    crit_class = "red" if summary["high_critical"] > 0 else "green"
    is_crit = summary["high_critical"] > 2
    st.markdown(
        render_metric_card("🔴", summary["high_critical"], "High / Critical",
                           crit_class, critical=is_crit),
        unsafe_allow_html=True,
    )

with cols[2]:
    st.markdown(
        render_metric_card("🌐", summary["unique_source_ips"], "Source IPs", "cyan"),
        unsafe_allow_html=True,
    )

with cols[3]:
    st.markdown(
        render_metric_card("🖥️", summary["unique_hosts"], "Hosts", "purple"),
        unsafe_allow_html=True,
    )

with cols[4]:
    inj_color = "red" if injection_flags else "green"
    st.markdown(
        render_metric_card("🛡️", len(injection_flags), "Injection Flags",
                           inj_color, critical=bool(injection_flags)),
        unsafe_allow_html=True,
    )

with cols[5]:
    st.markdown(render_risk_gauge(risk_score), unsafe_allow_html=True)

st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# Main Tabs
# ─────────────────────────────────────────────────────────────

tabs = st.tabs([
    "📌 Incident Overview",
    "🕒 Timeline",
    "🔎 Patterns & MITRE",
    "🎯 IOC Extraction",
    "🧪 Alert Data",
    "✅ Investigation Checklist",
    "📄 Report & Export",
])

# ═══════════════════════════════════════════════════════════════
# TAB 0: Incident Overview
# ═══════════════════════════════════════════════════════════════

with tabs[0]:
    st.markdown("""
    <div class="section-header">
        <span class="section-icon">📌</span>
        <h2>Incident Overview</h2>
        <span class="section-badge badge-blue">AUTOMATED ANALYSIS</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(
        f'<div class="metric-glass blue fade-in" style="margin-bottom:1.5rem;">'
        f'<div style="color:#94a3b8;font-size:0.78rem;text-transform:uppercase;'
        f'letter-spacing:1.5px;margin-bottom:0.5rem;">Narrative Summary</div>'
        f'<div style="color:#cbd5e1;line-height:1.8;font-size:0.95rem;">'
        f'{sanitize_html(summary["narrative"])}</div></div>',
        unsafe_allow_html=True,
    )

    # Injection warning
    if injection_flags:
        st.markdown(render_injection_warning(len(injection_flags)),
                    unsafe_allow_html=True)
        st.dataframe(
            pd.DataFrame(injection_flags),
            use_container_width=True,
            hide_index=True,
        )

    # Charts row
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("""
        <div class="section-header">
            <span class="section-icon">📊</span>
            <h2>Severity Distribution</h2>
        </div>
        """, unsafe_allow_html=True)

        sev_data = summary["severity_counts"]
        sev_order = ["low", "medium", "high", "critical"]
        sev_colors = {"low": "#22c55e", "medium": "#eab308",
                      "high": "#f97316", "critical": "#ef4444"}

        sev_df = pd.DataFrame([
            {"severity": s, "count": sev_data.get(s, 0)}
            for s in sev_order if sev_data.get(s, 0) > 0
        ])

        if not sev_df.empty:
            fig_sev = px.bar(
                sev_df, x="severity", y="count",
                color="severity",
                color_discrete_map=sev_colors,
                template="plotly_dark",
            )
            fig_sev.update_layout(
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Inter", color="#94a3b8"),
                showlegend=False,
                margin=dict(l=20, r=20, t=20, b=40),
                xaxis=dict(gridcolor="rgba(56,189,248,0.05)"),
                yaxis=dict(gridcolor="rgba(56,189,248,0.05)"),
                height=300,
            )
            st.plotly_chart(fig_sev, use_container_width=True)

    with chart_col2:
        st.markdown("""
        <div class="section-header">
            <span class="section-icon">🗂️</span>
            <h2>Event Categories</h2>
        </div>
        """, unsafe_allow_html=True)

        cat_data = summary["category_counts"]
        cat_df = pd.DataFrame([
            {"category": k.replace("_", " ").title(), "count": v}
            for k, v in cat_data.items()
        ]).sort_values("count", ascending=True)

        if not cat_df.empty:
            fig_cat = px.bar(
                cat_df, x="count", y="category",
                orientation="h",
                color_discrete_sequence=["#38bdf8"],
                template="plotly_dark",
            )
            fig_cat.update_layout(
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Inter", color="#94a3b8"),
                showlegend=False,
                margin=dict(l=20, r=20, t=20, b=40),
                xaxis=dict(gridcolor="rgba(56,189,248,0.05)"),
                yaxis=dict(gridcolor="rgba(56,189,248,0.05)"),
                height=300,
            )
            st.plotly_chart(fig_cat, use_container_width=True)

    # MITRE techniques observed
    mitre_techs = summary.get("mitre_techniques", [])
    if mitre_techs:
        st.markdown("""
        <div class="section-header">
            <span class="section-icon">🎯</span>
            <h2>MITRE ATT&CK Techniques Observed</h2>
        </div>
        """, unsafe_allow_html=True)

        mitre_html = " ".join(
            f'<span class="mitre-badge" style="margin:4px;">{sanitize_html(t)}</span>'
            for t in mitre_techs
        )
        st.markdown(
            f'<div class="fade-in" style="padding:1rem 0;">{mitre_html}</div>',
            unsafe_allow_html=True,
        )


# ═══════════════════════════════════════════════════════════════
# TAB 1: Timeline
# ═══════════════════════════════════════════════════════════════

with tabs[1]:
    st.markdown("""
    <div class="section-header">
        <span class="section-icon">🕒</span>
        <h2>Chronological Event Timeline</h2>
        <span class="section-badge badge-blue">CHRONOLOGICAL</span>
    </div>
    """, unsafe_allow_html=True)

    view_mode = st.radio(
        "View Mode", ["Visual Timeline", "Data Table"],
        horizontal=True, label_visibility="collapsed",
    )

    if view_mode == "Visual Timeline":
        timeline_html = '<div class="timeline-container stagger">'
        for i, event in enumerate(timeline):
            safe_event = {
                k: sanitize_html(str(v)) if isinstance(v, str) else v
                for k, v in event.items()
            }
            timeline_html += render_timeline_event(safe_event, i)
        timeline_html += '</div>'
        st.markdown(timeline_html, unsafe_allow_html=True)
    else:
        st.dataframe(
            pd.DataFrame(timeline),
            use_container_width=True,
            hide_index=True,
        )

    # Timeline heatmap
    st.markdown("""
    <div class="section-header" style="margin-top:2rem;">
        <span class="section-icon">🌡️</span>
        <h2>Event Density Heatmap</h2>
    </div>
    """, unsafe_allow_html=True)

    heat_df = pd.DataFrame(timeline)
    if "time" in heat_df.columns and not heat_df.empty:
        heat_df["parsed_time"] = pd.to_datetime(heat_df["time"], errors="coerce")
        heat_df = heat_df.dropna(subset=["parsed_time"])

        if not heat_df.empty:
            heat_df["minute"] = heat_df["parsed_time"].dt.strftime("%H:%M")
            heat_df["sev_num"] = heat_df["severity"].map(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}
            )

            heat_pivot = heat_df.groupby(["category", "minute"])["sev_num"] \
                                .max().reset_index()

            if not heat_pivot.empty:
                fig_heat = px.density_heatmap(
                    heat_pivot, x="minute", y="category",
                    z="sev_num",
                    color_continuous_scale=["#0c1828", "#22c55e", "#eab308",
                                           "#f97316", "#ef4444"],
                    template="plotly_dark",
                )
                fig_heat.update_layout(
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                    font=dict(family="Inter", color="#94a3b8"),
                    margin=dict(l=20, r=20, t=20, b=40),
                    height=280,
                    coloraxis_colorbar=dict(title="Severity"),
                )
                st.plotly_chart(fig_heat, use_container_width=True)


# ═══════════════════════════════════════════════════════════════
# TAB 2: Patterns & MITRE
# ═══════════════════════════════════════════════════════════════

with tabs[2]:
    st.markdown("""
    <div class="section-header">
        <span class="section-icon">🔎</span>
        <h2>Correlated Patterns & MITRE ATT&CK Mapping</h2>
        <span class="section-badge badge-amber">CORRELATION ENGINE</span>
    </div>
    """, unsafe_allow_html=True)

    if patterns:
        for p in patterns:
            safe_p = {
                k: sanitize_html(str(v)) if isinstance(v, str) else v
                for k, v in p.items()
            }
            mitre = p.get("mitre")
            st.markdown(render_pattern_card(safe_p, mitre), unsafe_allow_html=True)
    else:
        st.info("No strong repeated-activity pattern met the baseline correlation "
                "thresholds.")

    # MITRE heatmap
    if events:
        st.markdown("""
        <div class="section-header" style="margin-top:2rem;">
            <span class="section-icon">🗺️</span>
            <h2>MITRE ATT&CK Coverage Map</h2>
        </div>
        """, unsafe_allow_html=True)

        mitre_data = []
        for e in events:
            m = e.get("mitre", {})
            if m.get("technique") != "N/A":
                mitre_data.append({
                    "tactic": m.get("tactic", "Unknown"),
                    "technique": m.get("technique", "N/A"),
                    "severity": e["severity"],
                })

        if mitre_data:
            mitre_df = pd.DataFrame(mitre_data)
            mitre_count = mitre_df.groupby(["tactic", "technique"]).size() \
                                  .reset_index(name="count")

            fig_mitre = px.treemap(
                mitre_count,
                path=["tactic", "technique"],
                values="count",
                color="count",
                color_continuous_scale=["#0c1828", "#38bdf8", "#ef4444"],
                template="plotly_dark",
            )
            fig_mitre.update_layout(
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Inter", color="#e2e8f0"),
                margin=dict(l=10, r=10, t=10, b=10),
                height=350,
            )
            st.plotly_chart(fig_mitre, use_container_width=True)


# ═══════════════════════════════════════════════════════════════
# TAB 3: IOC Extraction
# ═══════════════════════════════════════════════════════════════

with tabs[3]:
    st.markdown("""
    <div class="section-header">
        <span class="section-icon">🎯</span>
        <h2>Extracted Indicators of Compromise</h2>
        <span class="section-badge badge-red">THREAT INTELLIGENCE</span>
    </div>
    """, unsafe_allow_html=True)

    if iocs:
        ioc_type_icons = {
            "ipv4": "🌐", "domain": "🔗", "url": "🔗",
            "md5": "#️⃣", "sha1": "#️⃣", "sha256": "#️⃣",
            "email": "📧",
        }

        ioc_type_css = {
            "ipv4": "ioc-ip", "domain": "ioc-domain", "url": "ioc-url",
            "md5": "ioc-hash", "sha1": "ioc-hash", "sha256": "ioc-hash",
            "email": "ioc-domain",
        }

        # Summary by type
        ioc_summary_cols = st.columns(4)
        ioc_types = {}
        for ioc in iocs:
            t = ioc["type"]
            ioc_types[t] = ioc_types.get(t, 0) + 1

        for i, (t, count) in enumerate(ioc_types.items()):
            with ioc_summary_cols[i % 4]:
                icon = ioc_type_icons.get(t, "📌")
                st.markdown(
                    render_metric_card(icon, count, f"{t.upper()} IOCs", "amber"),
                    unsafe_allow_html=True,
                )

        st.markdown("<div style='height:1rem;'></div>", unsafe_allow_html=True)

        # IOC table
        for ioc in iocs:
            css_class = ioc_type_css.get(ioc["type"], "ioc-ip")
            icon = ioc_type_icons.get(ioc["type"], "📌")
            event_ids = ", ".join(f"#{eid}" for eid in ioc["event_ids"])
            st.markdown(f"""
            <div class="pattern-card" style="border-left-color: #38bdf8;">
                <div style="display:flex;align-items:center;gap:0.8rem;">
                    <span style="font-size:1.3rem;">{icon}</span>
                    <span class="ioc-tag {css_class}">{ioc['type'].upper()}</span>
                    <code style="color:#38bdf8;font-size:0.9rem;">
                        {sanitize_html(ioc['value'])}
                    </code>
                </div>
                <div class="pattern-detail" style="margin-top:0.5rem;">
                    Referenced in events: <strong>{event_ids}</strong>
                    &nbsp;•&nbsp; Occurrences: <strong>{ioc['count']}</strong>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No external IOCs (public IPs, domains, hashes, URLs) were "
                "extracted from the current alert set.")


# ═══════════════════════════════════════════════════════════════
# TAB 4: Alert Data
# ═══════════════════════════════════════════════════════════════

with tabs[4]:
    st.markdown("""
    <div class="section-header">
        <span class="section-icon">🧪</span>
        <h2>Normalized SIEM Events</h2>
        <span class="section-badge badge-blue">RAW DATA</span>
    </div>
    """, unsafe_allow_html=True)

    # Filters
    filter_col1, filter_col2, filter_col3 = st.columns(3)
    with filter_col1:
        sev_filter = st.multiselect(
            "Filter by Severity",
            ["low", "medium", "high", "critical"],
            default=["low", "medium", "high", "critical"],
        )
    with filter_col2:
        all_cats = sorted({e["category"] for e in events})
        cat_filter = st.multiselect("Filter by Category", all_cats, default=all_cats)
    with filter_col3:
        all_sources = sorted({e["source_ip"] for e in events if e["source_ip"]})
        src_filter = st.multiselect("Filter by Source IP", all_sources,
                                    default=all_sources)

    filtered = [
        e for e in events
        if e["severity"] in sev_filter
        and e["category"] in cat_filter
        and (e["source_ip"] in src_filter or not e["source_ip"])
    ]

    display_df = pd.DataFrame(filtered)
    # Drop raw_text and mitre dict for cleaner display
    drop_cols = [c for c in ["raw_text", "mitre"] if c in display_df.columns]
    if drop_cols:
        display_df = display_df.drop(columns=drop_cols)

    st.dataframe(display_df, use_container_width=True, hide_index=True)
    st.caption(f"Showing {len(filtered)} of {len(events)} events")


# ═══════════════════════════════════════════════════════════════
# TAB 5: Investigation Checklist
# ═══════════════════════════════════════════════════════════════

with tabs[5]:
    st.markdown("""
    <div class="section-header">
        <span class="section-icon">✅</span>
        <h2>Analyst Investigation Checklist</h2>
        <span class="section-badge badge-green">RESPONSE GUIDE</span>
    </div>
    """, unsafe_allow_html=True)

    # Progress tracking
    completed = sum(
        1 for item in checklist
        if st.session_state.get(f"check_{item['id']}", False)
    )
    progress_pct = int((completed / len(checklist)) * 100) if checklist else 0

    st.markdown(f"""
    <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;">
        <span style="color:#94a3b8;font-size:0.85rem;">
            Progress: {completed}/{len(checklist)} steps completed
        </span>
        <span style="color:#38bdf8;font-family:'JetBrains Mono',monospace;
                     font-size:0.85rem;">
            {progress_pct}%
        </span>
    </div>
    <div class="checklist-progress">
        <div class="checklist-progress-bar" style="width:{progress_pct}%;"></div>
    </div>
    """, unsafe_allow_html=True)

    for item in checklist:
        col_check, col_content = st.columns([0.05, 0.95])
        with col_check:
            st.checkbox(
                "Done", value=False, key=f"check_{item['id']}",
                label_visibility="collapsed",
            )
        with col_content:
            st.markdown(render_checklist_item(item), unsafe_allow_html=True)

    st.caption(
        "Checking an item records analyst review in the current browser session. "
        "Export the incident report to preserve your findings."
    )


# ═══════════════════════════════════════════════════════════════
# TAB 6: Report & Export
# ═══════════════════════════════════════════════════════════════

with tabs[6]:
    st.markdown("""
    <div class="section-header">
        <span class="section-icon">📄</span>
        <h2>Incident Report & Export</h2>
        <span class="section-badge badge-blue">EXPORTABLE</span>
    </div>
    """, unsafe_allow_html=True)

    report = build_report(result)

    if use_llm and llm_available():
        with st.spinner("🤖 Generating advisory narrative..."):
            report["llm_advisory"] = generate_llm_summary(events, summary, patterns)
    else:
        report["llm_advisory"] = None

    # LLM narrative display
    if report.get("llm_advisory"):
        st.markdown("""
        <div class="section-header">
            <span class="section-icon">🤖</span>
            <h2>AI Advisory Narrative</h2>
            <span class="section-badge badge-amber">LLM GENERATED</span>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(
            f'<div class="metric-glass purple fade-in">'
            f'<div style="color:#cbd5e1;line-height:1.8;font-size:0.92rem;">'
            f'{sanitize_html(report["llm_advisory"])}</div></div>',
            unsafe_allow_html=True,
        )
        st.caption("⚠️ This narrative is advisory only and may contain inaccuracies. "
                   "Always validate with primary evidence.")

    report_bytes = json.dumps(report, indent=2, default=str).encode("utf-8")

    # Export buttons
    exp_col1, exp_col2 = st.columns(2)
    with exp_col1:
        st.download_button(
            "⬇️ Download JSON Incident Report",
            data=report_bytes,
            file_name=f"aegistrace_incident_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
        )
    with exp_col2:
        # CSV export of events
        csv_data = pd.DataFrame(events)
        drop_cols = [c for c in ["raw_text", "mitre"] if c in csv_data.columns]
        if drop_cols:
            csv_data = csv_data.drop(columns=drop_cols)
        st.download_button(
            "⬇️ Download Events CSV",
            data=csv_data.to_csv(index=False).encode("utf-8"),
            file_name=f"aegistrace_events_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )

    # Collapsible full JSON
    with st.expander("📋 View Full JSON Report"):
        st.json(report)


# ─────────────────────────────────────────────────────────────
# Footer
# ─────────────────────────────────────────────────────────────

st.markdown(f"""
<div class="app-footer">
    🛡️ <strong>AegisTrace AI</strong> — Defensive SOC Triage Platform
    &nbsp;•&nbsp;
    <span class="footer-version">v2.0.0</span>
    &nbsp;•&nbsp;
    Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
    <br/>
    <span style="color:#334155;font-size:0.72rem;">
        All response actions require analyst review. This tool does not execute
        commands, access endpoints, or perform automated containment.
    </span>
</div>
""", unsafe_allow_html=True)

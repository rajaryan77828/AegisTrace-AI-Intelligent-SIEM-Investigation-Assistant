"""
AegisTrace AI — Professional Cybersecurity Dashboard Styles
All CSS animations, glassmorphism, scan-line overlays, and component styles.
"""


def get_all_styles() -> str:
    """Return the complete CSS stylesheet for the AegisTrace AI dashboard."""
    return """
<style>
/* ═══════════════════════════════════════════════════════════════
   GLOBAL & BACKGROUND
   ═══════════════════════════════════════════════════════════════ */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap');

[data-testid="stAppViewContainer"] {
    background: #060d18;
    background-image:
        radial-gradient(ellipse at 20% 50%, rgba(56,189,248,0.03) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 20%, rgba(14,165,233,0.03) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 80%, rgba(2,132,199,0.02) 0%, transparent 50%);
}

[data-testid="stAppViewContainer"]::before {
    content: "";
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(56,189,248,0.015) 2px,
        rgba(56,189,248,0.015) 4px
    );
    pointer-events: none;
    z-index: 0;
    animation: scanlines 8s linear infinite;
}

@keyframes scanlines {
    0% { transform: translateY(0); }
    100% { transform: translateY(4px); }
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #070e1a 0%, #0a1628 100%);
    border-right: 1px solid rgba(56,189,248,0.1);
}

[data-testid="stSidebar"]::before {
    content: "";
    position: absolute;
    top: 0; right: 0;
    width: 1px; height: 100%;
    background: linear-gradient(180deg, transparent, rgba(56,189,248,0.3), transparent);
    animation: sidebarGlow 4s ease-in-out infinite;
}

@keyframes sidebarGlow {
    0%, 100% { opacity: 0.3; }
    50% { opacity: 1; }
}

.block-container {
    max-width: 1500px;
    padding-top: 1.5rem;
}

* {
    font-family: 'Inter', sans-serif;
}

code, pre, .stCode, [data-testid="stCode"] {
    font-family: 'JetBrains Mono', monospace !important;
}

/* ═══════════════════════════════════════════════════════════════
   HERO BANNER
   ═══════════════════════════════════════════════════════════════ */
.hero-banner {
    position: relative;
    padding: 2rem 2.5rem;
    border: 1px solid rgba(56,189,248,0.15);
    border-radius: 20px;
    background: linear-gradient(135deg,
        rgba(6,13,24,0.95) 0%,
        rgba(10,22,40,0.95) 50%,
        rgba(6,13,24,0.95) 100%);
    backdrop-filter: blur(20px);
    margin-bottom: 1.5rem;
    overflow: hidden;
}

.hero-banner::before {
    content: "";
    position: absolute;
    top: -50%; left: -50%;
    width: 200%; height: 200%;
    background: conic-gradient(
        from 0deg,
        transparent 0deg,
        rgba(56,189,248,0.05) 60deg,
        transparent 120deg
    );
    animation: radarSweep 6s linear infinite;
    pointer-events: none;
}

@keyframes radarSweep {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

.hero-banner::after {
    content: "";
    position: absolute;
    bottom: 0; left: 0;
    width: 100%; height: 1px;
    background: linear-gradient(90deg, transparent, rgba(56,189,248,0.5), transparent);
    animation: heroLine 3s ease-in-out infinite;
}

@keyframes heroLine {
    0%, 100% { opacity: 0.3; transform: scaleX(0.5); }
    50% { opacity: 1; transform: scaleX(1); }
}

.hero-title {
    font-size: 2.8rem;
    font-weight: 700;
    color: #e2e8f0;
    margin: 0;
    position: relative;
    z-index: 1;
    letter-spacing: -0.5px;
}

.hero-title .accent {
    background: linear-gradient(135deg, #38bdf8, #0ea5e9, #06b6d4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.hero-subtitle {
    color: #64748b;
    font-size: 1.05rem;
    margin: 0.5rem 0 0;
    position: relative;
    z-index: 1;
    font-weight: 400;
    letter-spacing: 2px;
    text-transform: uppercase;
}

.hero-status {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(34,197,94,0.1);
    border: 1px solid rgba(34,197,94,0.2);
    border-radius: 20px;
    padding: 4px 14px;
    font-size: 0.78rem;
    color: #4ade80;
    margin-top: 1rem;
    position: relative;
    z-index: 1;
}

.hero-status .pulse-dot {
    width: 8px; height: 8px;
    background: #4ade80;
    border-radius: 50%;
    animation: statusPulse 2s ease-in-out infinite;
}

@keyframes statusPulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(0.8); }
}

/* ═══════════════════════════════════════════════════════════════
   METRIC CARDS — GLASSMORPHISM
   ═══════════════════════════════════════════════════════════════ */
.metric-glass {
    position: relative;
    padding: 1.3rem 1.5rem;
    border-radius: 16px;
    background: rgba(15,23,42,0.6);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(56,189,248,0.1);
    overflow: hidden;
    transition: all 0.3s ease;
}

.metric-glass:hover {
    border-color: rgba(56,189,248,0.3);
    transform: translateY(-2px);
    box-shadow: 0 8px 32px rgba(56,189,248,0.1);
}

.metric-glass::before {
    content: "";
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 3px;
    border-radius: 16px 16px 0 0;
}

.metric-glass.blue::before { background: linear-gradient(90deg, #38bdf8, #0ea5e9); }
.metric-glass.red::before { background: linear-gradient(90deg, #ef4444, #dc2626); }
.metric-glass.amber::before { background: linear-gradient(90deg, #f59e0b, #d97706); }
.metric-glass.purple::before { background: linear-gradient(90deg, #a855f7, #9333ea); }
.metric-glass.green::before { background: linear-gradient(90deg, #22c55e, #16a34a); }
.metric-glass.cyan::before { background: linear-gradient(90deg, #06b6d4, #0891b2); }

.metric-icon {
    font-size: 1.8rem;
    margin-bottom: 0.5rem;
}

.metric-value {
    font-size: 2.2rem;
    font-weight: 700;
    color: #f1f5f9;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
}

.metric-label {
    color: #64748b;
    font-size: 0.82rem;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-top: 0.4rem;
    font-weight: 500;
}

/* Critical pulse animation */
.metric-glass.critical-pulse {
    animation: criticalPulse 2s ease-in-out infinite;
}

@keyframes criticalPulse {
    0%, 100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
    50% { box-shadow: 0 0 20px 4px rgba(239,68,68,0.15); }
}

/* ═══════════════════════════════════════════════════════════════
   RISK GAUGE
   ═══════════════════════════════════════════════════════════════ */
.risk-gauge-container {
    text-align: center;
    padding: 1.5rem;
    background: rgba(15,23,42,0.6);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(56,189,248,0.1);
    border-radius: 16px;
}

.risk-gauge {
    position: relative;
    width: 180px; height: 100px;
    margin: 0 auto;
    overflow: hidden;
}

.risk-gauge-bg {
    width: 180px; height: 180px;
    border-radius: 50%;
    background: conic-gradient(
        from 180deg,
        #22c55e 0deg,
        #eab308 72deg,
        #f97316 126deg,
        #ef4444 162deg,
        #dc2626 180deg,
        transparent 180deg
    );
    mask: radial-gradient(circle at center, transparent 55px, black 56px);
    -webkit-mask: radial-gradient(circle at center, transparent 55px, black 56px);
}

.risk-label {
    font-size: 0.85rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-top: 0.8rem;
}

.risk-score {
    font-size: 2.5rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    margin-top: -2.5rem;
    position: relative;
    z-index: 2;
}

.risk-score.low { color: #22c55e; }
.risk-score.medium { color: #eab308; }
.risk-score.high { color: #f97316; }
.risk-score.critical { color: #ef4444; }

/* ═══════════════════════════════════════════════════════════════
   TIMELINE VISUALIZATION
   ═══════════════════════════════════════════════════════════════ */
.timeline-container {
    position: relative;
    padding: 1rem 0 1rem 2.5rem;
}

.timeline-container::before {
    content: "";
    position: absolute;
    left: 16px; top: 0;
    width: 2px; height: 100%;
    background: linear-gradient(180deg, rgba(56,189,248,0.3), rgba(56,189,248,0.05));
}

.timeline-event {
    position: relative;
    padding: 1rem 1.5rem;
    margin-bottom: 1rem;
    background: rgba(15,23,42,0.5);
    backdrop-filter: blur(8px);
    border: 1px solid rgba(56,189,248,0.08);
    border-radius: 12px;
    border-left: 3px solid;
    transition: all 0.3s ease;
    animation: fadeSlideIn 0.5s ease-out forwards;
    opacity: 0;
}

.timeline-event:hover {
    background: rgba(15,23,42,0.8);
    transform: translateX(4px);
}

@keyframes fadeSlideIn {
    from { opacity: 0; transform: translateX(-10px); }
    to { opacity: 1; transform: translateX(0); }
}

.timeline-event::before {
    content: "";
    position: absolute;
    left: -2.05rem; top: 1.4rem;
    width: 12px; height: 12px;
    border-radius: 50%;
    border: 2px solid;
    z-index: 2;
}

.timeline-event.sev-critical { border-left-color: #ef4444; }
.timeline-event.sev-critical::before { background: #ef4444; border-color: #ef4444; box-shadow: 0 0 10px rgba(239,68,68,0.5); }

.timeline-event.sev-high { border-left-color: #f97316; }
.timeline-event.sev-high::before { background: #f97316; border-color: #f97316; box-shadow: 0 0 10px rgba(249,115,22,0.5); }

.timeline-event.sev-medium { border-left-color: #eab308; }
.timeline-event.sev-medium::before { background: #eab308; border-color: #eab308; }

.timeline-event.sev-low { border-left-color: #22c55e; }
.timeline-event.sev-low::before { background: #22c55e; border-color: #22c55e; }

.timeline-time {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: #38bdf8;
    margin-bottom: 0.3rem;
}

.timeline-category {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 6px;
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-right: 0.5rem;
}

.timeline-msg {
    color: #cbd5e1;
    font-size: 0.9rem;
    margin-top: 0.4rem;
    line-height: 1.5;
}

.timeline-meta {
    display: flex;
    gap: 1rem;
    margin-top: 0.5rem;
    flex-wrap: wrap;
}

.timeline-meta-item {
    font-size: 0.75rem;
    color: #475569;
    font-family: 'JetBrains Mono', monospace;
}

.timeline-meta-item span {
    color: #94a3b8;
}

/* Category badge colors */
.cat-authentication_failure { background: rgba(239,68,68,0.15); color: #fca5a5; }
.cat-authentication_success { background: rgba(34,197,94,0.15); color: #86efac; }
.cat-malware { background: rgba(168,85,247,0.15); color: #d8b4fe; }
.cat-suspicious_process { background: rgba(249,115,22,0.15); color: #fdba74; }
.cat-network_connection { background: rgba(56,189,248,0.15); color: #7dd3fc; }
.cat-privilege_change { background: rgba(236,72,153,0.15); color: #f9a8d4; }
.cat-dns_activity { background: rgba(6,182,212,0.15); color: #67e8f9; }
.cat-data_movement { background: rgba(234,179,8,0.15); color: #fde047; }
.cat-security_detection { background: rgba(239,68,68,0.15); color: #fca5a5; }
.cat-other { background: rgba(100,116,139,0.15); color: #94a3b8; }

/* ═══════════════════════════════════════════════════════════════
   SECTION HEADERS
   ═══════════════════════════════════════════════════════════════ */
.section-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 1.2rem;
    padding-bottom: 0.8rem;
    border-bottom: 1px solid rgba(56,189,248,0.1);
}

.section-header h2 {
    margin: 0;
    font-size: 1.4rem;
    font-weight: 600;
    color: #e2e8f0;
}

.section-header .section-icon {
    font-size: 1.5rem;
}

.section-badge {
    display: inline-flex;
    align-items: center;
    padding: 3px 12px;
    border-radius: 20px;
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-left: auto;
}

.badge-red { background: rgba(239,68,68,0.15); color: #fca5a5; border: 1px solid rgba(239,68,68,0.2); }
.badge-green { background: rgba(34,197,94,0.15); color: #86efac; border: 1px solid rgba(34,197,94,0.2); }
.badge-amber { background: rgba(245,158,11,0.15); color: #fcd34d; border: 1px solid rgba(245,158,11,0.2); }
.badge-blue { background: rgba(56,189,248,0.15); color: #7dd3fc; border: 1px solid rgba(56,189,248,0.2); }

/* ═══════════════════════════════════════════════════════════════
   INJECTION WARNING BOX
   ═══════════════════════════════════════════════════════════════ */
.injection-warning {
    position: relative;
    padding: 1.2rem 1.5rem;
    border-radius: 12px;
    background: rgba(239,68,68,0.05);
    border: 1px solid rgba(239,68,68,0.2);
    margin: 1rem 0;
    overflow: hidden;
}

.injection-warning::before {
    content: "";
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: linear-gradient(90deg,
        transparent 0%,
        rgba(239,68,68,0.03) 50%,
        transparent 100%);
    animation: warningWave 3s ease-in-out infinite;
    pointer-events: none;
}

@keyframes warningWave {
    0% { transform: translateX(-100%); }
    100% { transform: translateX(100%); }
}

.injection-warning h4 {
    color: #fca5a5;
    margin: 0 0 0.5rem;
    font-size: 1rem;
}

.injection-warning p {
    color: #94a3b8;
    font-size: 0.88rem;
    margin: 0;
    line-height: 1.5;
}

/* ═══════════════════════════════════════════════════════════════
   CHECKLIST
   ═══════════════════════════════════════════════════════════════ */
.checklist-item {
    display: flex;
    align-items: flex-start;
    gap: 1rem;
    padding: 1rem 1.2rem;
    margin-bottom: 0.6rem;
    background: rgba(15,23,42,0.5);
    border: 1px solid rgba(56,189,248,0.06);
    border-radius: 10px;
    transition: all 0.3s ease;
}

.checklist-item:hover {
    background: rgba(15,23,42,0.8);
    border-color: rgba(56,189,248,0.15);
}

.checklist-num {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px; height: 28px;
    min-width: 28px;
    border-radius: 8px;
    background: rgba(56,189,248,0.1);
    color: #38bdf8;
    font-size: 0.78rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
}

.checklist-content h4 {
    margin: 0;
    font-size: 0.92rem;
    color: #e2e8f0;
    font-weight: 600;
}

.checklist-content p {
    margin: 0.3rem 0 0;
    font-size: 0.82rem;
    color: #64748b;
    line-height: 1.5;
}

.checklist-progress {
    width: 100%;
    height: 6px;
    background: rgba(56,189,248,0.1);
    border-radius: 3px;
    overflow: hidden;
    margin: 1rem 0;
}

.checklist-progress-bar {
    height: 100%;
    background: linear-gradient(90deg, #38bdf8, #06b6d4);
    border-radius: 3px;
    transition: width 0.5s ease;
}

/* ═══════════════════════════════════════════════════════════════
   PATTERN / MITRE CARDS
   ═══════════════════════════════════════════════════════════════ */
.pattern-card {
    padding: 1.2rem 1.5rem;
    background: rgba(15,23,42,0.5);
    border: 1px solid rgba(56,189,248,0.08);
    border-radius: 12px;
    margin-bottom: 0.8rem;
    border-left: 3px solid #f59e0b;
    transition: all 0.3s ease;
}

.pattern-card:hover {
    background: rgba(15,23,42,0.8);
    transform: translateX(3px);
}

.pattern-card h4 {
    margin: 0 0 0.4rem;
    color: #e2e8f0;
    font-size: 0.95rem;
}

.pattern-card .pattern-detail {
    color: #64748b;
    font-size: 0.82rem;
    line-height: 1.5;
}

.pattern-card .indicator {
    font-family: 'JetBrains Mono', monospace;
    color: #38bdf8;
    font-size: 0.82rem;
}

.mitre-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 0.7rem;
    font-weight: 600;
    background: rgba(168,85,247,0.15);
    color: #d8b4fe;
    border: 1px solid rgba(168,85,247,0.2);
    margin-top: 0.5rem;
}

/* ═══════════════════════════════════════════════════════════════
   IOC TABLE
   ═══════════════════════════════════════════════════════════════ */
.ioc-tag {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.72rem;
    font-family: 'JetBrains Mono', monospace;
    margin: 2px;
}

.ioc-ip { background: rgba(56,189,248,0.1); color: #7dd3fc; border: 1px solid rgba(56,189,248,0.15); }
.ioc-domain { background: rgba(168,85,247,0.1); color: #d8b4fe; border: 1px solid rgba(168,85,247,0.15); }
.ioc-hash { background: rgba(249,115,22,0.1); color: #fdba74; border: 1px solid rgba(249,115,22,0.15); }
.ioc-url { background: rgba(34,197,94,0.1); color: #86efac; border: 1px solid rgba(34,197,94,0.15); }

/* ═══════════════════════════════════════════════════════════════
   TABS OVERRIDE
   ═══════════════════════════════════════════════════════════════ */
.stTabs [data-baseweb="tab-list"] {
    gap: 4px;
    background: rgba(15,23,42,0.5);
    border-radius: 12px;
    padding: 4px;
    border: 1px solid rgba(56,189,248,0.08);
}

.stTabs [data-baseweb="tab"] {
    border-radius: 8px;
    color: #64748b;
    font-weight: 500;
    font-size: 0.85rem;
    padding: 0.6rem 1.2rem;
    transition: all 0.3s ease;
}

.stTabs [data-baseweb="tab"]:hover {
    color: #cbd5e1;
    background: rgba(56,189,248,0.05);
}

.stTabs [aria-selected="true"] {
    background: rgba(56,189,248,0.1) !important;
    color: #38bdf8 !important;
    border-bottom: none !important;
}

.stTabs [data-baseweb="tab-highlight"] {
    display: none;
}

/* ═══════════════════════════════════════════════════════════════
   DATAFRAME OVERRIDE
   ═══════════════════════════════════════════════════════════════ */
[data-testid="stDataFrame"] {
    border: 1px solid rgba(56,189,248,0.08);
    border-radius: 12px;
    overflow: hidden;
}

/* ═══════════════════════════════════════════════════════════════
   SIDEBAR ENHANCEMENTS
   ═══════════════════════════════════════════════════════════════ */
.sidebar-brand {
    text-align: center;
    padding: 1rem 0 1.5rem;
    border-bottom: 1px solid rgba(56,189,248,0.1);
    margin-bottom: 1.5rem;
}

.sidebar-brand h3 {
    color: #e2e8f0;
    font-size: 1.1rem;
    margin: 0.5rem 0 0;
}

.sidebar-brand p {
    color: #475569;
    font-size: 0.75rem;
    margin: 0;
    letter-spacing: 1px;
    text-transform: uppercase;
}

.sidebar-section {
    background: rgba(15,23,42,0.4);
    border: 1px solid rgba(56,189,248,0.06);
    border-radius: 10px;
    padding: 1rem;
    margin-bottom: 1rem;
}

.sidebar-section h4 {
    color: #94a3b8;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin: 0 0 0.8rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid rgba(56,189,248,0.06);
}

/* ═══════════════════════════════════════════════════════════════
   FOOTER
   ═══════════════════════════════════════════════════════════════ */
.app-footer {
    text-align: center;
    padding: 1.5rem 0 1rem;
    border-top: 1px solid rgba(56,189,248,0.08);
    margin-top: 2rem;
    color: #334155;
    font-size: 0.78rem;
    letter-spacing: 0.5px;
}

.app-footer a {
    color: #38bdf8;
    text-decoration: none;
}

.app-footer .footer-version {
    font-family: 'JetBrains Mono', monospace;
    color: #475569;
}

/* ═══════════════════════════════════════════════════════════════
   DOWNLOAD BUTTON OVERRIDE
   ═══════════════════════════════════════════════════════════════ */
.stDownloadButton button {
    background: linear-gradient(135deg, rgba(56,189,248,0.15), rgba(14,165,233,0.1)) !important;
    border: 1px solid rgba(56,189,248,0.2) !important;
    color: #38bdf8 !important;
    border-radius: 10px !important;
    font-weight: 600 !important;
    transition: all 0.3s ease !important;
}

.stDownloadButton button:hover {
    background: linear-gradient(135deg, rgba(56,189,248,0.25), rgba(14,165,233,0.2)) !important;
    border-color: rgba(56,189,248,0.4) !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 20px rgba(56,189,248,0.15) !important;
}

/* ═══════════════════════════════════════════════════════════════
   SCROLLBAR
   ═══════════════════════════════════════════════════════════════ */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0a1628; }
::-webkit-scrollbar-thumb { background: rgba(56,189,248,0.2); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(56,189,248,0.4); }

/* ═══════════════════════════════════════════════════════════════
   ANIMATION UTILITIES
   ═══════════════════════════════════════════════════════════════ */
.fade-in {
    animation: fadeIn 0.6s ease-out forwards;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.slide-up {
    animation: slideUp 0.5s ease-out forwards;
}

@keyframes slideUp {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
}

/* Stagger children */
.stagger > * { opacity: 0; animation: fadeSlideIn 0.4s ease-out forwards; }
.stagger > *:nth-child(1) { animation-delay: 0.05s; }
.stagger > *:nth-child(2) { animation-delay: 0.1s; }
.stagger > *:nth-child(3) { animation-delay: 0.15s; }
.stagger > *:nth-child(4) { animation-delay: 0.2s; }
.stagger > *:nth-child(5) { animation-delay: 0.25s; }
.stagger > *:nth-child(6) { animation-delay: 0.3s; }
.stagger > *:nth-child(7) { animation-delay: 0.35s; }
.stagger > *:nth-child(8) { animation-delay: 0.4s; }
.stagger > *:nth-child(9) { animation-delay: 0.45s; }
.stagger > *:nth-child(10) { animation-delay: 0.5s; }

/* Typing cursor for LLM output */
.typing-cursor::after {
    content: "▊";
    animation: blink 1s step-end infinite;
    color: #38bdf8;
}

@keyframes blink {
    50% { opacity: 0; }
}
</style>
"""


def render_metric_card(icon: str, value, label: str, color: str = "blue",
                       critical: bool = False) -> str:
    """Render a glassmorphism metric card."""
    pulse = " critical-pulse" if critical else ""
    return f"""
    <div class="metric-glass {color}{pulse} fade-in">
        <div class="metric-icon">{icon}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-label">{label}</div>
    </div>
    """


def render_timeline_event(event: dict, index: int) -> str:
    """Render a single timeline event node."""
    sev = event.get("severity", "low")
    cat = event.get("category", "other")
    time_str = event.get("time", "Unknown")
    msg = event.get("message", "")
    src = event.get("source_ip", "")
    user = event.get("user", "")
    host = event.get("host", "")
    eid = event.get("event_id", "")

    meta_parts = []
    if src:
        meta_parts.append(f'<span class="timeline-meta-item">SRC: <span>{src}</span></span>')
    if user:
        meta_parts.append(f'<span class="timeline-meta-item">USER: <span>{user}</span></span>')
    if host:
        meta_parts.append(f'<span class="timeline-meta-item">HOST: <span>{host}</span></span>')
    if eid:
        meta_parts.append(f'<span class="timeline-meta-item">ID: <span>#{eid}</span></span>')

    meta_html = "\n".join(meta_parts)

    return f"""
    <div class="timeline-event sev-{sev}" style="animation-delay: {index * 0.08}s;">
        <div class="timeline-time">{time_str}</div>
        <span class="timeline-category cat-{cat}">{cat.replace('_', ' ')}</span>
        <span class="timeline-category" style="background:rgba(100,116,139,0.1);color:#64748b;">
            {sev.upper()}
        </span>
        <div class="timeline-msg">{msg}</div>
        <div class="timeline-meta">{meta_html}</div>
    </div>
    """


def render_risk_gauge(score: int) -> str:
    """Render an animated risk gauge."""
    if score <= 25:
        level = "low"
        label = "LOW RISK"
    elif score <= 50:
        level = "medium"
        label = "MEDIUM RISK"
    elif score <= 75:
        level = "high"
        label = "HIGH RISK"
    else:
        level = "critical"
        label = "CRITICAL RISK"

    needle_deg = 180 + (score / 100) * 180

    return f"""
    <div class="risk-gauge-container fade-in">
        <div class="risk-gauge">
            <div class="risk-gauge-bg"></div>
            <div style="position:absolute; top:50%; left:50%;
                        width:60px; height:2px;
                        background: linear-gradient(90deg, transparent, #e2e8f0);
                        transform-origin: left center;
                        transform: rotate({needle_deg}deg);
                        transition: transform 1.5s cubic-bezier(0.34, 1.56, 0.64, 1);
                        z-index:3;">
            </div>
        </div>
        <div class="risk-score {level}">{score}</div>
        <div class="risk-label">{label}</div>
    </div>
    """


def render_checklist_item(item: dict) -> str:
    """Render a styled checklist item."""
    return f"""
    <div class="checklist-item">
        <div class="checklist-num">{item['id']:02d}</div>
        <div class="checklist-content">
            <h4>{item['step']}</h4>
            <p>{item['guidance']}</p>
        </div>
    </div>
    """


def render_pattern_card(pattern: dict, mitre: dict | None = None) -> str:
    """Render a correlated pattern card with optional MITRE badge."""
    mitre_html = ""
    if mitre:
        mitre_html = f"""
        <span class="mitre-badge">{mitre.get('technique', 'N/A')}</span>
        """

    return f"""
    <div class="pattern-card">
        <h4>⚡ {pattern['pattern']}</h4>
        <div class="pattern-detail">
            Indicator: <span class="indicator">{pattern['indicator']}</span>
            &nbsp;•&nbsp; Count: <strong>{pattern['count']}</strong>
        </div>
        <div class="pattern-detail">{pattern['assessment']}</div>
        {mitre_html}
    </div>
    """


def render_injection_warning(count: int) -> str:
    """Render the prompt injection warning banner."""
    return f"""
    <div class="injection-warning">
        <h4>⚠️ Prompt-Injection Attempt Detected — {count} Flag(s)</h4>
        <p>
            Instruction-like text was found inside SIEM alert fields.
            This content is treated as <strong>untrusted evidence</strong>.
            The system does not follow, execute, or relay instructions embedded in alerts.
        </p>
    </div>
    """

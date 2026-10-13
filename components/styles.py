"""CSS and HTML renderers for the AegisTrace console.

Rule: every dynamic value is escaped with ``sanitize_html`` *here*, once, so
callers pass raw values and nothing is double-escaped.
"""
from __future__ import annotations

from components.assets import img, svg_data_uri
from utils.sanitizer import sanitize_html as esc

SEV_COLOR = {"low": "#4ade80", "medium": "#fbbf24", "high": "#ff9f43", "critical": "#ff5d5d"}

_CSS = """
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');
:root{
  --ink:#0a1016; --panel:#111a23; --panel2:#0e1720; --line:#1f2e3b; --text:#d6e0ea; --muted:#8aa0b2;
  --teal:#2dd4bf; --sky:#38bdf8; --amber:#fbbf24; --red:#ff5d5d; --orange:#ff9f43; --green:#4ade80; --violet:#a78bfa;
  --mono:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
  --sans:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',sans-serif;
}
html,body,[class*="css"],.stApp{font-family:var(--sans)!important}
.stApp{background:radial-gradient(1200px 500px at 85% -10%,rgba(45,212,191,.08),transparent 60%),var(--ink);color:var(--text)}
header[data-testid="stHeader"]{background:transparent}
.block-container{padding-top:1.4rem;max-width:1400px}
h1,h2,h3,h4{letter-spacing:-.01em}
code,pre,.mono{font-family:var(--mono)!important}

/* sidebar */
section[data-testid="stSidebar"]{background:var(--panel2);border-right:1px solid var(--line)}
section[data-testid="stSidebar"] .block-container{padding-top:1rem}
.side-brand{display:flex;align-items:center;gap:.7rem;padding:.2rem 0 1rem;border-bottom:1px solid var(--line);margin-bottom:.8rem}
.side-brand img{width:42px;height:42px}
.side-brand b{display:block;font-size:1.05rem;color:#fff}
.side-brand span{font-size:.74rem;color:var(--muted)}
.side-h{font-size:.8rem;font-weight:600;color:var(--muted);margin:1.1rem 0 .3rem;padding-top:.7rem;border-top:1px solid var(--line)}

/* hero */
.hero{position:relative;overflow:hidden;border:1px solid var(--line);border-radius:14px;
  background:linear-gradient(100deg,#0d1822 35%,rgba(13,24,34,.55)),var(--panel);padding:1.7rem 2rem;margin-bottom:1.1rem;min-height:170px}
.hero .art{position:absolute;right:0;top:0;height:100%;width:68%;opacity:.95;pointer-events:none;
  -webkit-mask-image:linear-gradient(90deg,transparent,#000 35%);mask-image:linear-gradient(90deg,transparent,#000 35%)}
.hero .art img{width:100%;height:100%;object-fit:cover;object-position:right center}
.hero-body{position:relative;z-index:1;max-width:560px}
.hero-title{display:flex;align-items:center;gap:.8rem;font-size:2.15rem;font-weight:700;color:#fff;line-height:1.1}
.hero-title img{width:52px;height:52px}
.hero-sub{color:var(--muted);margin:.7rem 0 1rem;font-size:1rem;line-height:1.5}
.status{display:inline-flex;align-items:center;gap:.55rem;font:500 .78rem var(--mono);color:var(--teal);
  border:1px solid rgba(45,212,191,.35);border-radius:999px;padding:.28rem .8rem;background:rgba(45,212,191,.07)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--teal);box-shadow:0 0 0 0 rgba(45,212,191,.7);animation:pulse 2s infinite}
.status.warn{color:var(--amber);border-color:rgba(251,191,36,.35);background:rgba(251,191,36,.07)}
.status.warn .dot{background:var(--amber)}
@keyframes pulse{70%{box-shadow:0 0 0 9px rgba(45,212,191,0)}100%{box-shadow:0 0 0 0 rgba(45,212,191,0)}}

/* metric cards */
.metric{background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--c,var(--sky));border-radius:10px;
  padding:.9rem 1rem;height:100%;min-height:104px}
.metric .v{font:600 2rem var(--mono);color:#fff;line-height:1.1}
.metric .l{color:var(--muted);font-size:.8rem;margin-top:.25rem}
.metric .i{float:right;font-size:1.15rem;opacity:.8}
.metric.crit{animation:alarm 2.4s ease-in-out infinite}
@keyframes alarm{50%{box-shadow:0 0 0 1px rgba(255,93,93,.55),0 0 22px rgba(255,93,93,.18)}}
.gauge{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:.35rem .5rem .6rem;text-align:center;min-height:104px}
.gauge img{width:100%;max-width:210px;display:block;margin:0 auto}

/* sections */
.sec{display:flex;align-items:center;gap:.7rem;margin:1.2rem 0 .8rem;padding-bottom:.55rem;border-bottom:1px solid var(--line)}
.sec h2{font-size:1.15rem;font-weight:600;margin:0;color:#fff;padding:0}
.sec .ic{font-size:1.2rem}
.tag{margin-left:auto;font:500 .7rem var(--mono);color:var(--sky);border:1px solid rgba(56,189,248,.35);border-radius:6px;padding:.15rem .5rem}
.tag.amber{color:var(--amber);border-color:rgba(251,191,36,.4)}.tag.red{color:var(--red);border-color:rgba(255,93,93,.4)}
.tag.green{color:var(--green);border-color:rgba(74,222,128,.4)}.tag.violet{color:var(--violet);border-color:rgba(167,139,250,.4)}

.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:1.1rem 1.25rem;line-height:1.75;color:#c8d4df}
.panel .cap{color:var(--muted);font-size:.78rem;margin-bottom:.4rem}
.panel.violet{border-left:3px solid var(--violet)}.panel.blue{border-left:3px solid var(--sky)}

/* timeline */
.tl{position:relative;margin:.4rem 0 0 .6rem;padding-left:1.6rem;border-left:2px solid var(--line)}
.tl-item{position:relative;margin-bottom:.7rem;background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--c);
  border-radius:8px;padding:.65rem .9rem;animation:slide .45s ease both;animation-delay:calc(var(--i)*40ms)}
.tl-item::before{content:"";position:absolute;left:calc(-1.6rem - 7px);top:1rem;width:12px;height:12px;border-radius:50%;
  background:var(--c);border:2px solid var(--ink);box-shadow:0 0 10px var(--c)}
.tl-top{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center;font:500 .75rem var(--mono);color:var(--muted)}
.tl-msg{margin-top:.3rem;color:#dbe5ee;font-size:.9rem;word-break:break-word}
.sev{font:600 .68rem var(--mono);color:var(--c);border:1px solid var(--c);border-radius:5px;padding:.05rem .4rem;text-transform:uppercase}
.mitre{font:500 .72rem var(--mono);color:var(--sky);background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.28);border-radius:5px;padding:.08rem .45rem}
@keyframes slide{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:none}}

/* pattern / ioc / checklist cards */
.card{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--c,var(--amber));border-radius:8px;padding:.85rem 1.05rem;margin-bottom:.65rem}
.card h4{margin:0 0 .25rem;font-size:.98rem;color:#fff}
.card .meta{font:500 .76rem var(--mono);color:var(--muted)}
.card .body{color:#b9c7d3;font-size:.9rem;margin-top:.35rem}
.ioc{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap}
.ioc code{color:var(--teal);font-size:.88rem}
.chip{font:600 .68rem var(--mono);border-radius:5px;padding:.1rem .45rem;border:1px solid var(--line);color:var(--muted)}
.chip.ip{color:var(--sky);border-color:rgba(56,189,248,.4)}.chip.domain{color:var(--violet);border-color:rgba(167,139,250,.4)}
.chip.hash{color:var(--amber);border-color:rgba(251,191,36,.4)}.chip.url,.chip.email{color:var(--orange);border-color:rgba(255,159,67,.4)}
.alert{border:1px solid rgba(255,93,93,.45);background:rgba(255,93,93,.08);border-radius:10px;padding:.9rem 1.1rem;margin:.6rem 0 1rem;color:#ffd6d6}
.alert b{color:#fff}
.progress{height:6px;background:var(--line);border-radius:999px;overflow:hidden;margin:.3rem 0 1rem}
.progress>div{height:100%;background:linear-gradient(90deg,var(--teal),var(--sky));transition:width .5s ease}
.empty{display:flex;gap:1.2rem;align-items:center;border:1px dashed var(--line);border-radius:12px;padding:1.2rem 1.5rem;color:var(--muted)}
.empty img{width:120px;flex:none}
.art-side{display:flex;justify-content:center}
.art-side img{width:100%;max-width:220px}
.footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--line);text-align:center;color:var(--muted);font-size:.8rem}
.footer small{display:block;margin-top:.3rem;color:#4b6173;font-size:.72rem}

/* Streamlit widgets */
.stTabs [data-baseweb="tab-list"]{gap:.25rem;border-bottom:1px solid var(--line)}
.stTabs [data-baseweb="tab"]{height:2.6rem;padding:0 .95rem;border-radius:8px 8px 0 0;color:var(--muted)}
.stTabs [aria-selected="true"]{color:#fff!important;background:var(--panel)}
.stButton>button,.stDownloadButton>button{border-radius:8px;border:1px solid var(--line);background:var(--panel);transition:border-color .15s,transform .15s}
.stButton>button:hover,.stDownloadButton>button:hover{border-color:var(--teal);color:var(--teal)}
.stButton>button[kind="primary"]{background:var(--teal);color:#06231f;border-color:var(--teal);font-weight:600}
[data-testid="stDataFrame"]{border:1px solid var(--line);border-radius:8px}
:focus-visible{outline:2px solid var(--teal)!important;outline-offset:2px}
@media (max-width:760px){.hero{padding:1.2rem}.hero-title{font-size:1.6rem}.hero .art{width:100%;opacity:.35}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}

/* ── Animations & Enterprise UI ── */
@keyframes glow-pulse {
  0%, 100% { box-shadow: 0 0 15px rgba(45,212,191,0.2), inset 0 0 15px rgba(45,212,191,0.1); }
  50% { box-shadow: 0 0 25px rgba(45,212,191,0.5), inset 0 0 25px rgba(45,212,191,0.25); }
}
@keyframes border-rainbow {
  0% { border-color: rgba(45,212,191,0.6); }
  33% { border-color: rgba(167,139,250,0.6); }
  66% { border-color: rgba(56,189,248,0.6); }
  100% { border-color: rgba(45,212,191,0.6); }
}
@keyframes float {
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-6px); }
}
@keyframes scan-laser {
  0% { transform: translateY(-100%); }
  100% { transform: translateY(1000%); }
}

.plan-card {
  position: relative;
  background: linear-gradient(135deg, rgba(17,26,35,0.95), rgba(14,23,32,0.85));
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 1.6rem 1.4rem;
  margin-bottom: 1.2rem;
  transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  overflow: hidden;
  backdrop-filter: blur(12px);
}
.plan-card:hover {
  transform: translateY(-5px) scale(1.01);
  box-shadow: 0 16px 36px rgba(0,0,0,0.45);
}
.plan-card.pro-ulta {
  border: 1px solid rgba(56,189,248,0.4);
  animation: glow-pulse 4s infinite ease-in-out;
}
.plan-card.pro-max-ulta {
  border: 2px solid rgba(167,139,250,0.6);
  animation: border-rainbow 6s infinite linear, glow-pulse 3s infinite ease-in-out;
}
.plan-badge {
  display: inline-block;
  font: 700 0.72rem var(--mono);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: 0.25rem 0.65rem;
  border-radius: 999px;
  margin-bottom: 0.75rem;
}
.plan-badge.ulta {
  background: rgba(56,189,248,0.15);
  color: var(--sky);
  border: 1px solid rgba(56,189,248,0.4);
}
.plan-badge.max-ulta {
  background: linear-gradient(90deg, rgba(167,139,250,0.25), rgba(45,212,191,0.25));
  color: #fff;
  border: 1px solid rgba(167,139,250,0.5);
  box-shadow: 0 0 12px rgba(167,139,250,0.4);
}
.plan-price {
  font: 700 2.2rem var(--mono);
  color: #fff;
  line-height: 1;
  margin: 0.4rem 0 0.8rem;
}
.plan-price span {
  font-size: 0.9rem;
  color: var(--muted);
  font-weight: 400;
}
.plan-features {
  list-style: none;
  padding: 0;
  margin: 1rem 0;
  color: #c8d4df;
  font-size: 0.88rem;
}
.plan-features li {
  padding: 0.35rem 0;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.plan-features li::before {
  content: "✔";
  color: var(--teal);
  font-weight: bold;
}
.company-strip {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  flex-wrap: wrap;
  padding: 0.9rem 1.2rem;
  background: rgba(17,26,35,0.6);
  border: 1px solid var(--line);
  border-radius: 10px;
  margin: 1rem 0 1.5rem;
}
.company-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  font: 600 0.82rem var(--mono);
  color: #d6e0ea;
  padding: 0.3rem 0.7rem;
  background: rgba(255,255,255,0.04);
  border-radius: 6px;
  border: 1px solid rgba(255,255,255,0.08);
  transition: transform 0.2s ease, border-color 0.2s ease;
}
.company-pill:hover {
  transform: translateY(-2px);
  border-color: var(--teal);
  color: #fff;
}
"""


def get_all_styles() -> str:
    return f"<style>{_CSS}</style>"


# ── renderers ───────────────────────────────────────────────────────────────

def render_hero(status: str = "System active — defensive analysis mode", warn: bool = False) -> str:
    return (
        '<div class="hero"><div class="art">' + img("hero.svg", "Animated attack path") + '</div>'
        '<div class="hero-body"><div class="hero-title">' + img("logo.svg", "AegisTrace AI")
        + '<span>AegisTrace AI</span></div>'
        '<div class="hero-sub">Triage SIEM alerts, reconstruct the attack timeline and map it to MITRE ATT&amp;CK. '
        'Alert text is treated as untrusted evidence.</div>'
        f'<span class="status{" warn" if warn else ""}"><span class="dot"></span>{esc(status)}</span></div></div>'
    )


def render_sidebar_brand() -> str:
    return ('<div class="side-brand">' + img("logo.svg", "AegisTrace AI")
            + '<div><b>AegisTrace AI</b><span>SOC triage console v2.1</span></div></div>')


def render_section(icon: str, title: str, tag: str = "", tag_class: str = "") -> str:
    tag_html = f'<span class="tag {esc(tag_class)}">{esc(tag)}</span>' if tag else ""
    return f'<div class="sec"><span class="ic">{esc(icon)}</span><h2>{esc(title)}</h2>{tag_html}</div>'


def render_metric_card(icon: str, value, label: str, color: str = "blue", critical: bool = False) -> str:
    c = {"blue": "#38bdf8", "red": "#ff5d5d", "green": "#4ade80", "cyan": "#2dd4bf",
         "purple": "#a78bfa", "amber": "#fbbf24"}.get(color, "#38bdf8")
    return (f'<div class="metric{" crit" if critical else ""}" style="--c:{c}"><span class="i">{esc(icon)}</span>'
            f'<div class="v">{esc(value)}</div><div class="l">{esc(label)}</div></div>')


def render_risk_gauge(score: int) -> str:
    """Animated semicircle gauge as a self-contained SVG image."""
    score = max(0, min(100, int(score)))
    color = "#ff5d5d" if score >= 80 else "#ff9f43" if score >= 60 else "#fbbf24" if score >= 35 else "#4ade80"
    label = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW"
    arc = 157.08  # length of the r=50 half circle
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 140 92">
<style>.t{{font:600 24px 'IBM Plex Mono',monospace;fill:#fff}}.s{{font:600 9px 'IBM Plex Mono',monospace;fill:{color};letter-spacing:.08em}}
.f{{stroke-dasharray:{arc};stroke-dashoffset:{arc};animation:g 1.3s cubic-bezier(.2,.8,.2,1) .1s forwards}}
@keyframes g{{to{{stroke-dashoffset:{arc * (1 - score / 100):.2f}}}}}
@media (prefers-reduced-motion:reduce){{.f{{animation:none;stroke-dashoffset:{arc * (1 - score / 100):.2f}}}}}</style>
<path d="M20 70 A50 50 0 0 1 120 70" fill="none" stroke="#1f2e3b" stroke-width="11" stroke-linecap="round"/>
<path class="f" d="M20 70 A50 50 0 0 1 120 70" fill="none" stroke="{color}" stroke-width="11" stroke-linecap="round"/>
<text class="t" x="70" y="62" text-anchor="middle">{score}</text>
<text class="s" x="70" y="82" text-anchor="middle">{label} RISK</text></svg>"""
    return f'<div class="gauge"><img src="{svg_data_uri(svg)}" alt="Risk score {score} of 100, {label.lower()}"/></div>'


def render_timeline_event(e: dict, index: int) -> str:
    c = SEV_COLOR.get(e.get("severity"), "#8aa0b2")
    meta = " · ".join(esc(x) for x in (e.get("source_ip"), e.get("user"), e.get("host")) if x)
    return (
        f'<div class="tl-item" style="--c:{c};--i:{min(index, 40)}"><div class="tl-top">'
        f'<span>#{esc(e.get("event_id"))}</span><span>{esc(e.get("time"))}</span>'
        f'<span class="sev">{esc(e.get("severity"))}</span>'
        f'<span>{esc(str(e.get("category", "")).replace("_", " "))}</span>'
        f'<span class="mitre">{esc(e.get("mitre", "N/A"))}</span></div>'
        f'<div class="tl-msg">{esc(e.get("message") or "(no message)")}</div>'
        f'<div class="tl-top" style="margin-top:.25rem">{meta}</div></div>'
    )


def render_pattern_card(p: dict) -> str:
    c = SEV_COLOR.get(p.get("severity"), "#fbbf24")
    m = p.get("mitre") or {}
    mitre = f'<span class="mitre">{esc(m.get("tactic"))} · {esc(m.get("technique"))}</span>' if m.get("technique", "N/A") != "N/A" else ""
    ids = ", ".join(f"#{i}" for i in p.get("event_ids", [])[:20])
    return (
        f'<div class="card" style="--c:{c}"><h4>{esc(p.get("pattern"))}</h4>'
        f'<div class="meta">indicator: {esc(p.get("indicator"))} · events: {esc(p.get("count"))} · '
        f'<span class="sev" style="--c:{c}">{esc(p.get("severity"))}</span></div>'
        f'<div class="body">{esc(p.get("assessment"))}</div>'
        f'<div class="meta" style="margin-top:.45rem">{mitre} {esc(ids)}</div></div>'
    )


def render_ioc_card(ioc: dict) -> str:
    kind = ioc["type"]
    cls = {"ipv4": "ip", "domain": "domain", "url": "url", "email": "email"}.get(kind, "hash")
    c = SEV_COLOR.get(ioc.get("max_severity"), "#38bdf8")
    ids = ", ".join(f"#{i}" for i in ioc["event_ids"][:20])
    return (
        f'<div class="card" style="--c:{c}"><div class="ioc"><span class="chip {cls}">{esc(kind.upper())}</span>'
        f'<code>{esc(ioc["defanged"])}</code></div>'
        f'<div class="meta" style="margin-top:.4rem">events {esc(ids)} · seen {esc(ioc["count"])}× · '
        f'max severity {esc(ioc.get("max_severity"))}</div></div>'
    )


def render_checklist_item(item: dict) -> str:
    return (f'<div class="card" style="--c:#2dd4bf"><h4>{esc(item["id"])}. {esc(item["step"])}</h4>'
            f'<div class="body">{esc(item["guidance"])}</div></div>')


def render_injection_warning(count: int) -> str:
    return ('<div class="alert"><b>Prompt-injection attempt detected.</b> '
            f'{esc(count)} alert field(s) contain instruction-like text. It was flagged, not obeyed, and is '
            'excluded from any instruction channel sent to the AI provider.</div>')


def render_empty(art: str, title: str, text: str) -> str:
    return f'<div class="empty">{img(art, "")}<div><b style="color:#fff">{esc(title)}</b><br/>{esc(text)}</div></div>'


def render_art_side(name: str, alt: str = "") -> str:
    return f'<div class="art-side">{img(name, alt)}</div>'


def render_footer(version: str, generated: str) -> str:
    return (f'<div class="footer"><b>AegisTrace AI</b> — defensive SOC triage · v{esc(version)} · {esc(generated)}'
            f'<br/>Created by <b><a href="https://rajaryan.neocities.org" target="_blank" style="color:var(--teal);text-decoration:none;">RAJ ARYAN</a></b>'
            '<small>All response actions require analyst review. This tool does not execute commands, '
            'access endpoints, or perform automated containment.</small></div>')

# ── subscription cards ───────────────────────────────────────────────────────────────
def render_subscription_card(title: str, price: str, features: list[str], badge: str = "") -> str:
    feat_html = "".join(f"<li>{esc(f)}</li>" for f in features)
    badge_html = f"<span class=\"badge\">{esc(badge)}</span>" if badge else ""
    return (
        f"<div class=\"sub-card\" style=\"--c:{esc('#38bdf8')}\">"
        f"<h3>{esc(title)} {badge_html}</h3>"
        f"<div class=\"price\">{esc(price)}</div>"
        f"<ul class=\"features\">{feat_html}</ul>"
        f"</div>"
    )


def render_company_showcase() -> str:
    companies = [
        ("🏢 Google", "Chronicle & GCP Security Command Center integration"),
        ("💻 Microsoft", "Microsoft Sentinel, Defender XDR & M365 telemetry"),
        ("☁️ Amazon AWS", "GuardDuty, CloudTrail & Security Hub feeds"),
        ("⚡ CrowdStrike", "Falcon EDR event streams & automated quarantine hooks"),
        ("🛡️ Palo Alto", "Cortex XSOAR playbook sync & telemetry ingest"),
    ]
    pills = "".join(
        f'<div class="company-pill" title="{esc(desc)}"><span>{esc(name)}</span></div>'
        for name, desc in companies
    )
    return (
        '<div style="margin: 0.8rem 0 0.4rem;">'
        '<div style="font: 600 0.8rem var(--mono); color: var(--teal); letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 0.5rem;">'
        'Trusted & Verified in Production Architectures:</div>'
        f'<div class="company-strip">{pills}</div>'
        '</div>'
    )


def render_plan_card(tier_key: str, name: str, badge: str, price: str, period: str, desc: str, features: list[str], enterprise_clients: str) -> str:
    is_max = "max" in tier_key
    card_cls = "plan-card pro-max-ulta" if is_max else "plan-card pro-ulta"
    badge_cls = "plan-badge max-ulta" if is_max else "plan-badge ulta"
    feat_html = "".join(f"<li>{esc(f)}</li>" for f in features)
    return (
        f'<div class="{card_cls}">'
        f'<div class="{badge_cls}">{esc(badge)}</div>'
        f'<h3 style="margin:0;font-size:1.5rem;color:#fff;">{esc(name)}</h3>'
        f'<div style="color:var(--muted);font-size:0.85rem;margin:0.25rem 0 0.8rem;">{esc(desc)}</div>'
        f'<div class="plan-price">{esc(price)} <span>{esc(period)}</span></div>'
        f'<div style="font:600 0.78rem var(--mono);color:var(--sky);margin-bottom:0.6rem;">{esc(enterprise_clients)}</div>'
        f'<ul class="plan-features">{feat_html}</ul>'
        f'</div>'
    )


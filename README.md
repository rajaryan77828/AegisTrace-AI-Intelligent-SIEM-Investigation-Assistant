<p align="center"><img src="assets/logo.svg" alt="AegisTrace AI" width="110"/></p>

<h1 align="center">AegisTrace AI</h1>
<p align="center"><strong>SIEM investigation assistant</strong> — detect, correlate, investigate, defend.</p>
<p align="center"><em>Created by <strong><a href="https://rajaryan.neocities.org">RAJ ARYAN</a></strong> · <a href="https://rajaryan.neocities.org">rajaryan.neocities.org</a></em></p>

AegisTrace AI is a defensive SOC triage app built with Python and Streamlit. Load SIEM alerts (JSON or CSV) and it
normalizes them, rebuilds the timeline, maps activity to MITRE ATT&CK, correlates patterns, extracts indicators, scores
risk, and exports a report. An optional AI narrative works with **any LLM API you configure from the sidebar**.

## What's new in 2.1

- **Bring-your-own AI provider, from the UI.** OpenAI, Anthropic, Google Gemini, Groq, OpenRouter, Mistral, DeepSeek,
  Together, xAI, Ollama, LM Studio, or any custom endpoint. Set base URL, model, key, protocol and auth header at runtime
  and click *Test connection*. No vendor SDK needed.
- **New console UI & Cyber Animations** with animated hero, pulse lasers, rainbow borders, animated risk gauge, severity-coded timeline, and illustrated empty states.
- **Enterprise Subscriptions & Integrations (💎 Pro Ulta & Pro Max Ulta)**:
  - **Pro Ulta ($2,499/mo):** High-throughput ingestion (250,000 EPS), live MITRE ATT&CK correlation, Google Cloud & Chronicle SIEM bridge.
  - **Pro Max Ulta ($8,999/mo):** Multi-cloud correlation, Microsoft Sentinel / Defender XDR sync, AWS Security Hub integration, zero-trust LLM sandbox, and automated kill-chain disruption.
- **Detection fixes** (see *Changelog*): order-aware kill chain, working kill-chain risk bonus, correct categories,
  no more `"nan"` users from CSVs, defanged IOCs, ECS / Elastic / Splunk input shapes.
- **Security hardening**: SSRF guard on custom endpoints, formula-injection-safe CSV export, LLM output stripped of
  Markdown images/links, bounded and delimited prompts.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate      # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

Opens at http://localhost:8501 with demo data. Upload or paste your own alerts in the sidebar.

## Using any AI API

1. Sidebar → turn on **Enable AI advisory narrative**.
2. Pick a provider (presets fill base URL, model and protocol) or choose **Custom endpoint**.
3. Paste your API key, click **Test connection**.
4. Open the **AI advisory** tab and click **Generate advisory**.

| Protocol | Used by |
|---|---|
| OpenAI-compatible `/chat/completions` | OpenAI, Groq, OpenRouter, Mistral, DeepSeek, Together, xAI, Ollama, LM Studio, vLLM, most gateways |
| Anthropic `/messages` | Claude |
| Google `generateContent` | Gemini |

For an unusual API, choose *Custom endpoint*, set the protocol closest to it, and use **Advanced → Custom auth header**
(for example `X-API-Key`, with an optional prefix such as `Bearer `).

**Key handling.** Keys live only in the browser session's memory. They are never written to disk, logged, or put in the
JSON report. A key configured on the server (env / Secrets) is never sent to the browser and is only used with the
server's own endpoint, so a visitor cannot redirect it elsewhere.

**Local models (Ollama / LM Studio).** Localhost and private addresses are blocked by default to prevent SSRF on shared
deployments. When running on your own machine, set `AEGIS_ALLOW_PRIVATE_ENDPOINTS=1` (see `.env.example`).
Link-local / cloud-metadata addresses (169.254.0.0/16) are always blocked.

**Server defaults (optional).** Copy `.env.example` to `.env`, or on Streamlit Cloud add Secrets:

```toml
AEGIS_PROVIDER = "openai"
AEGIS_API_KEY  = "your_key"
AEGIS_MODEL    = "gpt-4.1-mini"
```

The legacy `OPENAI_API_KEY` / `OPENAI_MODEL` variables still work. The analyzer runs fully without any key.

## Input

JSON array, `{"events": [...]}`, Elastic `hits.hits[]._source`, Splunk `results`, a single object, or CSV. Nested ECS
fields (`source.ip`, `user.name`, `event.action`) are flattened automatically. Severity can be a label (`P1`, `warning`)
or a number (0–4, 0–10, 0–100). Timestamps can be ISO-8601, `YYYY-MM-DD HH:MM:SS`, or epoch seconds/milliseconds.

| Standard field | Common aliases |
|---|---|
| `timestamp` | `time`, `@timestamp`, `datetime`, `event_time`, `created_at`, `_time` |
| `source_ip` | `src_ip`, `src`, `source.address`, `source.ip`, `client_ip`, `remote_ip` |
| `destination_ip` | `dst_ip`, `dst`, `destination.address`, `destination.ip`, `server_ip` |
| `event_type` | `event`, `type`, `category`, `action`, `rule_name`, `event.action` |
| `severity` | `level`, `priority`, `risk`, `threat_level`, `event.severity` |
| `user` | `username`, `account`, `principal`, `actor`, `user.name` |
| `host` | `hostname`, `device`, `computer`, `endpoint`, `host.name` |
| `message` | `description`, `details`, `alert`, `reason`, `summary`, `msg` |

Limit: 50,000 events and 20 MB per analysis.

## Security model

SIEM fields are untrusted evidence everywhere:

1. All dynamic HTML is escaped once, in the renderers (`utils/sanitizer.py`).
2. Prompt-injection text is detected (Unicode-normalized, one finding per field) and flagged, never obeyed.
3. The LLM prompt wraps data in random delimiters, caps size (150 events, 400 chars per field), drops `raw_text`, and
   the reply is stripped of Markdown images/links/HTML to block data-exfiltration through rendered URLs.
4. CSV export neutralizes formula injection (`=`, `+`, `-`, `@`).
5. IOCs are displayed defanged.
6. The tool never executes commands, blocks IPs or modifies accounts.
7. XSRF protection is on (`.streamlit/config.toml`).

## Project layout

```
app.py                 Streamlit UI (tabs, sidebar, AI provider panel)
analyzer.py            Normalization, MITRE mapping, correlation, IOCs, risk score
llm_providers.py       Provider presets + provider-agnostic HTTP client
llm_summary.py         Hardened prompt builder and advisory generator
components/            styles.py (CSS + renderers), assets.py (SVG loader)
utils/                 sanitizer.py, security.py (SSRF guard), compat.py
assets/                logo, animated hero, AI and radar illustrations (SVG)
tests/                 49 unit tests (analyzer, sanitizer, LLM adapters, SSRF)
.streamlit/config.toml Theme and server settings
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Changelog (2.0 → 2.1)

**Bugs fixed**
- Kill-chain risk bonus never applied (it searched for the text "kill chain", which the pattern title lacked).
- Kill-chain and failure-to-success detection ignored time order; both now require chronological order.
- A DNS event was categorized as *malware* because the domain contained "malware". Classification now uses
  `event_type` first, ignores domains/URLs/hashes in free text, and uses word boundaries.
- CSV blanks became the string `"nan"` (fake "repeated account: nan" patterns).
- Numeric risk scores such as `85` were treated as *low*.
- The LLM was called on every Streamlit rerun (each checkbox click). It now runs only on **Generate**.
- Pattern MITRE tags were hard-coded to brute force; they now follow the events.
- Prompt-injection findings were duplicated across `message` and `raw_text`; the `system prompt` pattern was too broad.
- IOC code had dead hash-dedupe logic, an `[A-Z|a-z]` regex typo, and dropped documentation-range IPs.
- Misc: private `pd.io.common` API, relative sample path, unmatched `<div>` wrappers around sidebar widgets,
  `"HH:MM"` heatmap sorting across midnight, nondeterministic MITRE ordering, `use_container_width` deprecation,
  missing `.env` loader, missing files referenced by the README (`components/`, `utils/`, tests, logo, config).

**Added** provider-agnostic AI client and settings panel, SSRF guard, defanged IOCs, hierarchical input shapes,
epoch/numeric parsing, animated artwork, and an AI advisory tab.

## License

MIT — Copyright (c) 2026 **RAJ ARYAN** ([rajaryan.neocities.org](https://rajaryan.neocities.org)). See [LICENSE](LICENSE).

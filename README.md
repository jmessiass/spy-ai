# SpyAI

**SpyAI — passive reconnaissance for AI-facing systems**

SpyAI scans hosts on the public internet or your lab for the ports, HTTP banners, API paths, and TLS footprints typical of LLM agents, RAG backends, vector stores, and adjacent infrastructure. It produces a Markdown report plus a full execution log—no authentication, no fuzzing, no exploits.

## What it does

1. **Port scan** — parallel TCP connect (`python3`, stdlib only) on a compact common port set plus AI-likely ports (8000–8080, 9000, 9200, 11434, 5601, 3000, etc.).
2. **HTTP fingerprinting** — `HEAD /` banners per HTTP-likely open port.
3. **Endpoint discovery** — `GET` on a curated wordlist (`/openapi.json`, `/health`, `/v1/models`, `/api/chat`, MinIO health paths, and more).
4. **HTML/JS mining** — extracts embedded API paths from `fetch()`, `axios`, `data-endpoint`, and common JS config keys on `/`.
5. **OpenAPI parsing** — lists paths and methods when `/openapi.json` returns 200.
6. **Agent health** — detects uvicorn-style `/health` JSON with an `agent` field.
7. **TLS certificates** — subject, issuer, dates, SANs on HTTPS ports (optional `openssl`).

Service names in the report are **heuristic** (port-based). For full version detection or top-1000 sweeps, run **nmap separately** and use SpyAI for AI-focused HTTP discovery.

## Why SpyAI

Generic port scanners miss predictable AI stack surfaces: inference APIs on high ports, OpenAPI docs, RAG health endpoints, and custom headers (`X-AI-Backend`, `X-RAG-Provider`, etc.). SpyAI targets those footprints with minimal dependencies so you can map an AI-facing attack surface quickly.

## Install

```bash
git clone https://github.com/jmessiass/spy-ai.git
cd spy-ai
chmod +x spy-ai lib/scan_ports.py
```

## Dependencies

| Tool | Required | Enables |
|------|----------|---------|
| `python3` | Yes | TCP port scan (`lib/scan_ports.py`), OpenAPI/HTML parsing, agent `/health` JSON |
| `curl` | Yes | HTTP probes |
| `openssl` | No | TLS certificate mining |
| `timeout` or `gtimeout` | No | Bounds TLS handshake (macOS: `brew install coreutils` for `gtimeout`) |

**Not required:** `nmap`. Use it on your own if you want broader port coverage or `-sV` version probes.

## Usage

```bash
./spy-ai 192.168.1.10
./spy-ai api.example.com
./spy-ai --help
```

The target may be an IPv4 address or a hostname (FQDN).

## Output layout

Reports and logs are written under `output/` next to the script:

```
spy-ai/
├── spy-ai
├── lib/
│   └── scan_ports.py
├── data/
│   ├── passive_probes.txt
│   └── interesting_headers.txt
└── output/
    ├── 192.168.1.10-1.md
    └── logs/
        └── 192.168.1.10-1.exec.log
```

Each run increments `<target>-<N>` (e.g. `api.example.com-2.md` on a second scan).

### Sample report sections

```markdown
## Open Ports
| Port | Service |
| ---- | ------- |
| 8030 | http |

## HTTP Banners (HEAD /)
| Port | Scheme | Status | Server | Content-Type | Location |

## Discovered Endpoints
### Port 8030 (http)
| Path | Status | Content-Type | Size | Notes |
| /openapi.json | 200 | application/json | 1234 | |
| /health | 200 | application/json | 89 | |
```

See also optional sections: **OpenAPI Schemas**, **Agent Services**, **Auth Challenges (401)**, **TLS Certificates**.

## Customization

Edit wordlists in `data/` (one entry per line; `#` comments allowed):

- **`passive_probes.txt`** — HTTP paths to `GET` on each open HTTP-likely port.
- **`interesting_headers.txt`** — response headers echoed in the execution log.

To add ports to the TCP scan, edit `COMMON_PORTS` or `HTTP_LIKELY_PORTS` in `spy-ai` (or extend `lib/scan_ports.py` `SERVICE_HINTS` for report labels).

## Passive vs active

SpyAI does **not** send credentials or exploit payloads. From the application’s perspective it is passive (read-only probes). It still generates **active network traffic** (TCP connect + `curl`)—use only on systems you are authorized to test.

## Legal

Unauthorized scanning may violate law or policy. You are responsible for obtaining permission before running SpyAI against any target.

## License

MIT — see [LICENSE](LICENSE).

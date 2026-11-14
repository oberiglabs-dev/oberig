# oberig

**Your agent's amulet.** Private AI you can check.

Oberig is a small local guard that sits between your coding agent (Claude Code, Codex, OpenCode) and NEAR AI Cloud. It sends prompts only to an enclave it has verified, masks your secrets first, stops hidden instructions before the model reads them, and gives every answer a stitched seal you can check.

Four verbs: **Verify · Mask · Shield · Seal.** A fifth tool, **Scrub**, cleans agent traces before you share them.

- Built for NEAR AI Cloud (`cloud-api.near.ai`). Every model request goes there. There is no other provider and no fallback.
- Runs on `127.0.0.1` only. Stores nothing on disk. No telemetry.
- Zero dependencies. Node.js 18.17 or newer. MIT.
- Windows, macOS and Linux.

### How it relates to NEAR AI's own tools

NEAR AI Gateway (with its IronWire local proxy) gets your agent to NEAR AI private models in a click, and nearai-cloud-verifier checks attestation reports on demand. Oberig is a small, separate layer you can read in one sitting: it checks the attestation before the first request and every answer's signature after it, refuses to send when a check fails, masks secrets so the enclave never sees them, strips hidden instructions from tool results, and runs the same on Windows, macOS and Linux. It has not been tested together with the Gateway app.

*Oberig (оберіг) is Ukrainian for a protective amulet. In folk embroidery, the stitched pattern itself was the oberig.*

---

## Quick start

You need a NEAR AI Cloud API key (cloud.near.ai: buy credits, then create a key). Oberig reads it from `NEARAI_API_KEY`, or from `NEAR_AI_API_KEY` if the first is not set. It never reads keys from files.

**PowerShell**

```powershell
git clone https://github.com/oberiglabs-dev/oberig; cd oberig
$env:NEARAI_API_KEY = "<your key>"; node bin/oberig.js
```

**macOS / Linux**

```sh
git clone https://github.com/oberiglabs-dev/oberig && cd oberig
NEARAI_API_KEY="<your key>" node bin/oberig.js
```

You see this (your signer and address will differ):

```
  ×   ×
×   ×   ×   OBERIG v0.1.0
  ×   ×     your agent's amulet
Enclave    NEAR AI · deepseek-ai/DeepSeek-V4.1-Flash-1017
Verified   ✓ enclave attested · signer 0x236f…da4c
Guards     mask on · shield on · seals on
Privacy    runs only on this computer · stores nothing · no telemetry
Address    http://127.0.0.1:8790  (dashboard: open it in a browser)
```

Then point your agent at it (next section). Each request prints one metadata-only line, for example:

```
14:05:02  claude-code → near ✓ verified  ◆ masked 2  ⚑ stopped 1  200  1.8s  seal 7f3a
```

The live dashboard is at `http://127.0.0.1:8790/`.

`npm install -g .` in the repo folder gives you the `oberig` command. The rest of this README uses it.

### Try it without a key

These need no NEAR AI key:

```sh
node bin/oberig.js verify          # fetch a fresh attestation and print the enclave receipt
node bin/oberig.js shield README.md
node bin/oberig.js scrub ./some-traces
node --test test/                  # 88 tests, offline (mocked NEAR AI server)
```

`oberig verify --chat` also sends one short test prompt and checks its signature. That needs a key and costs a tiny amount.

---

## Connect your agent

Any model name works: Oberig always uses the configured NEAR AI model (default `deepseek-ai/DeepSeek-V4.1-Flash-1017`). The agent's own API key is ignored and never forwarded. `oberig setup` prints these lines for your port.

### Claude Code

Claude Code speaks the Anthropic Messages API. Oberig serves `/v1/messages` (streaming and tool use) and translates it to NEAR AI's Chat Completions.

```powershell
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8790"; $env:ANTHROPIC_AUTH_TOKEN = "oberig"; claude
```

```sh
ANTHROPIC_BASE_URL=http://127.0.0.1:8790 ANTHROPIC_AUTH_TOKEN=oberig claude
```

Optional: `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` turns off Claude Code's own non-essential network calls (telemetry, error reports, update checks).

### Codex

Codex talks to `/v1/chat/completions`. In `~/.codex/config.toml`:

```toml
model = "deepseek-ai/DeepSeek-V4.1-Flash-1017"
model_provider = "oberig"

[model_providers.oberig]
name = "Oberig"
base_url = "http://127.0.0.1:8790/v1"
wire_api = "chat"
```

Oberig v0.1 serves Chat Completions only, not the Responses API, so `wire_api = "chat"` is required.

### OpenCode

In `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "oberig": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Oberig",
      "options": { "baseURL": "http://127.0.0.1:8790/v1" },
      "models": { "deepseek-ai/DeepSeek-V4.1-Flash-1017": {} }
    }
  },
  "model": "oberig/deepseek-ai/DeepSeek-V4.1-Flash-1017"
}
```

### Other tools

Any OpenAI-compatible client: base URL `http://127.0.0.1:8790/v1`, any API key.

---

## What happens to a request

```
agent ──► Oberig on 127.0.0.1 ─────────────────────────────────────────────► NEAR AI Cloud
           1. verify   fresh attestation for the model (before sending, re-checked every 10 min)
           2. shield   hidden instructions in tool results are cut out
           3. mask     secrets and personal data become [[OBERIG_*]] placeholders
           4. send     exact bytes hashed (SHA-256), canonical model ID, x-no-aliasing
           5. restore  placeholders put back locally, also inside tool-call arguments
           6. seal     answer signature checked against the exact bytes; receipt + stitched seal
```

If the attestation check fails, nothing is sent and the agent gets a clear error (`OBERIG_REQUIRE_ATTESTATION=1`, the default).

---

## Verify: what is checked and what is not

Before the first request (and again after 10 minutes, or when an answer's signer does not match), Oberig asks `GET /v1/attestation/report` for the model with its own random 32-byte nonce, `provider=near`, `signing_algo=ed25519` and the header `x-no-aliasing: true`. The report is fetched before any prompt is sent; a report fetched after an answer is never used for it.

| Check | Default | `OBERIG_VERIFY=full` |
|---|---|---|
| Report returned for this exact model (non-empty `model_attestations`), every candidate checked | ✓ | ✓ |
| Fresh nonce echoed by the service | ✓ | ✓ |
| Intel TDX quote signed by an Intel-rooted key: attestation key signature, QE report binding, QE report signed by the PCK certificate, PCK chain to the pinned Intel SGX Root CA (SHA-256 `44:A0:19:6B:…:74:D3`), validity dates | ✓ | ✓ |
| Nonce bound in the quote's report data | ✓ | ✓ |
| Signing key bound in the quote's report data (the signer Oberig then pins) | ✓ | ✓ |
| TD debug mode off | ✓ | ✓ |
| App configuration measured: MRCONFIGID = `01 ‖ sha256(app_compose) ‖ 0…` | ✓ | ✓ |
| RTMR3 replayed from the event log | ✓ | ✓ |
| NVIDIA GPU evidence carries our nonce | ✓ | ✓ |
| NEAR AI gateway enclave: the same quote checks | ✓ | ✓ |
| NVIDIA GPU verdict from NRAS (`x-nvidia-overall-att-result`) | not checked locally | ✓ (token signature not checked) |
| Intel TCB status, QE identity, revocation lists (Intel PCS collateral) | not checked | not checked |
| Image provenance (Sigstore), measurement allow-lists | not checked | not checked |

After each answer Oberig fetches `GET /v1/signature/{id}` and checks:

- the signed text is `<model>:<sha256 of the request bytes Oberig sent>:<sha256 of the response bytes it received>` (or `<request>:<response>` for a gateway signature)
- the Ed25519 signature verifies (ECDSA/EIP-191 is supported too, with small built-in keccak256 and secp256k1 modules)
- the signer is the key pinned from the attestation

The answer reaches your agent first; the signature check follows and lands in the log line and the receipt. The signature covers the masked request, so a valid signature also shows the enclave received placeholders, not your secrets.

**Limits, as NEAR AI states them, and as the receipts say them:**

- All instances of a model share one signing key. A signer match shows the attested key signed the answer, not which machine answered.
- Preflight evidence plus one response signature is not yet a complete model-to-gateway-to-answer chain.
- By default Oberig asks NEAR AI non-streaming, with the canonical model ID and `x-no-aliasing: true`, to get a model-level (`provider_tee`) signature, then streams to your agent locally. With `OBERIG_UPSTREAM_STREAM=1` it streams from NEAR AI and expects a gateway signature over the exact stream bytes. Which kind a given answer carries is shown in its receipt.
- Tested live on 14 Nov 2026 against NEAR AI Cloud (DeepSeek V4.1 Flash 1017): `oberig verify --chat` passed every local attestation check and verified the test answer's signature with the model's TEE key, and a Claude Code style request through the gateway came back with 2 values masked, the signature verified and a seal.

`oberig verify` prints the receipt:

```
  OBERIG · enclave receipt

  model     deepseek-ai/DeepSeek-V4.1-Flash-1017
  service   NEAR AI Cloud · provider near
  ...
  ✓  TDX quote signed by an Intel-rooted key
  ✓  nonce bound in quote report data
  ✓  signer bound in quote report data
  ...
  ·  Intel TCB status: not checked locally
  ·  GPU verdict (NVIDIA): not checked locally

  result    ✓ enclave attested
```

followed by the receipt's stitched seal and its 4-character id. Exit code 0 means attested.

---

## Mask

Before a request leaves your computer, secrets and personal data are replaced with placeholders, so not even the enclave sees them:

`[[OBERIG_SECRET_1]]` `[[OBERIG_EMAIL_1]]` `[[OBERIG_PHONE_1]]` `[[OBERIG_CARD_1]]` `[[OBERIG_TERM_1]]`

- Numbering is stable for the session: the same value always gets the same placeholder.
- Answers are restored locally, including inside tool-call arguments (with JSON escaping) and across streamed chunks.
- Patterns cover private keys, common API key and token formats, NEAR private keys, JWTs, database passwords in URLs, bearer tokens, seed phrases, wallet keys, `*_SECRET=`/`*_TOKEN=`/`*_KEY=`/`*_PASSWORD=` style assignments, emails, international phone numbers and card numbers (Luhn-checked). Add your own words with `OBERIG_TERMS`.
- The map between values and placeholders lives in memory only and is gone when Oberig stops.

Pattern matching can miss a secret in an unusual format. Treat Mask as a seatbelt, not a guarantee.

## Shield

Oberig scans what your agent is about to send to the model for hidden instructions:

- HTML and markdown comments that carry instructions
- zero-width and invisible characters, Unicode tag characters (decoded and shown), bidi controls
- CSS-hidden text in HTML (`display:none`, `font-size:0` and similar) that carries instructions
- "ignore previous / system / developer instructions" style directives and fake chat-template markers
- instructions aimed at the agent to run remote scripts (`curl … | sh`, `iwr … | iex` and similar)
- markdown images and links that carry data out in the query string

Tool results (web pages, READMEs, issues, emails, files the agent read) get every rule. Text you typed yourself only gets the hidden-content rules, so your own words are never rewritten. System prompts and the model's own messages are not touched.

| `OBERIG_SHIELD` | Behaviour |
|---|---|
| `block` (default) | hidden parts are removed or replaced, and one short note is added for the model: `[oberig: removed hidden instructions from this content]` |
| `warn` | findings are counted and logged; nothing is changed |
| `off` | no scanning |

`oberig shield <file>` shows what it finds in any file (exit code 1 when something is found). The same `src/shield.js` runs in a browser.

**Limits.** The shield is a pattern scanner. It raises the cost of common tricks; it does not understand intent. It can miss new phrasings, other languages, instructions inside images, and encoded payloads (for example base64 that the model is asked to decode). It can also cut legitimate text, for example when your agent reads a test suite full of injection examples. Use `OBERIG_SHIELD=warn` for that kind of work.

## Seal

Every request gets a receipt, kept in memory with metadata only: time, client, model, attestation status (signer, nonce), response signature status and kind, masked counts, shield findings, SHA-256 of the request and response bytes, HTTP status, timing, and a short id. From the receipt's own hash Oberig draws a deterministic cross-stitch seal in the vyshyvanka tradition (8-fold symmetry, red, black and a little gold). The same receipt always gives the same seal.

The dashboard at `http://127.0.0.1:8790/` shows the session as a growing embroidered band (a rushnyk) of seals, with counters (verified answers, secrets kept home, hidden instructions stopped, traces scrubbed) and the request list. Hover a seal to read its receipt. It never shows prompt or answer text.

## Scrub

`oberig scrub <file|folder>` writes sanitised copies of agent traces that are safer to share as open data, for example when a project asks people to contribute their agent traces.

```sh
oberig scrub ~/.claude/projects/my-project          # writes ~/.claude/projects/my-project-scrubbed/
oberig scrub ./session.jsonl                         # writes ./session.scrubbed.jsonl
oberig scrub ~/.codex/sessions --out ./codex-clean
```

- Handles Claude Code JSONL transcripts, Codex logs, and any text or JSON file. JSON stays valid JSON and JSONL stays one object per line.
- Masks secrets, emails, phone numbers and card numbers; turns home folders (`C:\Users\name`, `/Users/name`, `/home/name`) into `~`; replaces your user name, machine name, private IP addresses and `.local`/`.internal`/`.corp`/`.lan` host names with `[[OBERIG_USER_n]]` and `[[OBERIG_HOST_n]]`.
- Never changes the originals, refuses to write inside the input folder, skips binary files, uploads nothing.
- Prints a summary. If a gateway is running, it adds the file count to the dashboard counter.

Read the copies before you share them. Pattern matching can miss things.

---

## Configuration

All settings come from the environment. There is no config file.

| Variable | Default | Meaning |
|---|---|---|
| `NEARAI_API_KEY` | | Your NEAR AI Cloud key. `NEAR_AI_API_KEY` is read if this is not set. |
| `OBERIG_MODEL` | `deepseek-ai/DeepSeek-V4.1-Flash-1017` | NEAR AI model. It must return a NEAR model attestation (`provider=near`), or nothing is sent. |
| `OBERIG_PORT` | `8790` | Local port (also `oberig start --port N`). Oberig always binds `127.0.0.1`. |
| `OBERIG_REQUIRE_ATTESTATION` | `1` | `1`: nothing is sent unless the attestation check passes. `0`: send anyway and mark answers `unverified`. |
| `OBERIG_VERIFY` | `local` | `full` adds the NVIDIA GPU verdict from NRAS (sends NEAR AI's GPU evidence to NVIDIA). |
| `OBERIG_SIGNING_ALGO` | `ed25519` | `ecdsa` uses EIP-191 signatures instead. |
| `OBERIG_ATTEST_TTL` | `600` | Seconds before the attestation is fetched and checked again (minimum 60). |
| `OBERIG_SHIELD` | `block` | `block`, `warn` or `off`. |
| `OBERIG_MASK` | `1` | `0` turns masking off. |
| `OBERIG_MASK_PII` | `1` | `0` masks secrets only (no emails, phones, cards). |
| `OBERIG_TERMS` | | Comma-separated words to always mask, for example client or project names. |
| `OBERIG_UPSTREAM_STREAM` | `0` | `1` streams from NEAR AI (gateway signature) instead of asking non-streaming (model signature). |
| `OBERIG_MAX_TOKENS` | `32768` | Upper bound for `max_tokens` on translated Claude Code requests. |
| `OBERIG_QUIET` | `0` | `1` hides the per-request log lines. |
| `NO_COLOR` | | Set to turn off terminal colours. |

## Endpoints

| Path | Use |
|---|---|
| `POST /v1/messages` | Anthropic Messages (Claude Code), streaming and tool use |
| `POST /v1/messages/count_tokens` | local estimate, nothing is sent |
| `POST /v1/chat/completions` | OpenAI Chat Completions (Codex, OpenCode, others), streaming and tool calls |
| `GET /v1/models` | the configured model |
| `GET /` | dashboard |
| `GET /_oberig/state`, `GET /_oberig/events` | dashboard data (metadata only) |

Every other path returns 404. Nothing is passed through to any other service.

## Security

- Listens on `127.0.0.1` only. Requests whose `Host` is not `localhost`, `127.0.0.1` or `[::1]` are refused (DNS rebinding).
- Requests with a browser `Origin` are refused on model routes; the dashboard only accepts its own origin.
- Model routes require `Content-Type: application/json`; bodies are capped at 32 MB.
- The NEAR AI key comes only from the environment and is sent only to `cloud-api.near.ai`. Keys and tokens your agent sends to Oberig are ignored and never forwarded.
- Network traffic: `cloud-api.near.ai` only; with `OBERIG_VERIFY=full` also `nras.attestation.nvidia.com`; `oberig scrub` may call your own local gateway.
- Nothing is written to disk by the gateway. Receipts and the placeholder map live in memory. No telemetry, no analytics.
- The dashboard is served with a strict Content-Security-Policy and loads no third-party resources.
- Zero dependencies: only Node.js built-ins (`node:http`, `node:crypto`, `node:fs`).

Found a problem? Open an issue at https://github.com/oberiglabs-dev/oberig/issues. For anything sensitive, please ask for a private contact first.

## Development

```sh
node --test test/
```

The tests cover translation and streaming, attestation checks on captured live NEAR AI reports (Ed25519 and ECDSA) and on synthetic reports with their own test certificate chain, response signatures (good, bad, wrong bytes, wrong signer), nonce mismatch, refusal when attestation is required, masking and restoring (also in tool-call arguments), shield detections and a no-false-positive README, scrub on a sample Claude Code transcript, routing through a mocked NEAR AI server, the security rules, and the CLI. Test keys are assembled from pieces at runtime; no real key appears in the source.

Project layout: `bin/oberig.js` (CLI), `src/server.js` (gateway), `src/verify.js` and `src/quote.js` (attestation and signatures), `src/ecdsa.js` (keccak256, secp256k1), `src/mask.js`, `src/shield.js` (UMD), `src/translate.js`, `src/streams.js`, `src/receipt.js`, `src/scrub.js`, `src/seal.js` and `src/stitch.js` (seal and stitch renderers), `dashboard/index.html`.

## Credits

- NEAR AI Cloud for the OpenAI-compatible API, the attestation reports and the per-answer signatures. The checks follow NEAR AI's published verification documentation and its open-source verifier.
- Intel for the TDX quote format and the SGX root certificate; NVIDIA for the NRAS service.
- Secret patterns follow the shape of common open-source secret scanners.
- Libraries: none. Only Node.js built-ins.

MIT License. See [LICENSE](LICENSE).

---
name: web3-systemic-agent
description: Autonomous Web3 security firewall, contract bytecode/proxy inspector, DEX honeypot scanner, DAO governance auditor, and x402-gated deep semantic Solidity auditor via MCP and HTTP REST.
---

# Web3 Systemic Agent Skill

Use `web3-systemic-agent` to perform deterministic pre-sign security checks (free Stage 1) and paid deep semantic LLM audits (Stage 2 via x402 USDC on Base Mainnet) before signing EVM transactions, swapping tokens, or executing DAO governance payloads.

## Connection Options

### 1. Model Context Protocol (MCP)
- **Hosted Remote MCP Endpoint:** `https://web3-systemic-agent.onrender.com/mcp`
- **Local Stdio via uvx:** `uvx web3-systemic-agent`
- **Local Stdio from Repo:** `python -m src.mcp_server`

#### Stage 1 MCP Tools (Free — `$0.00`)
1. `preflight_tx_firewall`: Pre-sign firewall evaluating calldata, unlimited approvals, Permit2, EIP-712 phishing, Indirect Prompt Injection, and `eth_call` state simulation (`verdict`: `ALLOW` | `BLOCK` | `MANUAL_REVIEW`).
2. `check_token_honeypot`: Static EVM bytecode scanner for blacklist traps, 100% sell taxes, trading freezes, and `SELFDESTRUCT`.
3. `scan_contract_selectors`: Extracts 4-byte function selectors and flags privileged backdoors (`transferOwnership`, `upgradeTo`, `mint`, `selfdestruct`).
4. `inspect_proxy_and_source`: Resolves EIP-1967/Beacon proxy implementation slots, `admin()`, `owner()`, `paused()`, and verified Solidity source status (Sourcify / Etherscan v2).
5. `scan_dao_proposals`: Fetches Snapshot DAO proposals and extracts on-chain target addresses and execution calldata.

#### Stage 2 MCP Tool (Paid via x402 USDC on Base Mainnet `eip155:8453`)
6. `deep_semantic_audit`: Combines Stage 1 on-chain gatekeeping with Google Gemini LLM semantic auditing (`$0.015 USDC` standard, or `$0.25 USDC` when `resolve_proxy=True` or `fetch_verified_source=True`).
   - Omitting `x402_payment_header` safely returns an HTTP `402` challenge (`status="payment_required"`) without charging.
   - Supply `x402_payment_header` (Base64 EIP-3009 `transferWithAuthorization`) or configure `X402_BUYER_PRIVATE_KEY` for automatic settlement.

#### MCP Resources & Prompts
- **Resources (`resources/list`, `resources/read`):**
  - `web3://x402/pricing` — Live x402 pricing tiers and supported networks
  - `web3://security/selectors-catalog` — Known EVM backdoor & honeypot selectors
  - `web3://feed/dao-curated-proposals` — Curated Snapshot DAO proposals dataset
  - `web3://feed/recent-audits` — Recent autonomous security evaluations
- **Prompts (`prompts/list`, `prompts/get`):**
  - `audit-token-before-swap` (`token_address`, optional `chain_id`)
  - `pre-sign-transaction-firewall` (`to_address`, optional `calldata`)
  - `audit-dao-governance-space` (optional `space_id`)

---

## 2. HTTP REST + x402 Micropayment Endpoints

Base URL: `https://web3-systemic-agent.onrender.com`

Paid endpoints use the **x402** protocol (`eip155:8453` Base Mainnet USDC) with `PAYMENT-SIGNATURE` header (Base64 EIP-3009 authorization):

| Endpoint | Price (USDC) | Purpose |
| :--- | :--- | :--- |
| `POST /token/check` | `$0.005` | Fast static token honeypot & selector screening |
| `POST /preflight` | `$0.01` | Pre-sign transaction firewall, EIP-712 inspection, IPI defense & `eth_call` simulation |
| `POST /audit` | `$0.015` | Two-stage deterministic + Gemini LLM security audit |
| `POST /audit/deep` | `$0.25` | Deep EIP-1967 proxy slot resolution + verified Solidity source retrieval + Gemini LLM audit |

### Example x402 Flow
1. Send `POST https://web3-systemic-agent.onrender.com/preflight` without `PAYMENT-SIGNATURE` to receive the `402 Payment Required` JSON challenge (`accepts[0].payTo`, `accepts[0].amount`, `accepts[0].asset`).
2. Sign an EIP-3009 `transferWithAuthorization` payload for Base USDC and encode it as Base64.
3. Retry the `POST` request with header `PAYMENT-SIGNATURE: <base64_payload>` to receive the verified audit/firewall JSON response.

## Recommended Agent Decision Tree
1. Always run **Stage 1 free MCP tools** (`preflight_tx_firewall`, `check_token_honeypot`, `scan_contract_selectors`, `inspect_proxy_and_source`, `scan_dao_proposals`) first.
2. If Stage 1 returns `BLOCK` or critical honeypot flags, abort the transaction immediately at zero LLM/USDC cost.
3. Escalate to `deep_semantic_audit` (or HTTP `/audit` / `/audit/deep`) only when Stage 1 detects privileged admin backdoors, upgradeable proxies, verified source needing semantic review, or suspicious DAO governance calldata.

# Web3 Condition-Action Trigger Agent (x402 A2A + Hybrid LLM Auditor)

Agente autônomo Web3 com pipeline híbrido em **dois estágios** (filtragem determinística on-chain a custo zero + auditoria semântica por LLM) e monetização **Agente-para-Agente (A2A)** nativa via protocolo **x402 (EIP-3009 Gasless USDC)** na rede **Base**.

---

## 🔗 Prova de Liquidação Real On-Chain (Base Sepolia)

O ciclo de pagamento Agente-para-Agente via **x402 EIP-3009 (`transferWithAuthorization`)** foi validado e liquidado publicamente na blockchain **Base Sepolia (Chain ID: `84532`)** sem consumo de ETH de gás pelo comprador nem pelo servidor:

| Parâmetro | Valor / Link Público no Basescan |
| :--- | :--- |
| **Bloco Minerado** | `54583500` (`Status: Success`) |
| **Transaction Hash** | [`0xa02872819cef168637efe50d917441fd196cd03b4baafc7b9ff3dc624f18fc0d`](https://sepolia.basescan.org/tx/0xa02872819cef168637efe50d917441fd196cd03b4baafc7b9ff3dc624f18fc0d) |
| **Carteira do Agente (`PAY_TO_ADDRESS`)** | [`0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63`](https://sepolia.basescan.org/address/0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63#tokentxns) |
| **Carteira do Agente Comprador (Teste)** | [`0x4EbC7529d8c948ed1245A8106F2834969dbCec2b`](https://sepolia.basescan.org/address/0x4EbC7529d8c948ed1245A8106F2834969dbCec2b#tokentxns) |
| **Facilitador x402 (Patrocinador de Gás)** | [`0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf`](https://sepolia.basescan.org/address/0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf) (`https://x402.org/facilitator`) |
| **Contrato Oficial USDC (Base Sepolia)** | [`0x036CbD53842c5426634e7929541eC2318f3dCF7e`](https://sepolia.basescan.org/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e) |
| **Valor Liquidado por Chamada** | `0.01 USDC` (`10,000` unidades atômicas) |

---

## 🏗️ Arquitetura em Dois Estágios + x402 Gatekeeper

```mermaid
flowchart TD
    Client["Agente Comprador / Cliente B2B"] -->|POST /evaluate| Gate["x402 Payment Gatekeeper\n(EIP-3009 USDC)"]
    Gate -->|Sem cabeçalho X-PAYMENT| R402["HTTP 402 Payment Required\n(0.01 USDC -> PAY_TO_ADDRESS)"]
    Gate -->|Com X-PAYMENT válido| S1["Estágio 1: ChainInspector (AsyncWeb3)\nBytecode + Saldo Wei + Calldata Selector"]
    S1 -->|Condição falhou| ShortCircuit["Short-Circuit Determinístico\n(llm_invoked=False, Custo LLM = $0.00)"]
    S1 -->|Erro de RPC| Err503["HTTP 503 Service Unavailable\n(Pagamento NÃO liquidado / Sem cobrança)"]
    S1 -->|Passou| S2["Estágio 2: SemanticEvaluator (Gemini / OpenAI)\nCruza Proposta vs Bytecode + enforce_decision_policy"]
    ShortCircuit --> Settle["Liquidação x402 + Registro em SQLite (data/agent.db)"]
    S2 --> Settle
    Settle --> Resp["HTTP 200 OK: FinalAgentResponse + PaymentReceipt"]
```

---

## 📂 Estrutura do Repositório

* `src/schemas.py` — Contratos Pydantic v2 (`ConditionRulePayload`, `DeterministicResult`, `LLMAuditOutput`, `SemanticAuditResult`, `PaymentReceipt`, `FinalAgentResponse`).
* `src/chain_inspector.py` — Estágio 1 determinístico via `AsyncWeb3` com cache FIFO isolado por Chain ID e fallback automático de múltiplos RPCs.
* `src/semantic_evaluator.py` — Estágio 2 semântico (`GeminiSemanticEvaluator`, `OpenAISemanticEvaluator`, `MockSemanticEvaluator`), política determinística `enforce_decision_policy`, limite de entrada de 32k caracteres e telemetria de custos.
* `src/x402_payment.py` — Integração do protocolo x402 (`X402Config`, `NETWORK_PROFILES` para Base Sepolia/Mainnet e Arbitrum One, `MockX402Facilitator`, `HTTPX402Facilitator`, parsing JSON/Base64 e proteção anti-replay).
* `src/governance_connector.py` — Conector autônomo de propostas de DAOs (`SnapshotGovernanceConnector`, endpoint `POST /governance/audit-proposals` e extração automática de contratos/calldata).
* `src/storage.py` — Persistência assíncrona em SQLite (`data/agent.db`) com tabelas `evaluations`, `error_log` e `payments`, além de redação automática de chaves/segredos (`redact_secrets`).
* `src/task_worker.py` — Worker pool assíncrono em memória com TTL (1h) e capacidade máxima limitada (10.000 jobs).
* `src/engine.py` — Orquestrador central `ConditionAgentEngine`.
* `src/api.py` / `api.py` — Servidor HTTP FastAPI.
* `src/report.py` — Relatório CLI de telemetria de tokens, custos de IA, receita x402 e lucro líquido.
* `scripts/` — Scripts reutilizáveis de operação e validação on-chain:
  * `scripts/run_live_scenarios.py` — Executa os 5 cenários reais na Base Sepolia com Gemini.
  * `scripts/client_agent_x402.py` — Demonstração completa do fluxo A2A (`HTTP 402` $\rightarrow$ assinatura $\rightarrow$ `HTTP 200`).
  * `scripts/setup_buyer_wallet.py` — Inspeciona ou gera a carteira compradora de teste e consulta saldos de ETH/USDC na Base Sepolia.
  * `scripts/send_live_usdc.py` — Executa liquidação real on-chain via EIP-3009 Gasless no facilitador oficial `https://x402.org/facilitator`.
  * `scripts/governance_listener.py` — Scanner autônomo de propostas reais de DAOs via Snapshot GraphQL API + Gemini.

---

## ⚙️ Configuração (`.env`)

```env
GEMINI_API_KEY=sua_chave_aqui
PAY_TO_ADDRESS=0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63
X402_ENABLED=true
X402_NETWORK=eip155:84532
X402_PRICE_EVALUATE=0.01
```

---

## 🚀 Comandos Principais

### 1. Subir a API HTTP
```powershell
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Executar Pagamento Real On-Chain (EIP-3009 Gasless na Base Sepolia)
```powershell
# Verificar saldo de USDC da carteira compradora na Base Sepolia
python scripts/setup_buyer_wallet.py

# Liquidar 0.01 USDC on-chain para PAY_TO_ADDRESS sem gastar ETH de gás
python scripts/send_live_usdc.py
```

### 3. Executar Simulação Completa A2A + Relatório Financeiro
```powershell
# Fluxo A2A (HTTP 402 -> Assinatura -> Auditoria Gemini -> Recibo)
python scripts/client_agent_x402.py

# Executar os 5 cenários de auditoria (Benigno, Exploit, Auditado, Short-Circuit, Truncamento)
python scripts/run_live_scenarios.py

# Relatório consolidado do SQLite (Tokens, Custos USD, Receita USDC e Lucro Líquido)
python -m src.report
```

### 4. Executar Suíte de Testes Automatizados
```powershell
# Suíte rápida (245 testes unitários e de casos de borda, sem rede externa)
python -m pytest -v --tb=short

# Suíte de integração ao vivo contra a Base Sepolia (11 testes on-chain)
python -m pytest -m integration -v
```

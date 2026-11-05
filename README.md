# Web3 Condition-Action Trigger Agent (x402 A2A + Hybrid LLM Auditor)

Agente autônomo Web3 com pipeline híbrido em **dois estágios** (filtragem determinística on-chain a custo zero + auditoria semântica por LLM) e monetização **Agente-para-Agente (A2A)** nativa via protocolo **x402 (EIP-3009 Gasless USDC)** na rede **Base**.

---

## 🔗 Provas de Liquidação Real On-Chain (Base Sepolia)

O ciclo de pagamento Agente-para-Agente via **x402 EIP-3009 (`transferWithAuthorization`)** foi validado e liquidado publicamente na blockchain **Base Sepolia (Chain ID: `84532`)** sem consumo de ETH de gás pelo comprador nem pelo servidor de auditoria:

| Parâmetro | Transação 1 (Liquidação Direta) | Transação 2 (Captura On-Chain ao Vivo + Auditoria API) |
| :--- | :--- | :--- |
| **Transaction Hash** | [`0xa02872819cef168637efe50d917441fd196cd03b4baafc7b9ff3dc624f18fc0d`](https://sepolia.basescan.org/tx/0xa02872819cef168637efe50d917441fd196cd03b4baafc7b9ff3dc624f18fc0d) | [`0x6aa7c671469d2d9a2e0a8eb3682d285394795a2da369573214f7eaad6759b647`](https://sepolia.basescan.org/tx/0x6aa7c671469d2d9a2e0a8eb3682d285394795a2da369573214f7eaad6759b647) |
| **Bloco Minerado** | `54583500` (`Status: Success`) | `54644484` (`Status: Success`) |
| **Transação On-Chain Auditada** | Transação sintética de teste (payload de governança) | [`0x87b868f7a98ce9ab9ea84775da1ea8468e775c2416c3fce4f636de74f40226ab`](https://sepolia.basescan.org/tx/0x87b868f7a98ce9ab9ea84775da1ea8468e775c2416c3fce4f636de74f40226ab) (capturada ao vivo do mempool/bloco) |
| **Carteira do Agente (`PAY_TO_ADDRESS`)** | [`0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63`](https://sepolia.basescan.org/address/0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63#tokentxns) | [`0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63`](https://sepolia.basescan.org/address/0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63#tokentxns) |
| **Carteira Compradora (Agente A2A)** | [`0x4EbC7529d8c948ed1245A8106F2834969dbCec2b`](https://sepolia.basescan.org/address/0x4EbC7529d8c948ed1245A8106F2834969dbCec2b#tokentxns) | [`0x4EbC7529d8c948ed1245A8106F2834969dbCec2b`](https://sepolia.basescan.org/address/0x4EbC7529d8c948ed1245A8106F2834969dbCec2b#tokentxns) |
| **Facilitador x402 (Patrocinador de Gás)** | [`0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf`](https://sepolia.basescan.org/address/0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf) (`https://x402.org/facilitator`) | [`0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf`](https://sepolia.basescan.org/address/0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf) (`https://x402.org/facilitator`) |
| **Contrato Oficial USDC** | [`0x036CbD53842c5426634e7929541eC2318f3dCF7e`](https://sepolia.basescan.org/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e) | [`0x036CbD53842c5426634e7929541eC2318f3dCF7e`](https://sepolia.basescan.org/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e) |
| **Valor Liquidado por Chamada** | `0.01 USDC` (`10.000` unidades atômicas) | `0.01 USDC` (`10.000` unidades atômicas) |
| **Custo de Gás para Comprador/Vendedor** | `0.00 ETH` (Gasless EIP-3009) | `0.00 ETH` (Gasless EIP-3009) |

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
* `src/semantic_evaluator.py` — Estágio 2 semântico (`GeminiSemanticEvaluator` com `gemini-3.5-flash-lite`, `OpenAISemanticEvaluator`, `MockSemanticEvaluator`), política determinística `enforce_decision_policy`, cap de 32k caracteres e telemetria de custos.
* `src/x402_payment.py` — Integração do protocolo x402 (`X402Config`, perfis `NETWORK_PROFILES` para Base Sepolia/Mainnet e Arbitrum One, `MockX402Facilitator`, `HTTPX402Facilitator`, parsing JSON/Base64 e proteção anti-replay).
* `src/governance_connector.py` — Conector de governança de DAOs (`SnapshotGovernanceConnector`, `WebhookAlertDispatcher` para Discord/Slack, endpoint `POST /governance/audit-proposals` e extração automática de contratos/calldata).
* `src/storage.py` — Persistência assíncrona em SQLite (`data/agent.db`) com tabelas `evaluations`, `error_log` e `payments`, além de redação automática de chaves/segredos (`redact_secrets`).
* `src/task_worker.py` — Worker pool assíncrono em memória com TTL (1h) e capacidade máxima limitada (10.000 jobs).
* `src/engine.py` — Orquestrador central `ConditionAgentEngine`.
* `src/api.py` / `api.py` — Servidor HTTP FastAPI unificado com gatekeeper x402.
* `src/report.py` — Relatório CLI de telemetria de tokens, custos de IA, receita x402 e lucro líquido.
* `Dockerfile` / `docker-compose.yml` / `.dockerignore` / `.env.example` — Containerização pronta para produção 24/7 (usuário não-root `appuser`, volume persistente para banco SQLite e healthcheck ativo).
* `scripts/` — Scripts operacionais e executáveis:
  * `scripts/client_agent_x402.py` — Cliente A2A com suporte a servidor remoto (`--url`), captura de transações on-chain ao vivo (`--fetch-live-tx`) e liquidação real na Base Sepolia (`--live-onchain`).
  * `scripts/governance_listener.py` — Sentinel bot de monitoramento de governança de DAOs via Snapshot GraphQL API com despacho de alertas ricos via webhook (`--webhook-url`, `--public-url`, `--min-alert-level`).
  * `scripts/run_live_scenarios.py` — Executa os 5 cenários reais na Base Sepolia com Gemini.
  * `scripts/setup_buyer_wallet.py` — Inspeciona ou gera a carteira compradora de teste e consulta saldos de ETH/USDC na Base Sepolia.
  * `scripts/send_live_usdc.py` — Executa liquidação real on-chain via EIP-3009 Gasless no facilitador oficial `https://x402.org/facilitator`.
* `tests/` & `src/test_*.py` — Suíte com 363 testes automatizados (352 unitários/segurança/regressão e 11 de integração ao vivo).

---

## ⚙️ Configuração do Ambiente (`.env`)

Copie o arquivo modelo e configure suas chaves:
```bash
cp .env.example .env
```

Exemplo de configuração para **Staging / Testnet (Base Sepolia)**:
```env
GEMINI_API_KEY=sua_chave_gemini_aqui
GEMINI_MODEL=gemini-3.5-flash-lite
PAY_TO_ADDRESS=0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63
X402_ENABLED=true
X402_NETWORK=eip155:84532
X402_PRICE_EVALUATE=0.01
X402_USE_LIVE_FACILITATOR=false
PUBLIC_API_URL=http://localhost:8000
ALERT_WEBHOOK_URL=
```

---

## 🐳 Docker & Implantação 24/7 em Cloud (Railway / Render / VPS)

O serviço está totalmente empacotado para execução contínua em contêineres Docker, rodando como usuário sem privilégios (`appuser`), com verificação contínua de saúde (`HEALTHCHECK`) e persistência segura em volume de dados:

### 1. Inicialização com Docker Compose
```bash
# 1. Preparar variáveis de ambiente
cp .env.example .env

# 2. Construir e iniciar o serviço em segundo plano
docker compose up -d --build

# 3. Inspecionar logs em tempo real
docker compose logs -f
```

### 2. Variáveis de Ambiente para Produção na Base Mainnet
Para publicar em plataformas PaaS (Railway, Render, Fly.io) apontando para a rede principal da Base:

| Variável | Valor de Produção (Base Mainnet) | Descrição |
| :--- | :--- | :--- |
| `GEMINI_API_KEY` | `AIza...` | Chave de produção do Google Gemini |
| `GEMINI_MODEL` | `gemini-3.5-flash-lite` | Modelo de alta velocidade e custo reduzido |
| `X402_ENABLED` | `true` | Ativa a cobrança x402 A2A |
| `X402_NETWORK` | `eip155:8453` | Identificador CAIP-2 da **Base Mainnet** |
| `X402_USE_LIVE_FACILITATOR` | `true` | Habilita liquidação real via facilitador HTTP x402 |
| `PAY_TO_ADDRESS` | `0xSuaCarteiraOficialBase` | Endereço EVM que recebe o USDC líquido |
| `PUBLIC_API_URL` | `https://sua-api.up.railway.app` | URL pública da API usada nos links dos webhooks |
| `ALERT_WEBHOOK_URL` | `https://discord.com/api/webhooks/...` | Canal de alerta no Discord ou Slack |

---

## 🚀 Comandos Principais e Operação

### 1. Subir a API Localmente (Modo Desenvolvimento)
```powershell
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Agente Cliente x402 & Captura On-Chain ao Vivo (`scripts/client_agent_x402.py`)
O cliente autônomo demonstra o ciclo completo A2A, suportando servidores locais ou remotos e captura de transações reais:

```powershell
# Ciclo A2A padrão contra servidor local ou remoto (HTTP 402 -> Assinatura EIP-3009 -> HTTP 200 OK)
python scripts/client_agent_x402.py --url http://127.0.0.1:8000

# Captura transação real recém-minerada na Base Sepolia, audita via Gemini e liquida 0.01 USDC on-chain
python scripts/client_agent_x402.py --fetch-live-tx --live-onchain
```

### 3. DAO Governance Scanner & Sentinel Webhook Bot (`scripts/governance_listener.py`)
Monitora propostas em tempo real no Snapshot, extrai calldata e contratos EVM, executa auditoria em dois estágios e despacha alertas enriquecidos:

```powershell
# Auditar propostas ao vivo e despachar alertas no Discord/Slack para severidade WARNING ou CRITICAL
python scripts/governance_listener.py --limit 3 --webhook-url "https://discord.com/api/webhooks/..." --public-url "https://your-api.com" --min-alert-level WARNING

# Modo curado determinístico (teste offline sem consumo de RPC de governança)
python scripts/governance_listener.py --curated
```

### 4. Pagamento e Validação de Carteira On-Chain
```powershell
# Inspecionar saldo da carteira compradora na Base Sepolia
python scripts/setup_buyer_wallet.py

# Liquidar 0.01 USDC on-chain via EIP-3009 Gasless no facilitador oficial
python scripts/send_live_usdc.py

# Relatório consolidado do SQLite (Tokens, Custos USD, Receita USDC e Lucro Líquido)
python -m src.report
```

---

## 🧪 Suíte de Testes Automatizados

O repositório possui cobertura ampla com **363 testes automatizados** e **zero advertências**:

```powershell
# Suíte completa de testes unitários, segurança, regressão e Docker (352 testes)
python -m pytest -v --tb=short

# Suíte de integração ao vivo contra a blockchain Base Sepolia (11 testes on-chain)
python -m pytest -m integration -v
```

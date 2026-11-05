# Guia de Execução: Próximas Etapas (Fases B2 a B5)

Este documento estabelece o roteiro prático e detalhado para a execução das próximas etapas do **Web3 Condition-Action Trigger Agent**, consolidando os procedimentos técnicos, comandos e responsabilidades para cada fase.

---

## 🗺️ Visão Geral do Fluxo

```mermaid
flowchart LR
    B2["Fase B2: Testes Reais Gratuitos\n(Base Sepolia + Gemini Real)"] --> B3["Fase B3: Integração x402\n(Flag X402_ENABLED=false)"]
    B3 --> B4["Fase B4: Carteira & Teste Pago E2E\n(USDC em Base Sepolia)"]
    B4 --> B5["Fase B5: Conectores & Produção\n(Snapshot/Safe + Mainnet)"]
```

---

## 1. Fase B2 — Testes Reais Gratuitos ✅ CONCLUÍDA

### Resultados Empíricos Obtidos (Base Sepolia + Gemini Real)
O script reutilizável [`scripts/run_live_scenarios.py`](file:///C:/Users/rafae/Desktop/Nova%20pasta/scripts/run_live_scenarios.py) foi executado com sucesso, validando os 5 cenários reais contra nós RPC da Base Sepolia e autenticação com Gemini:

| # | Cenário | S1 Passou | LLM Invocada | Score | Decisão | Tokens (In/Out) | Custo Estimado | Latência |
|---|---|---|---|---|---|---|---|---|
| **1** | **Proposta Benigna** | Sim | Sim | 1.0 | `APPROVE` | 737 / 109 | $0,000352 | 1.5s |
| **2** | **Ataque Discrepante (Exploit)** | Sim | Sim | 9.5 | `REJECT` | 637 / 163 | $0,000387 | 1.2s |
| **3** | **Operação Crítica Auditada** | Sim | Sim | 7.5 | `MANUAL_REVIEW` | 700 / 128 | $0,000364 | 2.8s |
| **4** | **Short-Circuit Estágio 1** | **Não** | **Não** | N/A | `HALTED` | **0 / 0** | **$0,000000** | **7.1ms** |
| **5** | **Anti-Abuso (>40k chars)** | Sim | Sim | 9.5 | `REJECT` | 5.012 / 221 | $0,001769 | 1.7s |

### Validação Financeira
* **Custo Médio por Chamada LLM:** ~$0,00038 USD (menos de 0,04 centavos de dólar).
* **Pior Caso (Payload Massivo truncado em 32k):** $0,001769 USD (menos de 0,18 centavos de dólar).
* **Margem Comercial vs. Preço de US$ 0,01:**
  * No caso típico: **96,4% de margem de lucro**.
  * No pior caso extremo: **82,3% de margem de lucro**.
* **Comprovação:** O preço de **US$ 0,01 por avaliação** é matematicamente sustentável e altamente lucrativo.
* **Comando para reexecução:** `python scripts/run_live_scenarios.py`

---

## 2. Fase B3 — Integração do Protocolo x402 (A2A sob Flag) ✅ CONCLUÍDA

### Entregas Validadas (233 testes passando, 0 falhas, 0 warnings)
1. **Módulo de Pagamentos ([`src/x402_payment.py`](file:///C:/Users/rafae/Desktop/Nova%20pasta/src/x402_payment.py)):**
   * `X402Config` controlado por `X402_ENABLED=false` (padrão gratuito preservando dev/testes), `X402_PRICE_EVALUATE=0.01`, `X402_NETWORK=eip155:84532` e `PAY_TO_ADDRESS`.
   * Suporte a cabeçalhos `X-PAYMENT` e `PAYMENT-SIGNATURE` (JSON puro ou Base64).
   * Facilitadores plugáveis: `MockX402Facilitator` (determinístico para testes locais) e `HTTPX402Facilitator` (integração HTTP com facilitador x402).
2. **Mapeamento de Rotas e Preço Dinâmico ([`src/api.py`](file:///C:/Users/rafae/Desktop/Nova%20pasta/src/api.py)):**
   * **Rotas Gratuitas:** `/health`, `/rules/validate`, `/metrics/summary`, `/logs/errors`, `/jobs/{id}` e `/payments`.
   * **Rotas Pagas (quando `X402_ENABLED=true`):** `/evaluate` ($0,01 USDC = `10000` unidades atômicas), `/rules/enqueue` ($0,01 USDC) e `/rules/evaluate-batch` ($0,01 \times N$ itens).
   * Validação de schema (`HTTP 422`) executada **antes** da cobrança.
3. **Política Estrita de Não-Cobrança em Caso de Erro (`HTTP 503`):**
   * Qualquer falha de RPC no Estágio 1 ou erro interno durante a avaliação responde com `HTTP 503 Service Unavailable` (`payment_settled: false`) **sem invocar `facilitator.settle()`**, garantindo que o cliente nunca seja cobrado por erro do agente.
4. **Ledger SQLite e Proteção Anti-Replay ([`src/storage.py`](file:///C:/Users/rafae/Desktop/Nova%20pasta/src/storage.py)):**
   * Tabela `payments` em `data/agent.db` com índice único por `payment_id` bloqueando ataques de replay (`HTTP 402`).
   * Métricas financeiras (`total_payments_settled`, `total_revenue_usdc`, `net_profit_usd`) integradas ao `python -m src.report` e ao endpoint `GET /payments`.
5. **Suíte Dedicada ([`src/test_phase_b3.py`](file:///C:/Users/rafae/Desktop/Nova%20pasta/src/test_phase_b3.py)):**
   * 58 novos testes cobrindo todo o fluxo x402.

---

## 3. Fase B4 — Carteira de Testnet e Validação Paga E2E (Local + On-Chain) ✅ CONCLUÍDA

### Resultados Obtidos e Prova On-Chain na Base Sepolia
1. **Configuração das Carteiras:**
   * **Carteira de Recebimento do Agente (`PAY_TO_ADDRESS`):** `0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63`
   * **Carteira Persistente do Agente Comprador:** `0x4EbC7529d8c948ed1245A8106F2834969dbCec2b`
   * **Facilitador Público x402 (Patrocinador de Gás):** `0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf` (`https://x402.org/facilitator`)
   * **Contrato Oficial USDC (Base Sepolia):** `0x036CbD53842c5426634e7929541eC2318f3dCF7e`
2. **Prova Imutável de Liquidação On-Chain (EIP-3009 Gasless):**
   * **Bloco Minerado:** `54583500` (Base Sepolia, Chain ID `84532`)
   * **Transaction Hash:** `0xa02872819cef168637efe50d917441fd196cd03b4baafc7b9ff3dc624f18fc0d`
   * **Link Oficial no Basescan:** [https://sepolia.basescan.org/tx/0xa02872819cef168637efe50d917441fd196cd03b4baafc7b9ff3dc624f18fc0d](https://sepolia.basescan.org/tx/0xa02872819cef168637efe50d917441fd196cd03b4baafc7b9ff3dc624f18fc0d)
   * **Histórico de Tokens da Carteira Recebedora:** [https://sepolia.basescan.org/address/0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63#tokentxns](https://sepolia.basescan.org/address/0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63#tokentxns)
   * **Custo de Gás para o Comprador e para o Agente:** `0.00 ETH` (100% subsidiado pelo facilitador x402 via `transferWithAuthorization`).
3. **Scripts Operacionais Entregues:**
   * [`scripts/setup_buyer_wallet.py`](file:///C:/Users/rafae/Desktop/Nova%20pasta/scripts/setup_buyer_wallet.py): Gera/inspeciona a carteira compradora e consulta saldos reais de ETH e USDC na Base Sepolia.
   * [`scripts/send_live_usdc.py`](file:///C:/Users/rafae/Desktop/Nova%20pasta/scripts/send_live_usdc.py): Assina autorização EIP-3009 gasless e liquida `0.01 USDC` on-chain via `https://x402.org/facilitator`, gravando o recibo no SQLite (`data/agent.db`).
   * [`scripts/client_agent_x402.py`](file:///C:/Users/rafae/Desktop/Nova%20pasta/scripts/client_agent_x402.py): Demonstra o fluxo completo A2A (`HTTP 402` $\rightarrow$ assinatura ECDSA $\rightarrow$ auditoria Gemini $\rightarrow$ `HTTP 200 OK` + `PaymentReceipt`).
4. **Comandos para Reexecução:**
   ```powershell
   # Inspecionar saldos on-chain da carteira compradora
   python scripts/setup_buyer_wallet.py

   # Executar pagamento real de 0.01 USDC on-chain (Gasless EIP-3009)
   python scripts/send_live_usdc.py

   # Executar ciclo completo A2A da API com auditoria Gemini
   python scripts/client_agent_x402.py

   # Exibir relatório financeiro e operacional consolidado
   python -m src.report
   ```

---

## 4. Fase B5 — Atração de Demanda, Produção e Conectores ✅ CONCLUÍDA

### Entregas Validadas (324 testes unitários + 11 de integração on-chain = 335 testes passando)
1. **Conector de Governança de DAOs ([`src/governance_connector.py`](file:///C:/Users/rafae/Desktop/Nova%20pasta/src/governance_connector.py) + [`scripts/governance_listener.py`](file:///C:/Users/rafae/Desktop/Nova%20pasta/scripts/governance_listener.py)):**
   * Integração ao vivo com a API GraphQL pública do **Snapshot** (`https://hub.snapshot.org/graphql`), consultando propostas reais de DAOs (`arbitrumfoundation.eth`, `aavedao.eth`, `ens.eth`) com fallback resiliente para propostas curadas (`--curated`).
   * Extração heurística automática de contratos EVM e seletores de calldata (`transferOwnership`, `upgradeTo`, `transfer`) embutidos no corpo das propostas.
   * Classificação estruturada de alertas (`CRITICAL` $\rightarrow$ `REJECT`, `WARNING` $\rightarrow$ `MANUAL_REVIEW`, `INFO` $\rightarrow$ `APPROVE`) e persistência no SQLite (`source="governance_listener"`).
   * Novo endpoint HTTP na API: `POST /governance/audit-proposals`.
2. **Perfis Multi-Rede e Chaveamento Automático Testnet $\leftrightarrow$ Mainnet ([`src/x402_payment.py`](file:///C:/Users/rafae/Desktop/Nova%20pasta/src/x402_payment.py)):**
   * Registro `NETWORK_PROFILES` com resolução automática de contratos oficiais de USDC, Chain IDs e RPCs para:
     * **Base Sepolia (`eip155:84532`):** USDC `0x036CbD53842c5426634e7929541eC2318f3dCF7e`
     * **Base Mainnet (`eip155:8453`):** USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`
     * **Arbitrum One (`eip155:42161`):** USDC `0xaf88d065e77c8cC2239327C5EDb3A432268e5831`
   * Fábrica `get_x402_facilitator` com suporte a `X402_USE_LIVE_FACILITATOR=true`.
3. **Suíte de Testes e Auditoria de Segurança Git ([`src/test_phase_b5.py`](file:///C:/Users/rafae/Desktop/Nova%20pasta/src/test_phase_b5.py)):**
   * 79 novos testes validando os perfis de rede, o conector do Snapshot, o endpoint de governança e a blindagem do Git (`git check-ignore` e `git ls-files` garantindo zero vazamento de `.env`, `.buyer_wallet.json` ou bancos `.db`).
4. **Comandos para Execução:**
   ```powershell
   # Auditar propostas reais ao vivo do Snapshot com Gemini na Base Sepolia
   python scripts/governance_listener.py --limit 3

   # Auditar propostas curadas determinísticas (APPROVE, REJECT, MANUAL_REVIEW)
   python scripts/governance_listener.py --curated
   ```

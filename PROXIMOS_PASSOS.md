# Playbook de Go-Live e Monetização (Daqui para Frente)

## 📌 Ponto de Partida Atual
* **Engenharia 100% Concluída:** A arquitetura completa foi implementada e validada com 363 testes automatizados aprovados com 0 warnings, incluindo [`Dockerfile`](file:///C:/Users/rafae/Desktop/Nova%20pasta/Dockerfile), [`docker-compose.yml`](file:///C:/Users/rafae/Desktop/Nova%20pasta/docker-compose.yml), gatekeeper x402 com liquidação gasless EIP-3009 na rota `POST /evaluate`, captura de transações ao vivo e bot sentinela com webhooks.
* **Provas On-Chain Reais:** Duas liquidações públicas já foram confirmadas na Base Sepolia sem custo de gás para o agente ou comprador.
* **Foco Daqui para Frente:** A fase de desenvolvimento técnico está encerrada. O foco agora é **100% operacional, comercial e financeiro** para colocar o contêiner em execução 24/7 na nuvem e gerar receita em USDC na **Base Mainnet**.

---

## 🚀 Passo 1: Publicar o Contêiner 24/7 na Nuvem (Deploy)

### 1.1 Versionar e Subir o Código para o GitHub
Execute no terminal local a partir da raiz do projeto:
```bash
git add .
git commit -m "chore: release production v1.0"
git push origin main
```

### 1.2 Criar o Projeto em Plataforma PaaS (Railway.app ou Render.com)
1. Acesse [Railway.app](https://railway.app/) ou [Render.com](https://render.com/) e autentique-se com sua conta GitHub.
2. Crie um **New Service** a partir do repositório GitHub do projeto.
3. A plataforma detectará automaticamente o [`Dockerfile`](file:///C:/Users/rafae/Desktop/Nova%20pasta/Dockerfile) na raiz, executando a build sob imagem leve `python:3.11-slim`, criando o usuário seguro não-root `appuser` e expondo a porta `8000`.

### 1.3 Configurar o Volume Persistente para o Banco de Dados
1. No painel do serviço na nuvem (Railway ou Render), acesse a aba **Volumes** (ou **Disks**).
2. Adicione um volume persistente com o ponto de montagem exato:
   * **Mount Path:** `/app/data`
3. Isso garante que o banco SQLite (`/app/data/agent.db`), os logs de auditoria e todo o histórico financeiro de pagamentos x402 sejam preservados permanentemente entre novos deploys ou reinicializações do contêiner.

---

## 💳 Passo 2: Virar a Chave para Base Mainnet (Receber USDC Real)

### 2.1 Configurar Variáveis de Ambiente em Produção
No painel de variáveis de ambiente da nuvem (Railway / Render), defina os parâmetros para operar na rede principal da Base (**Chain ID: `8453`**), onde cada unidade de USDC recebida equivale a 1 dólar comercial real (1:1):

```env
# Provedor Cognitivo (Google Gemini)
GEMINI_API_KEY=sua_chave_gemini_de_producao
GEMINI_MODEL=gemini-3.5-flash-lite

# Carteira Oficial de Recebimento na Base Mainnet
PAY_TO_ADDRESS=0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63

# Protocolo x402 de Micropagamentos A2A
X402_ENABLED=true
X402_NETWORK=eip155:8453
X402_PRICE_EVALUATE=0.05
X402_USE_LIVE_FACILITATOR=true
FACILITATOR_URL=https://x402.org/facilitator

# Infraestrutura e Despacho de Alertas
PUBLIC_API_URL=https://sua-api-em-producao.up.railway.app
ALERT_WEBHOOK_URL=https://discord.com/api/webhooks/SEU_ID/SEU_TOKEN
LEDGER_DB_PATH=/app/data/agent.db
```

> [!NOTE]
> O preço por chamada `X402_PRICE_EVALUATE` pode ser configurado entre `0.01` e `0.05` USDC. Como o custo médio da inferência com o modelo `gemini-3.5-flash-lite` é inferior a **$0,0004 USD**, a margem bruta de lucro operacional situa-se acima de **96% a 99%**.

### 2.2 Validar o Deploy em Produção (Smoke Test)
Assim que o build for concluído, valide os endpoints públicos no navegador ou terminal:
```bash
# Teste de conectividade e status do serviço
curl https://sua-api-em-producao.up.railway.app/

# Verificação detalhada de saúde e dependências
curl https://sua-api-em-producao.up.railway.app/health
```
Ambos devem responder com código `HTTP 200 OK`.

---

## 🎯 Passo 3: Ativar os 3 Canais de Aquisição de Clientes e Receita

### Canal A — Diretório x402 & Agentes Autônomos (A2A)
* **Ecossistema:** Agentes autônomos de tesouraria, bots de arbitrage e pipelines de DeFi precisam validar riscos antes de assinar transações on-chain.
* **Ação:** Registrar a `PUBLIC_API_URL` nos catálogos abertos do protocolo x402 (ex: x402 Bazaar, registros de serviços de agentes e ecossistema Coinbase CDP AgentKit).
* **Mecânica:** Outros agentes autônomos enviam requisições para `POST /evaluate`, recebem o desafio `HTTP 402 Payment Required`, assinam digitalmente a autorização EIP-3009 gasless e realizam o pagamento automaticamente máquina-para-máquina (A2A).

### Canal B — Bot Sentinela de Governança DAO (Geração Automática de Demanda)
* **Objetivo:** Identificar propostas suspeitas ou perigosas em grandes DAOs e converter alertas públicos em receita direta de auditoria.
* **Ação:** Configurar um agendador periódico (Cron Job no Railway, GitHub Actions agendado a cada 1 a 4 horas ou script em VPS) executando:
  ```bash
  python scripts/governance_listener.py --limit 5 --min-alert-level WARNING --webhook-url "https://discord.com/api/webhooks/SEU_ID/SEU_TOKEN" --public-url "https://sua-api-em-producao.up.railway.app"
  ```
* **Mecânica de Conversão:**
  1. O bot consulta propostas recém-criadas na Snapshot para DAOs de alto volume (Aave, Arbitrum Foundation, ENS).
  2. Executa a auditoria em dois estágios (filtragem determinística on-chain + auditoria semântica por LLM).
  3. Quando detecta anomalias de severidade `WARNING` ou `CRITICAL`, despacha automaticamente um embed rico no Discord ou Slack com resumo do risco e um link direto para contratação da auditoria profunda no endpoint protegido `PUBLIC_API_URL/evaluate`.

### Canal C — Base Builder Grants (Financiamento Direto)
* **Objetivo:** Captar subsídios de fomento (grants) da Base e da Coinbase.
* **Ação:** Submeter o projeto no portal [Base Builder Grants](https://base.org/builders) e no programa de incentivos para ecossistema de agentes autônomos da Coinbase Developer Platform (CDP).
* **Diferenciais Prontos para a Aplicação:**
  * Uso nativo da infraestrutura da **Base** e de contratos oficiais de USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`).
  * Utilização real do padrão **EIP-3009 gasless** via protocolo x402 com transações comprovadas on-chain.
  * Suíte de testes com 363 testes automatizados e contêiner Docker pronto para escala.

---

## 💰 Passo 4: Gestão de Caixa e Saque dos Lucros (USDC $\rightarrow$ PIX)

### 4.1 Monitoramento de Receita e Margem em Tempo Real
Acompanhe os resultados financeiros e a margem operacional a qualquer momento consultando a API ou via CLI:

```bash
# Relatório consolidado no terminal (Tokens, Custos de LLM, Volume USDC e Lucro Líquido)
python -m src.report

# Consulta via API pública
curl https://sua-api-em-producao.up.railway.app/metrics/summary
curl https://sua-api-em-producao.up.railway.app/payments
```

O sistema confronta o total de USDC liquidado contra os custos de inferência da API do Gemini, evidenciando o lucro líquido acumulado no banco de dados.

### 4.2 Acesso e Saque dos Recursos (USDC $\rightarrow$ BRL via PIX)
1. **Entrada Direta dos Fundos:** Todos os micropagamentos das avaliações pagas são liquidados on-chain e caem diretamente, sem qualquer retenção por intermediários, no endereço configurado:
   * **Carteira de Recebimento:** `0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63` (na rede **Base Mainnet**).
2. **Visualização do Saldo:** Conecte a carteira (MetaMask, Rabby ou Coinbase Wallet) apontando para a rede **Base (Chain ID 8453)** e visualize os tokens USDC oficiais recebidos.
3. **Conversão e Saque para Conta Bancária:**
   * Envie o saldo de USDC da carteira na rede Base para o endereço de depósito de USDC (rede Base) da sua corretora de preferência (ex: Binance, Coinbase ou Bybit).
   * Na corretora, converta USDC para Reais (BRL).
   * Realize a transferência via **PIX** imediatamente para sua conta bancária pessoal ou PJ.

  agy --conversation=bdacdb0d-91c4-4744-b36d-ea595f0f1bf1

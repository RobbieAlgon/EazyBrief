# EazyBrief

EazyBrief é uma plataforma que simplifica a criação de briefings profissionais usando inteligência artificial.

## Funcionalidades

- Criação rápida de briefings usando IA
- Múltiplos templates disponíveis
- Exportação em diferentes formatos (PDF, DOCX, TXT, HTML)
- Sistema de planos (Free, Pro, Premium)
- Integração com Stripe para pagamentos
- Dashboard personalizado
- Histórico de briefings

## Tecnologias Utilizadas

- Python/Flask
- Firebase (Autenticação, Database, Storage)
- Stripe (Pagamentos)
- Google Cloud (Vertex AI)
- Groq (LLM)

## Configuração do Ambiente

1. Clone o repositório:
```bash
git clone https://github.com/RobbieAlgon/EazyBrief.git
cd EazyBrief
```

2. Crie um ambiente virtual e instale as dependências:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

3. Configure as variáveis de ambiente:
Crie um arquivo `.env` na raiz do projeto com as seguintes variáveis:
```
FLASK_SECRET_KEY=sua_chave_secreta
FIREBASE_API_KEY=sua_chave_api
FIREBASE_AUTH_DOMAIN=seu_dominio
FIREBASE_DATABASE_URL=sua_url
FIREBASE_PROJECT_ID=seu_projeto
FIREBASE_STORAGE_BUCKET=seu_bucket
FIREBASE_MESSAGING_SENDER_ID=seu_sender_id
FIREBASE_APP_ID=seu_app_id
FIREBASE_CREDENTIALS_JSON=seu_json_credenciais
STRIPE_SECRET_KEY=sua_chave_stripe
STRIPE_PUBLISHABLE_KEY=sua_chave_publica
STRIPE_PRO_PRICE_ID=seu_price_id
STRIPE_PREMIUM_PRICE_ID=seu_price_id
STRIPE_WEBHOOK_SECRET=seu_webhook_secret
GCP_PROJECT_ID=seu_projeto_gcp
GROQ_API_KEY=sua_chave_groq
```

4. Execute a aplicação:
```bash
python app.py
```

## Deploy

O projeto está configurado para deploy na Vercel. Para fazer o deploy:

1. Faça push do código para o GitHub
2. Conecte seu repositório na Vercel
3. Configure as variáveis de ambiente na Vercel
4. Deploy!

## Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes. 
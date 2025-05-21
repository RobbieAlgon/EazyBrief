# Brief Generator

A web application for generating professional briefs using AI. Built with Flask and integrated with various services including Firebase, Stripe, and Groq.

## Features

- User authentication and authorization
- AI-powered brief generation
- Multiple export formats (PDF, DOCX, TXT, HTML)
- Subscription plans with Stripe integration
- Firebase integration for data storage
- Integration with various services (Google Drive, Trello, Slack, Microsoft Teams)

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd brief-generator
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with the following variables:
```
FLASK_SECRET_KEY=your_secret_key
FIREBASE_API_KEY=your_firebase_api_key
FIREBASE_AUTH_DOMAIN=your_firebase_auth_domain
FIREBASE_DATABASE_URL=your_firebase_database_url
FIREBASE_PROJECT_ID=your_firebase_project_id
FIREBASE_STORAGE_BUCKET=your_firebase_storage_bucket
FIREBASE_MESSAGING_SENDER_ID=your_firebase_messaging_sender_id
FIREBASE_APP_ID=your_firebase_app_id
FIREBASE_CREDENTIALS_JSON=your_firebase_credentials_json
GROQ_API_KEY=your_groq_api_key
STRIPE_SECRET_KEY=your_stripe_secret_key
STRIPE_PUBLISHABLE_KEY=your_stripe_publishable_key
STRIPE_WEBHOOK_SECRET=your_stripe_webhook_secret
STRIPE_PRO_PRICE_ID=your_stripe_pro_price_id
STRIPE_PREMIUM_PRICE_ID=your_stripe_premium_price_id
```

5. Run the application:
```bash
python app.py
```

## Environment Variables

- `FLASK_SECRET_KEY`: Secret key for Flask session management
- `FIREBASE_*`: Firebase configuration and credentials
- `GROQ_API_KEY`: API key for Groq AI service
- `STRIPE_*`: Stripe configuration for payment processing

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
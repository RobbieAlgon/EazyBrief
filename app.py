import os
from dotenv import load_dotenv
load_dotenv()  # Carrega variáveis do .env

import json
import base64
import datetime
import tempfile
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_babel import Babel
import firebase_admin
from firebase_admin import credentials, auth, db
from google.cloud import aiplatform
from google.cloud.aiplatform_v1.types import GenerateContentRequest, Content, Part
from groq import Groq
from werkzeug.utils import secure_filename
from markupsafe import Markup
import markdown

# Configuração do Flask
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'sua-chave-secreta-aqui')

# Configuração do Firebase
firebase_config = {
    "apiKey": os.getenv('FIREBASE_API_KEY'),
    "authDomain": os.getenv('FIREBASE_AUTH_DOMAIN'),
    "projectId": os.getenv('FIREBASE_PROJECT_ID'),
    "storageBucket": os.getenv('FIREBASE_STORAGE_BUCKET'),
    "messagingSenderId": os.getenv('FIREBASE_MESSAGING_SENDER_ID'),
    "appId": os.getenv('FIREBASE_APP_ID'),
    "databaseURL": os.getenv('FIREBASE_DATABASE_URL')
}

# Inicialização do Firebase Admin
cred_path = os.getenv('FIREBASE_CREDENTIALS_PATH', 'firebase_credentials.json')
if not os.path.exists(cred_path):
    raise FileNotFoundError("Arquivo de credenciais do Firebase não encontrado.")
cred = credentials.Certificate(cred_path)
firebase_admin.initialize_app(cred, {
    'databaseURL': firebase_config['databaseURL']
})

# Configuração do Vertex AI
aiplatform.init(project=os.getenv('GCP_PROJECT_ID', 'global-wharf-456714-k9'), location='us-central1')

# Configuração do Groq
groq_client = Groq(api_key=os.getenv('GROQ_API_KEY'))

# Flask-Babel config
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_SUPPORTED_LOCALES'] = ['en', 'pt', 'es', 'fr', 'de', 'it', 'ru', 'zh', 'ja', 'ko']
babel = Babel(app)

def get_locale():
    if 'user_language' in session and session['user_language'] in app.config['BABEL_SUPPORTED_LOCALES']:
        return session['user_language']
    return request.accept_languages.best_match(app.config['BABEL_SUPPORTED_LOCALES']) or 'en'

babel.locale_selector = get_locale

# Filtro markdown
@app.template_filter('markdown')
def markdown_filter(text):
    return Markup(markdown.markdown(text or '', extensions=['extra', 'smarty']))

# Função auxiliar para obter user_id
def get_user_id():
    if 'user' not in session or 'user_email' not in session:
        return None
    user_id = session['user'].get('uid') or session['user'].get('localId')
    if not user_id:
        user_id = session['user_email'].replace('.', '_')
    return user_id

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        if not email or not password:
            flash('Email e senha são obrigatórios.', 'danger')
            return render_template('signup.html')
        try:
            user = auth.create_user(email=email, password=password)
            auth.send_email_verification(user.uid)
            flash('Conta criada com sucesso! Verifique seu email.', 'success')
            return redirect(url_for('login'))
        except auth.EmailAlreadyExistsError:
            flash('Este email já está em uso.', 'danger')
        except Exception as e:
            flash(f'Erro ao criar conta: {str(e)}', 'danger')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'email_verified' in session and session['email_verified']:
        flash('Email verificado com sucesso!', 'success')
        session.pop('email_verified', None)
        session.pop('verified_email', None)
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        resend_verification = request.form.get('resend_verification', '').lower() == 'true'
        
        try:
            user = auth.sign_in_with_email_and_password(email, password)
            user_info = auth.get_user_by_email(email)
            
            if resend_verification:
                auth.send_email_verification(user_info.uid)
                flash('Email de verificação reenviado.', 'info')
                return render_template('login.html', show_resend_button=True, email=email)
            
            if not user_info.email_verified:
                flash('Verifique seu email antes de fazer login.', 'warning')
                return render_template('login.html', show_resend_button=True, email=email)
            
            session['user'] = {'uid': user_info.uid, 'refreshToken': user['refreshToken']}
            session['user_email'] = email
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('dashboard'))
        except auth.InvalidLoginCredentialsError:
            flash('Email ou senha incorretos.', 'danger')
        except auth.TooManyAttemptsError:
            flash('Muitas tentativas. Tente novamente mais tarde.', 'warning')
        except Exception as e:
            flash(f'Erro ao fazer login: {str(e)}', 'danger')
    return render_template('login.html', show_resend_button=False)

@app.route('/google/callback', methods=['POST'])
def google_callback():
    try:
        id_token = request.get_json().get('idToken')
        if not id_token:
            return jsonify({'success': False, 'message': 'Token não fornecido.'}), 400
        
        decoded_token = auth.verify_id_token(id_token)
        email = decoded_token.get('email')
        uid = decoded_token.get('uid')
        
        try:
            user = auth.get_user_by_email(email)
        except auth.UserNotFoundError:
            user = auth.create_user(email=email, email_verified=True, uid=uid)
        
        session['user'] = {'uid': user.uid, 'refreshToken': id_token}
        session['user_email'] = email
        return jsonify({'success': True, 'message': 'Login com Google bem-sucedido!'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro ao autenticar com Google: {str(e)}'}), 400

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash('Email é obrigatório.', 'danger')
            return render_template('reset_password.html')
        try:
            user = auth.get_user_by_email(email)
            reset_link = auth.generate_password_reset_link(email, action_code_settings={
                'url': request.url_root.rstrip('/') + url_for('login')
            })
            # Enviar email (implementar envio real com um serviço de email)
            flash('Link de redefinição de senha enviado.', 'success')
            return redirect(url_for('login'))
        except auth.UserNotFoundError:
            flash('Nenhuma conta encontrada com este email.', 'danger')
        except Exception as e:
            flash(f'Erro ao processar solicitação: {str(e)}', 'danger')
    return render_template('reset_password.html')

@app.route('/auth_action')
def handle_firebase_action():
    mode = request.args.get('mode', '')
    oob_code = request.args.get('oobCode', '')
    
    if mode == 'verifyEmail' and oob_code:
        try:
            user = auth.apply_action_code(oob_code)
            auth.update_user(user.uid, email_verified=True)
            session['email_verified'] = True
            session['verified_email'] = user.email
            flash('Email verificado com sucesso!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Erro ao verificar email: {str(e)}', 'danger')
            return redirect(url_for('login'))
    
    flash('Ação inválida.', 'danger')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session or 'user_email' not in session:
        flash('Faça login para acessar o dashboard.', 'warning')
        return redirect(url_for('login'))
    
    try:
        user_info = auth.get_user_by_email(session['user_email'])
        if not user_info.email_verified:
            flash('Verifique seu email antes de acessar o dashboard.', 'warning')
            return redirect(url_for('login'))
        
        user_id = get_user_id()
        briefs = []
        briefs_count = 0
        if user_id:
            briefs_snap = db.reference(f'briefs/{user_id}').get()
            if briefs_snap:
                for key, val in briefs_snap.items():
                    val['id'] = key
                    briefs.append(val)
                briefs.sort(key=lambda b: b.get('created_at', ''), reverse=True)
                briefs_count = len(briefs)
        
        concluidos = sum(1 for b in briefs if b.get('status', 'concluido') == 'concluido')
        andamento = sum(1 for b in briefs if b.get('status', 'concluido') == 'andamento')
        
        return render_template('dashboard.html', user=user_info, briefs=briefs, briefs_count=briefs_count, concluidos=concluidos, andamento=andamento)
    except Exception as e:
        flash('Sessão expirada. Faça login novamente.', 'warning')
        session.clear()
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('login'))

@app.route('/new_brief')
def new_brief():
    if 'user' not in session or 'user_email' not in session:
        flash('Faça login para acessar o gerador de briefs.', 'warning')
        return redirect(url_for('login'))
    user_info = auth.get_user_by_email(session['user_email'])
    return render_template('new_brief.html', user=user_info)

@app.route('/my_briefs')
def my_briefs():
    if 'user' not in session or 'user_email' not in session:
        flash('Faça login para acessar seus briefs.', 'warning')
        return redirect(url_for('login'))
    user_info = auth.get_user_by_email(session['user_email'])
    user_id = get_user_id()
    briefs = []
    try:
        briefs_snap = db.reference(f'briefs/{user_id}').get()
        if briefs_snap:
            for key, val in briefs_snap.items():
                val['id'] = key
                briefs.append(val)
            briefs.sort(key=lambda b: b.get('created_at', ''), reverse=True)
    except Exception as e:
        print(f"Erro ao buscar briefs: {str(e)}")
    return render_template('my_briefs.html', user=user_info, briefs=briefs)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session or 'user_email' not in session:
        flash('Faça login para acessar o perfil.', 'warning')
        return redirect(url_for('login'))
    
    user_info = auth.get_user_by_email(session['user_email'])
    user_id = get_user_id()
    prefs = db.reference(f'user_prefs/{user_id}').get() or {}
    
    if request.method == 'POST':
        display_name = request.form.get('display_name', user_info.display_name or '')
        phone = request.form.get('phone', user_info.phone_number or '')
        photo_url = prefs.get('photo_url', user_info.photo_url)
        
        if 'photo' in request.files and request.files['photo'].filename:
            photo = request.files['photo']
            if photo.mimetype not in ['image/jpeg', 'image/png']:
                flash('Formato de imagem inválido.', 'danger')
                return redirect(url_for('profile'))
            filename = secure_filename(photo.filename)
            storage = firebase_admin.storage.bucket()
            blob = storage.blob(f'profile_photos/{user_id}/{filename}')
            blob.upload_from_file(photo, content_type=photo.mimetype)
            photo_url = blob.public_url
        
        db.reference(f'user_prefs/{user_id}').update({
            'display_name': display_name,
            'phone': phone,
            'photo_url': photo_url
        })
        auth.update_user(user_info.uid, display_name=display_name, phone_number=phone, photo_url=photo_url)
        flash('Perfil atualizado com sucesso!', 'success')
        return redirect(url_for('profile'))
    
    return render_template(
        'profile.html',
        user_display_name=prefs.get('display_name', user_info.display_name or ''),
        user_email=user_info.email,
        user_phone=prefs.get('phone', user_info.phone_number or ''),
        user_photo=prefs.get('photo_url', user_info.photo_url),
        user=user_info
    )

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user' not in session or 'user_email' not in session:
        flash('Faça login para acessar as configurações.', 'warning')
        return redirect(url_for('login'))
    
    user_id = get_user_id()
    prefs = db.reference(f'user_prefs/{user_id}').get() or {}
    
    if request.method == 'POST':
        theme = request.form.get('theme', prefs.get('theme', 'light'))
        language = request.form.get('language', prefs.get('language', 'pt'))
        db.reference(f'user_prefs/{user_id}').update({'theme': theme, 'language': language})
        session['user_language'] = language
        flash('Preferências salvas com sucesso!', 'success')
        return redirect(url_for('settings'))
    
    return render_template('settings.html', user_language=prefs.get('language', 'pt'))

@app.route('/brief/<brief_id>')
def view_brief(brief_id):
    if 'user' not in session or 'user_email' not in session:
        flash('Faça login para acessar seus briefs.', 'warning')
        return redirect(url_for('login'))
    
    user_info = auth.get_user_by_email(session['user_email'])
    user_id = get_user_id()
    brief = db.reference(f'briefs/{user_id}/{brief_id}').get()
    if not brief:
        flash('Brief não encontrado.', 'danger')
        return redirect(url_for('my_briefs'))
    brief['id'] = brief_id
    return render_template('view_brief.html', user=user_info, brief=brief)

@app.route('/brief/<brief_id>/edit', methods=['GET', 'POST'])
def edit_brief(brief_id):
    if 'user' not in session or 'user_email' not in session:
        flash('Faça login para acessar seus briefs.', 'warning')
        return redirect(url_for('login'))
    
    user_info = auth.get_user_by_email(session['user_email'])
    user_id = get_user_id()
    brief = db.reference(f'briefs/{user_id}/{brief_id}').get()
    if not brief:
        flash('Brief não encontrado.', 'danger')
        return redirect(url_for('my_briefs'))
    brief['id'] = brief_id
    
    if request.method == 'POST':
        brief['brief_type'] = request.form.get('brief_type', brief['brief_type'])
        brief['template'] = request.form.get('template', brief['template'])
        brief['text'] = request.form.get('text', brief['text'])
        brief['result'] = request.form.get('result', brief['result'])
        db.reference(f'briefs/{user_id}/{brief_id}').update({
            'brief_type': brief['brief_type'],
            'template': brief['template'],
            'text': brief['text'],
            'result': brief['result'],
            'status': request.form.get('status', brief.get('status', 'concluido')),
        })
        flash('Brief atualizado com sucesso!', 'success')
        return redirect(url_for('view_brief', brief_id=brief_id))
    
    return render_template('edit_brief.html', user=user_info, brief=brief)

@app.route('/brief/<brief_id>/delete', methods=['POST'])
def delete_brief(brief_id):
    if 'user' not in session or 'user_email' not in session:
        flash('Faça login para acessar seus briefs.', 'warning')
        return redirect(url_for('login'))
    
    user_id = get_user_id()
    try:
        db.reference(f'briefs/{user_id}/{brief_id}').delete()
        flash('Brief excluído com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao excluir brief: {str(e)}', 'danger')
    return redirect(url_for('my_briefs'))

@app.context_processor
def inject_year():
    return {'year': datetime.datetime.now().year}

@app.context_processor
def inject_user_theme():
    user_theme = 'light'
    user_language = 'pt'
    user_photo = None
    user_id = get_user_id()
    if user_id:
        prefs = db.reference(f'user_prefs/{user_id}').get() or {}
        user_theme = prefs.get('theme', 'light')
        user_language = prefs.get('language', 'pt')
        user_info = auth.get_user_by_email(session['user_email'])
        user_photo = prefs.get('photo_url', user_info.photo_url)
    return dict(user_theme=user_theme, user_language=user_language, user_photo=user_photo)

@app.route('/api/generate-brief', methods=['POST'])
def api_generate_brief():
    # Verificar se request está disponível
    if not request:
        return jsonify({'error': 'Objeto request não disponível.'}), 500

    # Suporte a JSON e FormData
    if request.content_type and request.content_type.startswith('multipart/form-data'):
        text = request.form.get('text', '')
        brief_type = request.form.get('type', 'custom')
        template = request.form.get('template', 'classic')
        extras = json.loads(request.form.get('extras', '[]') or '[]')
        image_data_url = request.form.get('image', '')
        audio_file = request.files.get('audio')
        model_choice = request.form.get('model', 'gemini')
    else:
        data = request.get_json() or {}
        text = data.get('text', '')
        brief_type = data.get('type', 'custom')
        template = data.get('template', 'classic')
        extras = data.get('extras', [])
        image_data_url = data.get('image', '')
        audio_file = None
        model_choice = data.get('model', 'gemini')

    # Validação de entrada
    if not text and not image_data_url and not audio_file:
        return jsonify({'error': 'Texto, imagem ou áudio obrigatórios.'}), 400
    if image_data_url and not isinstance(image_data_url, str):
        return jsonify({'error': 'URL da imagem inválida.'}), 400
    if image_data_url and not image_data_url.startswith(('http', 'data:image')):
        return jsonify({'error': 'URL da imagem deve ser um link HTTP ou data URL.'}), 400

    # Transcrição de áudio
    if audio_file:
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.mp3') as temp_audio:
                audio_path = temp_audio.name
                audio_file.save(audio_path)
                with open(audio_path, 'rb') as f:
                    transcription = groq_client.audio.transcriptions.create(
                        file=(audio_file.filename, f.read()),
                        model="whisper-large-v3",
                        response_format="verbose_json",
                    )
                text = transcription.text.strip()
            os.remove(audio_path)
        except Exception as e:
            return jsonify({'error': f'Erro ao transcrever áudio: {str(e)}'}), 500

    # Montar campos extras
    extras_str = '\n'.join([f"{item.get('name', '')}: {item.get('value', '')}" for item in extras])

    # Configurar template
    template_str = {
        'classic': "\nGere o briefing no formato clássico, com tópicos claros, objetivos, público-alvo, entregáveis, prazo e informações relevantes.",
        'visual': "\nGere o briefing com uma estrutura visual, use listas, destaques e elementos que facilitem a leitura rápida.",
        'minimal': "\nGere um briefing minimalista, apenas os pontos essenciais, direto ao ponto, sem enfeites."
    }.get(template, "")

    # Montar prompt
    prompt_text = (
        f"Você é um assistente especialista em criar briefings profissionais. "
        f"Recebe o texto bruto de um cliente e transforma em um briefing único, visualmente atraente, objetivo e pronto para ser usado por um profissional da área de {brief_type}.{template_str}\n"
        f"\nTexto do cliente:\n{text}\n"
        f"\nCampos adicionais fornecidos pelo cliente:\n{extras_str}\n"
        "\nGere o briefing de acordo com as informações acima. Seja criativo, use formatação, listas, títulos e destaque pontos importantes."
    )

    try:
        if model_choice == 'gemini':
            from google.cloud.aiplatform_v1 import PredictionServiceClient
            from google.cloud.aiplatform_v1.types import GenerateContentRequest, Content, Part

            client = PredictionServiceClient()
            endpoint = f"projects/{os.getenv('GCP_PROJECT_ID')}/locations/us-central1/publishers/google/models/gemini-1.5-pro"
            parts = [Part(text=prompt_text)]
            if image_data_url and ',' in image_data_url:
                parts.append(Part(inline_data={"mime_type": "image/jpeg", "data": image_data_url.split(',')[1]}))
            request_obj = GenerateContentRequest(
                model=endpoint,
                contents=[Content(role="user", parts=parts)],
                generation_config={
                    "temperature": 1.0,
                    "top_p": 0.95,
                    "max_output_tokens": 1024
                }
            )
            response = client.generate_content(request_obj)
            result = response.candidates[0].content.parts[0].text
        else:  # Llama
            messages = [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt_text}
                    ] + (
                        [{"type": "image_url", "image_url": {"url": image_data_url}}]
                        if image_data_url and isinstance(image_data_url, str) and image_data_url.startswith(('http', 'data:image'))
                        else []
                    )
                }
            ]
            print(f"Mensagens enviadas: {json.dumps(messages, indent=2)}")  # Log para depuração
            model_name = "meta-llama/llama-4-maverick-17b-128e-instruct" if image_data_url else "meta-llama/llama-4-scout-17b-16e-instruct"
            completion = groq_client.chat.completions.create(
                model=model_name,
                messages=messages,
                temperature=0.7,
                max_tokens=1024,
                top_p=1,
                stream=False,
            )
            result = completion.choices[0].message.content

        # Salvar no Firebase
        user_id = get_user_id()
        if user_id:
            brief_data = {
                'text': text,
                'brief_type': brief_type,
                'template': template,
                'extras': extras,
                'image_data_url': image_data_url,
                'result': result,
                'created_at': datetime.datetime.utcnow().isoformat() + 'Z',
                'status': 'concluido',
            }
            db.reference(f'briefs/{user_id}').push(brief_data)

        html = f'<pre style="white-space:pre-wrap">{result}</pre>'
        return jsonify({'result': result, 'html': html})
    except Exception as e:
        return jsonify({'error': f'Erro ao gerar briefing: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
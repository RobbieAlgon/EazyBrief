import os
from dotenv import load_dotenv
load_dotenv()  # Carrega variáveis do .env

import json
import base64
from datetime import datetime, timedelta, timezone
import tempfile
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, Response
import firebase_admin
from firebase_admin import credentials, auth, db, storage
import pyrebase
from functools import wraps
import uuid
import requests
import logging
from groq import Groq
from werkzeug.utils import secure_filename
from markupsafe import Markup
import markdown
import stripe
import subprocess
import platform

# Função para sincronizar o horário do sistema
def sync_system_time():
    try:
        # Usa apenas o timeapi.io com formato específico
        time_server = 'https://timeapi.io/api/Time/current/zone/UTC'
        
        try:
            response = requests.get(time_server, timeout=5)
            if response.status_code == 200:
                data = response.json()
                # Extrai os componentes da data/hora
                year = data.get('year')
                month = data.get('month')
                day = data.get('day')
                hour = data.get('hour')
                minute = data.get('minute')
                second = data.get('seconds')
                
                if all(v is not None for v in [year, month, day, hour, minute, second]):
                    # Constrói a data/hora manualmente
                    server_time = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
                    
                    # Converte o horário do sistema para UTC
                    system_time = datetime.now(timezone.utc)
                    
                    # Calcula a diferença de tempo
                    time_diff = abs((server_time - system_time).total_seconds())
                    
                    if time_diff > 60:  # Se a diferença for maior que 1 minuto
                        logging.warning(f'Diferença de horário detectada: {time_diff} segundos')
                        logging.warning('Por favor, sincronize o horário do seu sistema manualmente:')
                        logging.warning('1. Clique com o botão direito no relógio do Windows')
                        logging.warning('2. Selecione "Ajustar data/hora"')
                        logging.warning('3. Clique em "Sincronizar agora"')
                        return False
                    
                    logging.info('Horário do sistema está sincronizado')
                    return True
                    
        except Exception as e:
            logging.warning(f'Erro ao tentar servidor {time_server}: {str(e)}')
        
        logging.error('Não foi possível obter o horário do servidor')
        return False
        
    except Exception as e:
        logging.error(f'Erro ao sincronizar horário: {str(e)}')
        return False

# Configuração do Flask
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Sessão dura 7 dias

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Sincroniza o horário antes de iniciar a aplicação
if not sync_system_time():
    logging.warning('Não foi possível sincronizar o horário do sistema. O login com Google pode não funcionar corretamente.')

import json
import base64
from datetime import datetime, timedelta
import tempfile
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, Response
import firebase_admin
from firebase_admin import credentials, auth, db, storage
import pyrebase
from functools import wraps
import uuid
import requests
import logging
from groq import Groq
from werkzeug.utils import secure_filename
from markupsafe import Markup
import markdown
import stripe
from datetime import datetime
from flask import send_file
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from docx import Document
from docx.shared import Pt
from flask import jsonify

# Inicialização do Pyrebase para autenticação de usuário final
firebase_config = {
    "apiKey": os.getenv("FIREBASE_API_KEY"),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
    "databaseURL": os.getenv("FIREBASE_DATABASE_URL"),
    "projectId": os.getenv("FIREBASE_PROJECT_ID"),
    "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
    "messagingSenderId": os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
    "appId": os.getenv("FIREBASE_APP_ID"),
}
pyrebase_app = pyrebase.initialize_app(firebase_config)
pyre_auth = pyrebase_app.auth()

# Configuração dos planos e limites
PLANS = {
    'free': {
        'name': 'Grátis',
        'price': 0,
        'brief_limit': 3,
        'features': [
            '3 briefs por mês',
            'Templates básicos',
            'Exportação em PDF',
            'Suporte por email',
            'Dashboard básico',
            'Histórico limitado'
        ],
        'templates': ['classic'],
        'export_formats': ['pdf'],
        'ai_models': ['gemini']
    },
    'pro': {
        'name': 'Pro',
        'price': 9,
        'stripe_price_id': os.getenv('STRIPE_PRO_PRICE_ID'),
        'brief_limit': 50,
        'features': [
            '50 briefs por mês',
            'Templates avançados',
            'Exportação em múltiplos formatos',
            'Suporte prioritário',
            'Dashboard avançado',
            'Histórico completo',
            'Personalização de templates',
            'Modelos de IA avançados',
            'Campos extras personalizados'
        ],
        'templates': ['classic', 'visual', 'minimal'],
        'export_formats': ['pdf', 'docx', 'txt', 'html'],
        'ai_models': ['gemini', 'groq']
    },
    'premium': {
        'name': 'Premium',
        'price': 19,
        'stripe_price_id': os.getenv('STRIPE_PREMIUM_PRICE_ID'),
        'brief_limit': None,  # Ilimitado
        'features': [
            'Briefs ilimitados',
            'Templates exclusivos',
            'Exportação em massa',
            'Suporte VIP',
            'Dashboard completo',
            'Backup automático',
            'API access',
            'Equipes e colaboração',
            'Personalização avançada',
            'Todos os modelos de IA'
        ],
        'templates': ['classic', 'visual', 'minimal', 'exclusive'],
        'export_formats': ['pdf', 'docx', 'txt', 'html'],
        'ai_models': ['gemini', 'groq']
    }
}

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
stripe_publishable_key = os.getenv('STRIPE_PUBLISHABLE_KEY')
if not stripe.api_key or not stripe_publishable_key:
    print("Warning: Stripe keys not found in environment variables")

# Função auxiliar para obter plano do usuário e briefs usados
from datetime import datetime

def get_user_plan_info(user_id):
    user_ref = db.reference(f'users/{user_id}')
    user_data = user_ref.get() or {}
    plan = user_data.get('plan', 'free')
    plan_expiry = user_data.get('plan_expiry')
    # Reset mensal do contador de briefs
    now = datetime.utcnow()
    month_key = now.strftime('%Y-%m')
    briefs_used = user_data.get('briefs_used', {})
    briefs_this_month = briefs_used.get(month_key, 0)
    return plan, plan_expiry, briefs_this_month, user_data

def increment_brief_count(user_id):
    user_ref = db.reference(f'users/{user_id}')
    user_data = user_ref.get() or {}
    now = datetime.utcnow()
    month_key = now.strftime('%Y-%m')
    briefs_used = user_data.get('briefs_used', {})
    briefs_used[month_key] = briefs_used.get(month_key, 0) + 1
    user_ref.update({'briefs_used': briefs_used})

# Função para checar se usuário pode criar brief

def can_create_brief(user_id):
    plan, plan_expiry, briefs_this_month, user_data = get_user_plan_info(user_id)
    limit = PLANS[plan]['brief_limit']
    if plan in ['pro', 'premium'] and plan_expiry:
        # Verifica se plano expirou
        expiry_dt = datetime.strptime(plan_expiry, '%Y-%m-%d')
        if expiry_dt < datetime.utcnow():
            # Downgrade automático
            db.reference(f'users/{user_id}').update({'plan': 'free', 'plan_expiry': None})
            plan = 'free'
            limit = PLANS['free']['brief_limit']
    if limit is None:
        return True
    # Enviar aviso se atingir o limite e ainda não foi avisado este mês
    now = datetime.utcnow()
    month_key = now.strftime('%Y-%m')
    if briefs_this_month >= limit:
        user_ref = db.reference(f'users/{user_id}')
        user_data = user_ref.get() or {}
        email = user_data.get('email')
        notified = user_data.get('notified_limit', {})
        if not notified.get(month_key):
            if email:
                try:
                    send_email(
                        subject='Atenção: Limite do plano atingido - EazyBrief',
                        recipients=[email],
                        body=f'Você atingiu o limite de briefs do seu plano {PLANS[plan]["name"]}. Faça upgrade para continuar usando sem restrições.'
                    )
                except Exception as e:
                    print(f'Erro ao enviar email de limite atingido: {e}')
            notified[month_key] = True
            user_ref.update({'notified_limit': notified})
        return False
    return True


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
cred_json = os.getenv('FIREBASE_CREDENTIALS_JSON')
if not cred_json:
    raise ValueError("FIREBASE_CREDENTIALS_JSON não configurado nas variáveis de ambiente")

try:
    cred_dict = json.loads(cred_json)
    cred = credentials.Certificate(cred_dict)
    firebase_admin.initialize_app(cred, {
        'databaseURL': firebase_config['databaseURL'],
        'storageBucket': os.getenv('FIREBASE_STORAGE_BUCKET')
    })
except json.JSONDecodeError:
    raise ValueError("FIREBASE_CREDENTIALS_JSON contém JSON inválido")
except Exception as e:
    raise ValueError(f"Erro ao inicializar Firebase Admin: {str(e)}")

# Configuração do Groq
groq_client = Groq(api_key=os.getenv('GROQ_API_KEY'))

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

# Decorator para rotas que requerem autenticação
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or 'user_email' not in session:
            flash('Faça login para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator para rotas que requerem usuário não autenticado
def guest_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' in session and 'user_email' in session:
            flash('Você já está logado.', 'info')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user' in session and 'user_email' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
@guest_required
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        if not email or not password:
            flash('Email e senha são obrigatórios.', 'danger')
            return render_template('signup.html')
        try:
            # Criar usuário usando Pyrebase
            user = pyre_auth.create_user_with_email_and_password(email, password)
            
            # Enviar email de verificação usando Pyrebase
            pyre_auth.send_email_verification(user['idToken'])
            
            flash('Conta criada com sucesso! Verifique seu email para ativar sua conta.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            error_message = str(e)
            print(f"Erro detalhado no signup: {error_message}")
            if 'EMAIL_EXISTS' in error_message:
                flash('Este email já está em uso.', 'danger')
            else:
                flash('Erro ao criar conta. Por favor, tente novamente.', 'danger')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
@guest_required
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
            if resend_verification:
                # Gerar novo link de verificação
                action_code_settings = auth.ActionCodeSettings(
                    url=f"{request.url_root}auth_action?mode=verifyEmail",
                    handle_code_in_app=True
                )
                auth.generate_email_verification_link(email, action_code_settings=action_code_settings)
                flash('Email de verificação reenviado. Por favor, verifique sua caixa de entrada.', 'info')
                return render_template('login.html', show_resend_button=True, email=email)
            
            # Tentar login
            user = pyre_auth.sign_in_with_email_and_password(email, password)
            user_info = auth.get_user_by_email(email)
            
            if not user_info.email_verified:
                flash('Verifique seu email antes de acessar o dashboard.', 'warning')
                return render_template('login.html', show_resend_button=True, email=email)
            
            session.permanent = True  # Torna a sessão permanente
            session['user'] = {'uid': user_info.uid, 'refreshToken': user['refreshToken']}
            session['user_email'] = email
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash('Email ou senha incorretos ou erro ao fazer login.', 'danger')
    return render_template('login.html', show_resend_button=False)

@app.route('/google/callback', methods=['POST'])
def google_callback():
    try:
        # Verifica e sincroniza o horário antes de processar o callback
        if not sync_system_time():
            logging.warning('Não foi possível sincronizar o horário do sistema')
        
        id_token = request.json.get('idToken')
        if not id_token:
            return jsonify({'success': False, 'message': 'Token não fornecido'})
        
        # Verificar o token com o Firebase Admin
        decoded_token = auth.verify_id_token(id_token)
        user_id = decoded_token['uid']
        email = decoded_token['email']
        
        # Verificar se o usuário já existe
        try:
            user = auth.get_user(user_id)
        except auth.UserNotFoundError:
            # Criar usuário se não existir
            user = auth.create_user(
                uid=user_id,
                email=email,
                email_verified=True
            )
        
        # Atualizar sessão
        session['user'] = {'uid': user_id}
        session['user_email'] = email
        
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f'Erro no callback do Google: {str(e)}')
        return jsonify({'success': False, 'message': str(e)})

@app.route('/google/login')
def google_login():
    return redirect(url_for('login'))

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash('Email é obrigatório.', 'danger')
            return render_template('reset_password.html')
        
        try:
            # Gerar link de redefinição de senha
            action_code_settings = auth.ActionCodeSettings(
                url=f"{request.url_root}auth_action?mode=resetPassword",
                handle_code_in_app=True
            )
            auth.generate_password_reset_link(email, action_code_settings=action_code_settings)
            flash('Link de redefinição de senha enviado. Por favor, verifique sua caixa de entrada.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f'Erro ao enviar email de redefinição: {str(e)}')
            flash('Erro ao enviar email de redefinição. Por favor, tente novamente.', 'danger')
    
    return render_template('reset_password.html')

@app.route('/auth_action')
def handle_firebase_action():
    mode = request.args.get('mode', '')
    oob_code = request.args.get('oobCode', '')
    
    print(f"DEBUG - Mode: {mode}, OOB Code: {oob_code}")
    
    if mode == 'verifyEmail' and oob_code:
        try:
            # Tentar fazer login com o código OOB
            user = pyre_auth.sign_in_with_email_link(oob_code)
            if user and user.get('email'):
                session['email_verified'] = True
                session['verified_email'] = user['email']
                flash('Email verificado com sucesso!', 'success')
                return redirect(url_for('login'))
            else:
                raise Exception("Falha ao verificar email")
        except Exception as e:
            print(f'Erro detalhado ao verificar email: {str(e)}')
            flash('Erro ao verificar email. Por favor, tente solicitar um novo email de verificação na página de login.', 'danger')
            return redirect(url_for('login'))
    elif mode == 'resetPassword' and oob_code:
        try:
            session['reset_password_code'] = oob_code
            return redirect(url_for('reset_password_confirm'))
        except Exception as e:
            flash(f'Erro ao processar link de redefinição: {str(e)}', 'danger')
            return redirect(url_for('login'))
    
    flash('Ação inválida.', 'danger')
    return redirect(url_for('login'))

@app.route('/reset-password-confirm', methods=['GET', 'POST'])
def reset_password_confirm():
    # Obter o código da sessão ou dos parâmetros da URL
    oob_code = session.get('reset_password_code') or request.args.get('oobCode')
    
    if not oob_code:
        flash('Código de redefinição de senha inválido ou expirado.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        if not new_password:
            flash('Nova senha é obrigatória.', 'danger')
            return render_template('reset_password_confirm.html')
        
        try:
            # Confirmar a redefinição de senha
            pyre_auth.confirm_password_reset(oob_code, new_password)
            session.pop('reset_password_code', None)
            flash('Senha redefinida com sucesso!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f'Erro ao redefinir senha: {str(e)}')
            flash('Erro ao redefinir senha. O link pode ter expirado.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('reset_password_confirm.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        user_info = auth.get_user_by_email(session['user_email'])
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
        
        # Criar dicionário de estatísticas
        stats = {
            'total_briefs': briefs_count,
            'completed_briefs': concluidos,
            'in_progress_briefs': andamento
        }

        # Buscar atividades recentes (últimos 2 briefs)
        recent_activity = []
        for brief in briefs[:2]:  # Pegar apenas os 2 mais recentes
            activity = {
                'description': f"Brief '{brief.get('brief_type', 'Sem tipo')}' {'concluído' if brief.get('status') == 'concluido' else 'em andamento'}",
                'timestamp': brief.get('created_at', '').split('T')[0],  # Formatar data
                'brief_id': brief['id']  # Adicionar o ID do brief
            }
            recent_activity.append(activity)
        
        return render_template('dashboard.html', 
                             user=user_info, 
                             briefs=briefs, 
                             briefs_count=briefs_count, 
                             concluidos=concluidos, 
                             andamento=andamento, 
                             stats=stats,
                             recent_activity=recent_activity)
    except Exception as e:
        print('DEBUG ERRO DASHBOARD:', repr(e))
        flash('Sessão expirada. Faça login novamente.', 'warning')
        session.clear()
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('login'))

@app.route('/new_brief')
@login_required
def new_brief():
    user_info = auth.get_user_by_email(session['user_email'])
    return render_template('new_brief.html', user=user_info)

@app.route('/my_briefs')
@login_required
def my_briefs():
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
@login_required
def profile():
    user_info = auth.get_user_by_email(session['user_email'])
    user_id = get_user_id()
    prefs = db.reference(f'user_prefs/{user_id}').get() or {}
    
    # Buscar informações do plano diretamente do banco de dados
    user_data = db.reference(f'users/{user_id}').get() or {}
    plan = user_data.get('plan', 'free')
    plan_expiry = user_data.get('plan_expiry')
    
    # Log para debug
    logging.info(f'[Profile] Carregando perfil para user_id={user_id}')
    logging.info(f'[Profile] Dados do usuário: {user_data}')
    logging.info(f'[Profile] Plano atual: {plan}, Expira em: {plan_expiry}')
    
    if request.method == 'POST':
        display_name = request.form.get('display_name', user_info.display_name or '')
        phone = request.form.get('phone', '').strip()
        photo_url = prefs.get('photo_url', user_info.photo_url)
        
        if 'photo' in request.files and request.files['photo'].filename:
            try:
                photo = request.files['photo']
                if photo.mimetype not in ['image/jpeg', 'image/png']:
                    flash('Formato de imagem inválido.', 'danger')
                    return redirect(url_for('profile'))
                
                filename = secure_filename(photo.filename)
                bucket_name = 'brief-generator-5c33f.firebasestorage.app'
                bucket = storage.bucket(bucket_name)
                blob = bucket.blob(f'profile_photos/{user_id}/{filename}')
                
                # Configurar metadados para tornar o arquivo público
                blob.metadata = {'cacheControl': 'public, max-age=31536000'}
                
                # Upload do arquivo
                blob.upload_from_file(photo, content_type=photo.mimetype)
                
                # Tornar o blob público
                blob.make_public()
                
                # Obter a URL pública
                photo_url = blob.public_url
                
            except Exception as e:
                print(f"Erro ao fazer upload da foto: {str(e)}")
                flash(f'Erro ao fazer upload da foto: {str(e)}', 'danger')
                return redirect(url_for('profile'))
        
        try:
            # Atualizar preferências do usuário
            db.reference(f'user_prefs/{user_id}').update({
                'display_name': display_name,
                'phone': phone,
                'photo_url': photo_url
            })
            
            # Atualizar informações do usuário no Firebase Auth
            update_data = {
                'display_name': display_name,
                'photo_url': photo_url
            }
            # Só adiciona o telefone se não estiver vazio
            if phone:
                update_data['phone_number'] = phone
            
            auth.update_user(user_info.uid, **update_data)
            flash('Perfil atualizado com sucesso!', 'success')
        except Exception as e:
            print(f"Erro ao atualizar perfil: {str(e)}")
            flash(f'Erro ao atualizar perfil: {str(e)}', 'danger')
        
        return redirect(url_for('profile'))
    
    return render_template(
        'profile.html',
        user_display_name=prefs.get('display_name', user_info.display_name or ''),
        user_email=user_info.email,
        user_phone=prefs.get('phone', user_info.phone_number or ''),
        user_photo=prefs.get('photo_url', user_info.photo_url),
        user=user_info,
        user_plan=plan,
        plan_expiry=plan_expiry,
        plans=PLANS
    )

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_id = get_user_id()
    prefs = db.reference(f'user_prefs/{user_id}').get() or {}
    
    if request.method == 'POST':
        theme = request.form.get('theme', prefs.get('theme', 'light'))
        db.reference(f'user_prefs/{user_id}').update({'theme': theme})
        flash('Preferências salvas com sucesso!', 'success')
        return redirect(url_for('settings'))
    
    return render_template('settings.html')

@app.route('/brief/<brief_id>')
@login_required
def view_brief(brief_id):
    user_info = auth.get_user_by_email(session['user_email'])
    user_id = get_user_id()
    brief = db.reference(f'briefs/{user_id}/{brief_id}').get()
    if not brief:
        flash('Brief não encontrado.', 'danger')
        return redirect(url_for('my_briefs'))
    brief['id'] = brief_id
    return render_template('view_brief.html', user=user_info, brief=brief)

@app.route('/brief/<brief_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_brief(brief_id):
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
@login_required
def delete_brief(brief_id):
    user_id = get_user_id()
    try:
        db.reference(f'briefs/{user_id}/{brief_id}').delete()
        flash('Brief excluído com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao excluir brief: {str(e)}', 'danger')
    return redirect(url_for('my_briefs'))

@app.context_processor
def inject_year():
    return {'year': datetime.now().year}

@app.context_processor
def inject_user_theme():
    user_theme = 'light'
    user_photo = None
    user_plan = 'free'
    user_id = get_user_id()
    if user_id:
        prefs = db.reference(f'user_prefs/{user_id}').get() or {}
        user_theme = prefs.get('theme', 'light')
        user_info = auth.get_user_by_email(session['user_email'])
        user_photo = prefs.get('photo_url', user_info.photo_url)
        user_data = db.reference(f'users/{user_id}').get() or {}
        user_plan = user_data.get('plan', 'free')
    return dict(user_theme=user_theme, user_photo=user_photo, user_plan=user_plan, plans=PLANS)

@app.route('/api/generate-brief', methods=['POST'])
def api_generate_brief():
    if not request.is_json:
        return jsonify({'error': 'Content-Type deve ser application/json'}), 400

    data = request.get_json()
    text = data.get('text', '')
    brief_type = data.get('brief_type', '')
    template = data.get('template', '')
    extras = data.get('extras', {})
    image_data_url = data.get('image_data_url', '')
    model_choice = data.get('model_choice', 'llama')  # Default to llama since we removed gemini

    # Construir o prompt
    extras_str = '\n'.join([f"{k}: {v}" for k, v in extras.items()])
    prompt_text = (
        f"Tipo de Briefing: {brief_type}\n"
        f"Template: {template}\n"
        f"Texto do cliente:\n{text}\n"
        f"\nCampos adicionais fornecidos pelo cliente:\n{extras_str}\n"
        "\nGere o briefing de acordo com as informações acima. Seja criativo, use formatação, listas, títulos e destaque pontos importantes."
    )

    try:
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
                'created_at': datetime.utcnow().isoformat() + 'Z',
                'status': 'concluido',
            }
            db.reference(f'briefs/{user_id}').push(brief_data)

        html = f'<pre style="white-space:pre-wrap">{result}</pre>'
        return jsonify({'result': result, 'html': html})
    except Exception as e:
        return jsonify({'error': f'Erro ao gerar briefing: {str(e)}'}), 500

@app.route('/brief/<brief_id>/export/pdf')
def export_brief_pdf(brief_id):
    if 'user' not in session or 'user_email' not in session:
        flash('Faça login para acessar seus briefs.', 'warning')
        return redirect(url_for('login'))
    user_id = get_user_id()
    brief = db.reference(f'briefs/{user_id}/{brief_id}').get()
    if not brief:
        flash('Brief não encontrado.', 'danger')
        return redirect(url_for('my_briefs'))

    # Geração do PDF em memória
    from io import BytesIO
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 50
    p.setFont('Helvetica-Bold', 16)
    p.drawString(50, y, f"Brief: {brief.get('title', 'Sem título')}")
    y -= 30
    p.setFont('Helvetica', 12)
    for key, value in brief.items():
        if key == 'id':
            continue
        if isinstance(value, str):
            lines = value.split('\n')
            for line in lines:
                if y < 50:
                    p.showPage()
                    y = height - 50
                    p.setFont('Helvetica', 12)
                p.drawString(50, y, f"{key.capitalize()}: {line}" if line else "")
                y -= 18
        else:
            if y < 50:
                p.showPage()
                y = height - 50
                p.setFont('Helvetica', 12)
            p.drawString(50, y, f"{key.capitalize()}: {value}")
            y -= 18
    p.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"brief_{brief_id}.pdf", mimetype='application/pdf')

@app.route('/brief/<brief_id>/export/docx')
def export_brief_docx(brief_id):
    if 'user' not in session or 'user_email' not in session:
        flash('Faça login para acessar seus briefs.', 'warning')
        return redirect(url_for('login'))
    user_id = get_user_id()
    brief = db.reference(f'briefs/{user_id}/{brief_id}').get()
    if not brief:
        flash('Brief não encontrado.', 'danger')
        return redirect(url_for('my_briefs'))

    doc = Document()
    doc.add_heading(f"Brief: {brief.get('title', 'Sem título')}", level=1)
    for key, value in brief.items():
        if key == 'id':
            continue
        doc.add_paragraph(f"{key.capitalize()}:", style='Heading2')
        if isinstance(value, str):
            for line in value.split('\n'):
                doc.add_paragraph(line, style='Normal')
        else:
            doc.add_paragraph(str(value), style='Normal')

    from io import BytesIO
    buffer = BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"brief_{brief_id}.docx", mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')

@app.route('/brief/<brief_id>/export/txt')
def export_brief_txt(brief_id):
    if 'user' not in session or 'user_email' not in session:
        flash('Faça login para acessar seus briefs.', 'warning')
        return redirect(url_for('login'))
    user_id = get_user_id()
    brief = db.reference(f'briefs/{user_id}/{brief_id}').get()
    if not brief:
        flash('Brief não encontrado.', 'danger')
        return redirect(url_for('my_briefs'))
    lines = [f"Brief: {brief.get('title', 'Sem título')}"]
    for key, value in brief.items():
        if key == 'id':
            continue
        lines.append(f"{key.capitalize()}:")
        if isinstance(value, str):
            lines.extend(value.split('\n'))
        else:
            lines.append(str(value))
        lines.append("")
    txt_content = '\n'.join(lines)
    from io import BytesIO
    buffer = BytesIO(txt_content.encode('utf-8'))
    return send_file(buffer, as_attachment=True, download_name=f"brief_{brief_id}.txt", mimetype='text/plain')

@app.route('/brief/<brief_id>/export/html')
def export_brief_html(brief_id):
    if 'user' not in session or 'user_email' not in session:
        flash('Faça login para acessar seus briefs.', 'warning')
        return redirect(url_for('login'))
    user_id = get_user_id()
    brief = db.reference(f'briefs/{user_id}/{brief_id}').get()
    if not brief:
        flash('Brief não encontrado.', 'danger')
        return redirect(url_for('my_briefs'))
    html = [f"<h1>Brief: {brief.get('title', 'Sem título')}</h1>"]
    for key, value in brief.items():
        if key == 'id':
            continue
        html.append(f"<h2>{key.capitalize()}:</h2>")
        if isinstance(value, str):
            for line in value.split('\n'):
                html.append(f"<p>{line}</p>")
        else:
            html.append(f"<p>{value}</p>")
    html_content = '\n'.join(html)
    from io import BytesIO
    buffer = BytesIO(html_content.encode('utf-8'))
    return send_file(buffer, as_attachment=True, download_name=f"brief_{brief_id}.html", mimetype='text/html')

@app.route('/plans')
def plans():
    if 'user' not in session or 'user_email' not in session:
        flash('Faça login para acessar os planos.', 'warning')
        return redirect(url_for('login'))
    user_id = get_user_id()
    plan, plan_expiry, briefs_this_month, user_data = get_user_plan_info(user_id)
    return render_template('plans.html', plans=PLANS, user_plan=plan, plan_expiry=plan_expiry, briefs_this_month=briefs_this_month)

@app.route('/upgrade/<plan_key>', methods=['POST'])
def upgrade(plan_key):
    logging.info(f'[Upgrade] Iniciando processo de upgrade para o plano {plan_key}')
    
    if plan_key not in PLANS:
        logging.error(f'[Upgrade] Plano inválido: {plan_key}')
        return jsonify({'error': 'Plano inválido.'}), 400
        
    if 'user' not in session or 'user_email' not in session:
        logging.error('[Upgrade] Usuário não está logado')
        return jsonify({'error': 'Login necessário.'}), 401
    
    user_id = get_user_id()
    logging.info(f'[Upgrade] User ID: {user_id}')
    
    # Se for o plano gratuito, atualiza direto no banco
    if plan_key == 'free':
        try:
            db.reference(f'users/{user_id}').update({
                'plan': 'free',
                'plan_expiry': None
            })
            flash('Plano atualizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            logging.error(f'[Upgrade] Erro ao atualizar para plano gratuito: {str(e)}')
            flash('Erro ao atualizar plano. Por favor, tente novamente mais tarde.', 'error')
            return redirect(url_for('plans'))
    
    # Para planos pagos, usa o Stripe
    if not stripe.api_key:
        logging.error('[Upgrade] STRIPE_API_KEY não configurada')
        flash('Erro de configuração do sistema de pagamento. Por favor, tente novamente mais tarde.', 'error')
        return redirect(url_for('plans'))
    
    session['upgrade_plan'] = plan_key
    
    try:
        # Stripe Checkout Session
        domain_url = request.url_root.strip('/')
        price_id = PLANS[plan_key]['stripe_price_id']
        
        logging.info(f'[Upgrade] Domain URL: {domain_url}')
        logging.info(f'[Upgrade] Price ID: {price_id}')
        
        if not price_id:
            logging.error(f'[Upgrade] Stripe Price ID não configurado para o plano {plan_key}')
            flash('Erro de configuração do sistema de pagamento. Por favor, tente novamente mais tarde.', 'error')
            return redirect(url_for('plans'))
        
        # Verificar se o preço existe no Stripe
        try:
            price = stripe.Price.retrieve(price_id)
            logging.info(f'[Upgrade] Preço encontrado no Stripe: {price}')
        except Exception as e:
            logging.error(f'[Upgrade] Erro ao verificar preço no Stripe: {str(e)}')
            flash('Erro de configuração do sistema de pagamento. Por favor, tente novamente mais tarde.', 'error')
            return redirect(url_for('plans'))
        
        stripe_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1
            }],
            mode='subscription',  # Changed from 'payment' to 'subscription'
            success_url=f'{domain_url}/payment/success?session_id={{CHECKOUT_SESSION_ID}}',
            cancel_url=f'{domain_url}/plans',
            metadata={'user_id': user_id, 'plan': plan_key}
        )
        
        logging.info(f'[Upgrade] Sessão do Stripe criada com sucesso: {stripe_session.id}')
        return redirect(stripe_session.url)
    except stripe.error.StripeError as e:
        logging.error(f'[Upgrade] Erro do Stripe: {str(e)}')
        flash('Erro ao processar pagamento. Por favor, tente novamente mais tarde.', 'error')
        return redirect(url_for('plans'))
    except Exception as e:
        logging.error(f'[Upgrade] Erro inesperado: {str(e)}')
        flash('Erro ao processar pagamento. Por favor, tente novamente mais tarde.', 'error')
        return redirect(url_for('plans'))

@app.route('/payment/success')
def payment_success():
    return render_template('payment_success.html')

@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
    
    logging.info(f'[Stripe Webhook] Recebido evento. Headers: {dict(request.headers)}')
    logging.info(f'[Stripe Webhook] Payload: {payload.decode()}')
    logging.info(f'[Stripe Webhook] Signature: {sig_header}')
    logging.info(f'[Stripe Webhook] Secret configurado: {"Sim" if endpoint_secret else "Não"}')
    
    if not endpoint_secret:
        logging.error('[Stripe Webhook] STRIPE_WEBHOOK_SECRET não configurado')
        return 'Webhook secret not configured', 500
        
    event = None
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
        logging.info(f'[Stripe Webhook] Evento construído com sucesso: {event["type"]}')
        logging.info(f'[Stripe Webhook] Dados do evento: {event["data"]}')
    except ValueError as e:
        logging.warning(f'[Stripe Webhook] Payload inválido: {e}')
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        logging.error(f'[Stripe Webhook] Falha na assinatura: {e}')
        return 'Invalid signature', 400
    except Exception as e:
        logging.error(f'[Stripe Webhook] Erro inesperado: {e}')
        return 'Webhook error', 400

    if event['type'] == 'checkout.session.completed':
        session_obj = event['data']['object']
        user_id = session_obj['metadata']['user_id']
        plan_key = session_obj['metadata']['plan']
        
        logging.info(f'[Stripe Webhook] Processando pagamento para user_id={user_id}, plano={plan_key}')
        logging.info(f'[Stripe Webhook] Dados da sessão: {session_obj}')
        
        try:
            expiry = (datetime.utcnow().replace(day=1) + datetime.timedelta(days=32)).replace(day=1)
            expiry_str = expiry.strftime('%Y-%m-%d')
            
            # Verificar dados atuais do usuário
            current_user_data = db.reference(f'users/{user_id}').get() or {}
            logging.info(f'[Stripe Webhook] Dados atuais do usuário: {current_user_data}')
            
            # Atualizar plano no banco de dados
            update_data = {
                'plan': plan_key,
                'plan_expiry': expiry_str
            }
            logging.info(f'[Stripe Webhook] Dados a serem atualizados: {update_data}')
            
            db.reference(f'users/{user_id}').update(update_data)
            
            # Verificar se a atualização foi bem sucedida
            updated_user_data = db.reference(f'users/{user_id}').get() or {}
            logging.info(f'[Stripe Webhook] Dados do usuário após atualização: {updated_user_data}')
            
            logging.info(f'[Stripe Webhook] Plano atualizado com sucesso para user_id={user_id}, plano={plan_key}, expira em={expiry_str}')
            
            # Enviar email de confirmação
            user_data = db.reference(f'users/{user_id}').get() or {}
            email = user_data.get('email') or session_obj.get('customer_email')
            if email:
                try:
                    send_email(
                        subject='Pagamento confirmado - EazyBrief',
                        recipients=[email],
                        body=f'Seu pagamento foi confirmado e seu plano {PLANS[plan_key]["name"]} já está ativo! Aproveite todos os benefícios.'
                    )
                    logging.info(f'[Stripe Webhook] Email de confirmação enviado para {email}')
                except Exception as e:
                    logging.error(f'[Stripe Webhook] Erro ao enviar email de confirmação: {e}')
        except Exception as e:
            logging.error(f'[Stripe Webhook] Erro ao atualizar plano: {e}')
            return 'Error updating plan', 500
    else:
        logging.info(f'[Stripe Webhook] Evento ignorado: {event["type"]}')
    
    return '', 200

# Lista de e-mails admin
ADMINS = [
    'robbiealgon@gmail.com',
    'robertocahimagonga@gmail.com'
]

def is_admin(email):
    return email and email.lower() in ADMINS

@app.route('/admin')
def admin_dashboard():
    if 'user_email' not in session or not is_admin(session['user_email']):
        flash('Acesso restrito ao administrador.', 'danger')
        return redirect(url_for('index'))
    # Buscar usuários e métricas
    users_ref = db.reference('users')
    users_data = users_ref.get() or {}
    total_users = len(users_data)
    active_pro = sum(1 for u in users_data.values() if u.get('plan') == 'pro')
    active_premium = sum(1 for u in users_data.values() if u.get('plan') == 'premium')
    briefs_this_month = sum(
        list(u.get('briefs_used', {}).values())[-1] if u.get('briefs_used') else 0
        for u in users_data.values()
    )
    return render_template(
        'admin.html',
        total_users=total_users,
        active_pro=active_pro,
        active_premium=active_premium,
        briefs_this_month=briefs_this_month,
        users=users_data
    )

@app.context_processor
def inject_ga_measurement_id():
    return {'GA_MEASUREMENT_ID': os.getenv('GA_MEASUREMENT_ID', '')}

@app.context_processor
def inject_stripe_key():
    return {'stripe_publishable_key': stripe_publishable_key}

# Função para criar notificação
def create_notification(user_id, title, message, type='info'):
    notification = {
        'id': str(uuid.uuid4()),
        'title': title,
        'message': message,
        'type': type,
        'read': False,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    db.reference(f'notifications/{user_id}').push(notification)
    return notification

@app.route('/notifications')
@login_required
def notifications():
    user_id = get_user_id()
    notifications_ref = db.reference(f'notifications/{user_id}')
    notifications_data = notifications_ref.get() or {}
    
    notifications = []
    for key, val in notifications_data.items():
        val['id'] = key
        notifications.append(val)
    
    notifications.sort(key=lambda x: x['created_at'], reverse=True)
    return render_template('notifications.html', notifications=notifications)

@app.route('/api/notifications/<notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    user_id = get_user_id()
    try:
        db.reference(f'notifications/{user_id}/{notification_id}').update({'read': True})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/notifications/read-all', methods=['POST'])
@login_required
def mark_all_notifications_read():
    user_id = get_user_id()
    try:
        notifications_ref = db.reference(f'notifications/{user_id}')
        notifications = notifications_ref.get() or {}
        for key in notifications:
            notifications_ref.child(key).update({'read': True})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Adicionar notificação ao menu lateral
@app.context_processor
def inject_notification_count():
    notification_count = 0
    if 'user' in session and 'user_email' in session:
        user_id = get_user_id()
        if user_id:
            notifications_ref = db.reference(f'notifications/{user_id}')
            notifications = notifications_ref.get() or {}
            notification_count = sum(1 for n in notifications.values() if not n.get('read', False))
    return dict(notification_count=notification_count)

@app.route('/support')
def support():
    return render_template('support.html')

@app.route('/api/contact', methods=['POST'])
def contact():
    if not request.is_json:
        return jsonify({'success': False, 'error': 'Content-Type deve ser application/json'}), 400
    
    data = request.get_json()
    subject = data.get('subject')
    message = data.get('message')
    
    if not subject or not message:
        return jsonify({'success': False, 'error': 'Assunto e mensagem são obrigatórios'}), 400
    
    try:
        # Salvar mensagem no Firebase
        contact_data = {
            'subject': subject,
            'message': message,
            'email': session.get('user_email', 'Não logado'),
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'status': 'new'
        }
        db.reference('contact_messages').push(contact_data)
        
        # Enviar email para os admins
        admin_emails = ADMINS
        for admin_email in admin_emails:
            try:
                send_email(
                    subject=f'Nova mensagem de contato: {subject}',
                    recipients=[admin_email],
                    body=f"""
                    Nova mensagem de contato recebida:
                    
                    De: {session.get('user_email', 'Não logado')}
                    Assunto: {subject}
                    
                    Mensagem:
                    {message}
                    """
                )
            except Exception as e:
                print(f'Erro ao enviar email para admin {admin_email}: {str(e)}')
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/status')
def status():
    # Obter status atual dos componentes
    api_status = check_api_status()
    db_status = check_database_status()
    auth_status = check_auth_status()
    payment_status = check_payment_status()
    
    # Obter incidentes recentes
    incidents = get_recent_incidents()
    
    return render_template('status.html',
        api_status=api_status,
        db_status=db_status,
        auth_status=auth_status,
        payment_status=payment_status,
        incidents=incidents,
        last_update=datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    )

@app.route('/api/status')
def api_status():
    return jsonify({
        'api_status': check_api_status(),
        'db_status': check_database_status(),
        'auth_status': check_auth_status(),
        'payment_status': check_payment_status()
    })

def check_api_status():
    try:
        # Verificar se a API está respondendo
        response = requests.get('https://api.eazybrief.com/health', timeout=5)
        if response.status_code == 200:
            return 'operational'
        return 'degraded'
    except:
        return 'down'

def check_database_status():
    try:
        # Verificar conexão com o banco de dados
        db = firebase_admin.db.reference('/')
        db.get()
        return 'operational'
    except:
        return 'down'

def check_auth_status():
    try:
        # Verificar serviço de autenticação
        auth = firebase_admin.auth.Client()
        auth.list_users(max_results=1)
        return 'operational'
    except:
        return 'down'

def check_payment_status():
    try:
        # Verificar serviço de pagamento
        response = requests.get('https://api.stripe.com/v1/health', timeout=5)
        if response.status_code == 200:
            return 'operational'
        return 'degraded'
    except:
        return 'down'

def get_recent_incidents():
    try:
        # Buscar incidentes recentes do banco de dados
        incidents_ref = firebase_admin.db.reference('/incidents')
        incidents = incidents_ref.order_by_child('created_at').limit_to_last(5).get()
        
        if not incidents:
            return []
            
        # Converter para lista e ordenar por data
        incident_list = []
        for incident_id, incident in incidents.items():
            incident['id'] = incident_id
            incident_list.append(incident)
            
        return sorted(incident_list, key=lambda x: x['created_at'], reverse=True)
    except:
        return []

@app.route('/legal')
def legal():
    return render_template('legal.html',
        last_update=datetime.now().strftime('%d/%m/%Y')
    )

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    if not request.is_json:
        return jsonify({'success': False, 'error': 'Content-Type deve ser application/json'}), 400
    
    data = request.get_json()
    
    # Validar campos obrigatórios
    required_fields = ['type', 'title', 'description', 'priority']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'success': False, 'error': f'Campo {field} é obrigatório'}), 400
    
    try:
        # Criar entrada no banco de dados
        feedback_data = {
            'type': data['type'],
            'title': data['title'],
            'description': data['description'],
            'priority': data['priority'],
            'contact': data.get('contact', ''),
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'user_id': get_user_id() if 'user' in session else None,
            'user_email': session.get('user_email')
        }
        
        # Salvar no Firebase
        db.reference('feedback').push(feedback_data)
        
        # Enviar email para os admins
        admin_emails = ADMINS
        for admin_email in admin_emails:
            try:
                send_email(
                    subject=f'Novo Feedback: {data["title"]}',
                    recipients=[admin_email],
                    body=f"""
                    Novo feedback recebido:
                    
                    Tipo: {data['type']}
                    Título: {data['title']}
                    Descrição: {data['description']}
                    Prioridade: {data['priority']}
                    Contato: {data.get('contact', 'Não fornecido')}
                    Usuário: {session.get('user_email', 'Não logado')}
                    Data: {feedback_data['created_at']}
                    """
                )
            except Exception as e:
                print(f'Erro ao enviar email para admin {admin_email}: {str(e)}')
        
        return jsonify({'success': True})
    except Exception as e:
        print(f'Erro ao processar feedback: {str(e)}')
        return jsonify({'success': False, 'error': 'Erro ao processar feedback'}), 500

@app.context_processor
def inject_firebase_config():
    return {
        'config': {
            'FIREBASE_API_KEY': os.getenv('FIREBASE_API_KEY'),
            'FIREBASE_AUTH_DOMAIN': os.getenv('FIREBASE_AUTH_DOMAIN'),
            'FIREBASE_PROJECT_ID': os.getenv('FIREBASE_PROJECT_ID'),
            'FIREBASE_STORAGE_BUCKET': os.getenv('FIREBASE_STORAGE_BUCKET'),
            'FIREBASE_MESSAGING_SENDER_ID': os.getenv('FIREBASE_MESSAGING_SENDER_ID'),
            'FIREBASE_APP_ID': os.getenv('FIREBASE_APP_ID')
        }
    }

@app.route('/export')
@login_required
def export_page():
    return render_template('export.html')

@app.route('/api/export/<format>', methods=['POST'])
@login_required
def export_brief(format):
    if format not in ['pdf', 'docx', 'txt', 'html']:
        return jsonify({'error': 'Formato não suportado'}), 400
    
    data = request.get_json()
    options = {
        'includeMetadata': data.get('includeMetadata', False),
        'includeImages': data.get('includeImages', False),
        'includeComments': data.get('includeComments', False)
    }
    
    try:
        if format == 'pdf':
            return export_brief_pdf(options)
        elif format == 'docx':
            return export_brief_docx(options)
        elif format == 'txt':
            return export_brief_txt(options)
        elif format == 'html':
            return export_brief_html(options)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Rotas de integração
@app.route('/api/integrations/google-drive/auth')
@login_required
def google_drive_auth():
    try:
        from google_auth_oauthlib.flow import Flow
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build
        
        flow = Flow.from_client_secrets_file(
            'client_secrets.json',
            scopes=['https://www.googleapis.com/auth/drive.file']
        )
        flow.redirect_uri = url_for('google_drive_callback', _external=True)
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        return jsonify({'authUrl': authorization_url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/integrations/trello/auth')
@login_required
def trello_auth():
    try:
        from trello import TrelloClient
        
        client = TrelloClient(
            api_key=os.getenv('TRELLO_API_KEY'),
            api_secret=os.getenv('TRELLO_API_SECRET')
        )
        
        auth_url = client.get_authorization_url(
            name='EazyBrief',
            expiration='never',
            scope=['read', 'write']
        )
        
        return jsonify({'authUrl': auth_url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/integrations/slack/auth')
@login_required
def slack_auth():
    try:
        client_id = os.getenv('SLACK_CLIENT_ID')
        scope = 'chat:write,channels:read,groups:read,im:read,mpim:read'
        redirect_uri = url_for('slack_callback', _external=True)
        
        auth_url = f'https://slack.com/oauth/v2/authorize?client_id={client_id}&scope={scope}&redirect_uri={redirect_uri}'
        
        return jsonify({'authUrl': auth_url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/integrations/teams/auth')
@login_required
def teams_auth():
    try:
        client_id = os.getenv('TEAMS_CLIENT_ID')
        redirect_uri = url_for('teams_callback', _external=True)
        
        auth_url = f'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope=offline_access%20Files.ReadWrite.All'
        
        return jsonify({'authUrl': auth_url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Callbacks de autenticação
@app.route('/integrations/google-drive/callback')
@login_required
def google_drive_callback():
    try:
        from google_auth_oauthlib.flow import Flow
        from google.oauth2.credentials import Credentials
        
        flow = Flow.from_client_secrets_file(
            'client_secrets.json',
            scopes=['https://www.googleapis.com/auth/drive.file']
        )
        flow.redirect_uri = url_for('google_drive_callback', _external=True)
        
        flow.fetch_token(code=request.args.get('code'))
        credentials = flow.credentials
        
        # Salvar credenciais no Firebase
        user_id = get_user_id()
        db.reference(f'user_integrations/{user_id}/google_drive').set({
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        })
        
        flash('Google Drive conectado com sucesso!', 'success')
        return redirect(url_for('export_page'))
    except Exception as e:
        flash(f'Erro ao conectar com Google Drive: {str(e)}', 'error')
        return redirect(url_for('export_page'))

@app.route('/integrations/trello/callback')
@login_required
def trello_callback():
    try:
        token = request.args.get('token')
        user_id = get_user_id()
        
        # Salvar token no Firebase
        db.reference(f'user_integrations/{user_id}/trello').set({
            'token': token
        })
        
        flash('Trello conectado com sucesso!', 'success')
        return redirect(url_for('export_page'))
    except Exception as e:
        flash(f'Erro ao conectar com Trello: {str(e)}', 'error')
        return redirect(url_for('export_page'))

@app.route('/integrations/slack/callback')
@login_required
def slack_callback():
    try:
        code = request.args.get('code')
        client_id = os.getenv('SLACK_CLIENT_ID')
        client_secret = os.getenv('SLACK_CLIENT_SECRET')
        
        # Trocar código por token
        response = requests.post('https://slack.com/api/oauth.v2.access', {
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code
        })
        
        if response.ok:
            data = response.json()
            if data['ok']:
                user_id = get_user_id()
                db.reference(f'user_integrations/{user_id}/slack').set({
                    'access_token': data['access_token'],
                    'bot_user_id': data['bot_user_id'],
                    'team_id': data['team']['id'],
                    'team_name': data['team']['name']
                })
                
                flash('Slack conectado com sucesso!', 'success')
                return redirect(url_for('export_page'))
        
        raise Exception('Erro ao obter token do Slack')
    except Exception as e:
        flash(f'Erro ao conectar com Slack: {str(e)}', 'error')
        return redirect(url_for('export_page'))

@app.route('/integrations/teams/callback')
@login_required
def teams_callback():
    try:
        code = request.args.get('code')
        client_id = os.getenv('TEAMS_CLIENT_ID')
        client_secret = os.getenv('TEAMS_CLIENT_SECRET')
        redirect_uri = url_for('teams_callback', _external=True)
        
        # Trocar código por token
        response = requests.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        })
        
        if response.ok:
            data = response.json()
            user_id = get_user_id()
            db.reference(f'user_integrations/{user_id}/teams').set({
                'access_token': data['access_token'],
                'refresh_token': data['refresh_token'],
                'expires_in': data['expires_in']
            })
            
            flash('Microsoft Teams conectado com sucesso!', 'success')
            return redirect(url_for('export_page'))
        
        raise Exception('Erro ao obter token do Teams')
    except Exception as e:
        flash(f'Erro ao conectar com Microsoft Teams: {str(e)}', 'error')
        return redirect(url_for('export_page'))

def export_brief_pdf(options):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        import io
        
        # Obter dados do brief
        brief_id = request.args.get('brief_id')
        brief_ref = db.reference(f'briefs/{brief_id}')
        brief_data = brief_ref.get()
        
        if not brief_data:
            raise Exception('Brief não encontrado')
        
        # Criar buffer para o PDF
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Título
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        story.append(Paragraph(brief_data['title'], title_style))
        
        # Metadados (se solicitado)
        if options['includeMetadata']:
            meta_style = ParagraphStyle(
                'MetaData',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.gray
            )
            story.append(Paragraph(f'Criado em: {brief_data.get("created_at", "N/A")}', meta_style))
            story.append(Paragraph(f'Última atualização: {brief_data.get("updated_at", "N/A")}', meta_style))
            story.append(Spacer(1, 20))
        
        # Conteúdo
        content_style = ParagraphStyle(
            'Content',
            parent=styles['Normal'],
            fontSize=12,
            spaceAfter=12
        )
        
        for section in brief_data.get('sections', []):
            story.append(Paragraph(section['title'], styles['Heading2']))
            story.append(Paragraph(section['content'], content_style))
            
            # Imagens (se solicitado)
            if options['includeImages'] and 'images' in section:
                for image_url in section['images']:
                    try:
                        img = Image(image_url, width=6*inch, height=4*inch)
                        story.append(img)
                        story.append(Spacer(1, 12))
                    except:
                        pass
            
            story.append(Spacer(1, 20))
        
        # Comentários (se solicitado)
        if options['includeComments'] and 'comments' in brief_data:
            story.append(Paragraph('Comentários', styles['Heading2']))
            for comment in brief_data['comments']:
                story.append(Paragraph(f"{comment['user']} ({comment['date']}):", styles['Heading3']))
                story.append(Paragraph(comment['text'], content_style))
                story.append(Spacer(1, 12))
        
        # Gerar PDF
        doc.build(story)
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"{brief_data['title']}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        raise Exception(f'Erro ao gerar PDF: {str(e)}')

def export_brief_docx(options):
    try:
        from docx import Document
        from docx.shared import Inches
        import io
        
        # Obter dados do brief
        brief_id = request.args.get('brief_id')
        brief_ref = db.reference(f'briefs/{brief_id}')
        brief_data = brief_ref.get()
        
        if not brief_data:
            raise Exception('Brief não encontrado')
        
        # Criar documento
        doc = Document()
        
        # Título
        doc.add_heading(brief_data['title'], 0)
        
        # Metadados (se solicitado)
        if options['includeMetadata']:
            doc.add_paragraph(f'Criado em: {brief_data.get("created_at", "N/A")}')
            doc.add_paragraph(f'Última atualização: {brief_data.get("updated_at", "N/A")}')
            doc.add_paragraph()
        
        # Conteúdo
        for section in brief_data.get('sections', []):
            doc.add_heading(section['title'], level=1)
            doc.add_paragraph(section['content'])
            
            # Imagens (se solicitado)
            if options['includeImages'] and 'images' in section:
                for image_url in section['images']:
                    try:
                        doc.add_picture(image_url, width=Inches(6))
                        doc.add_paragraph()
                    except:
                        pass
        
        # Comentários (se solicitado)
        if options['includeComments'] and 'comments' in brief_data:
            doc.add_heading('Comentários', level=1)
            for comment in brief_data['comments']:
                doc.add_heading(f"{comment['user']} ({comment['date']})", level=2)
                doc.add_paragraph(comment['text'])
        
        # Salvar em buffer
        buffer = io.BytesIO()
        doc.save(buffer)
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"{brief_data['title']}.docx",
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        )
    except Exception as e:
        raise Exception(f'Erro ao gerar DOCX: {str(e)}')

def export_brief_txt(options):
    try:
        # Obter dados do brief
        brief_id = request.args.get('brief_id')
        brief_ref = db.reference(f'briefs/{brief_id}')
        brief_data = brief_ref.get()
        
        if not brief_data:
            raise Exception('Brief não encontrado')
        
        # Criar conteúdo
        content = []
        content.append(f"Título: {brief_data['title']}\n")
        
        # Metadados (se solicitado)
        if options['includeMetadata']:
            content.append(f"Criado em: {brief_data.get('created_at', 'N/A')}")
            content.append(f"Última atualização: {brief_data.get('updated_at', 'N/A')}\n")
        
        # Conteúdo
        for section in brief_data.get('sections', []):
            content.append(f"\n{section['title']}")
            content.append("=" * len(section['title']))
            content.append(f"\n{section['content']}\n")
            
            # URLs das imagens (se solicitado)
            if options['includeImages'] and 'images' in section:
                content.append("Imagens:")
                for image_url in section['images']:
                    content.append(f"- {image_url}")
                content.append("")
        
        # Comentários (se solicitado)
        if options['includeComments'] and 'comments' in brief_data:
            content.append("\nComentários")
            content.append("=" * 10)
            for comment in brief_data['comments']:
                content.append(f"\n{comment['user']} ({comment['date']}):")
                content.append(f"{comment['text']}\n")
        
        # Gerar arquivo
        output = "\n".join(content)
        
        return Response(
            output,
            mimetype='text/plain',
            headers={
                'Content-Disposition': f'attachment; filename={brief_data["title"]}.txt'
            }
        )
    except Exception as e:
        raise Exception(f'Erro ao gerar TXT: {str(e)}')

def export_brief_html(options):
    try:
        # Obter dados do brief
        brief_id = request.args.get('brief_id')
        brief_ref = db.reference(f'briefs/{brief_id}')
        brief_data = brief_ref.get()
        
        if not brief_data:
            raise Exception('Brief não encontrado')
        
        # Criar HTML
        html = []
        html.append(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>{brief_data['title']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #666; margin-top: 30px; }}
                .metadata {{ color: #888; font-size: 0.9em; }}
                .section {{ margin: 20px 0; }}
                .image {{ max-width: 100%; margin: 10px 0; }}
                .comment {{ background: #f5f5f5; padding: 10px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <h1>{brief_data['title']}</h1>
        """)
        
        # Metadados (se solicitado)
        if options['includeMetadata']:
            html.append(f"""
            <div class="metadata">
                <p>Criado em: {brief_data.get('created_at', 'N/A')}</p>
                <p>Última atualização: {brief_data.get('updated_at', 'N/A')}</p>
            </div>
            """)
        
        # Conteúdo
        for section in brief_data.get('sections', []):
            html.append(f"""
            <div class="section">
                <h2>{section['title']}</h2>
                <div>{section['content']}</div>
            """)
            
            # Imagens (se solicitado)
            if options['includeImages'] and 'images' in section:
                for image_url in section['images']:
                    html.append(f'<img class="image" src="{image_url}" alt="Imagem">')
            
            html.append("</div>")
        
        # Comentários (se solicitado)
        if options['includeComments'] and 'comments' in brief_data:
            html.append('<h2>Comentários</h2>')
            for comment in brief_data['comments']:
                html.append(f"""
                <div class="comment">
                    <strong>{comment['user']}</strong> ({comment['date']})
                    <p>{comment['text']}</p>
                </div>
                """)
        
        html.append("</body></html>")
        
        return Response(
            "\n".join(html),
            mimetype='text/html',
            headers={
                'Content-Disposition': f'attachment; filename={brief_data["title"]}.html'
            }
        )
    except Exception as e:
        raise Exception(f'Erro ao gerar HTML: {str(e)}')

@app.context_processor
def inject_user_theme():
    user_theme = 'light'
    user_photo = None
    user_plan = 'free'
    user_id = get_user_id()
    if user_id:
        prefs = db.reference(f'user_prefs/{user_id}').get() or {}
        user_theme = prefs.get('theme', 'light')
        user_info = auth.get_user_by_email(session['user_email'])
        user_photo = prefs.get('photo_url', user_info.photo_url)
        
        # Buscar plano diretamente do banco de dados
        user_data = db.reference(f'users/{user_id}').get() or {}
        user_plan = user_data.get('plan', 'free')
        
        # Log para debug
        logging.info(f'[Context] Injetando contexto para user_id={user_id}')
        logging.info(f'[Context] Dados do usuário: {user_data}')
        logging.info(f'[Context] Plano atual: {user_plan}')
    
    return dict(user_theme=user_theme, user_photo=user_photo, user_plan=user_plan, plans=PLANS)

def get_oauth2_config():
    return {
        "web": {
            "client_id": os.getenv('GOOGLE_CLIENT_ID'),
            "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [f"{request.url_root}oauth2callback"]
        }
    }

@app.route('/authorize')
def authorize():
    flow = Flow.from_client_config(
        get_oauth2_config(),
        scopes=['https://www.googleapis.com/auth/calendar'],
        redirect_uri=f"{request.url_root}oauth2callback"
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']
    flow = Flow.from_client_config(
        get_oauth2_config(),
        scopes=['https://www.googleapis.com/auth/calendar'],
        redirect_uri=f"{request.url_root}oauth2callback",
        state=state
    )
    flow.fetch_token(
        authorization_response=request.url,
        code=request.args.get('code')
    )
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
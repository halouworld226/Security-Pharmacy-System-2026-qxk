import os
with open('.env', 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#'):
            key, value = line.split('=', 1)
            os.environ[key] = value
import csv
import io
import uuid
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify, g
from werkzeug.utils import secure_filename
import db_manager as db
import captcha_utils

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = int(os.environ.get('DB_PORT', 15432))
    DB_USER = os.environ.get('DB_USER', 'druguser')
    DB_PASSWORD = os.environ.get('DB_PASSWORD')  # 不设默认值
    DB_NAME = os.environ.get('DB_NAME', 'drugstore')

    # SSL 配置
    DB_SSL_ENABLED = os.environ.get('DB_SSL_ENABLED', 'false').lower() == 'true'
    DB_SSL_CERT_DIR = os.environ.get('DB_SSL_CERT_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs'))

    # 文件上传配置
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    PAGE_SIZE = 15

# 在 Config 类之后，检查数据库密码是否设置
if not Config.DB_PASSWORD:
    raise RuntimeError("❌ 环境变量 DB_PASSWORD 未设置！请创建 .env 文件。")

db.DB_CONFIG = {
    "host": Config.DB_HOST, "port": Config.DB_PORT,
    "user": Config.DB_USER, "password": Config.DB_PASSWORD,
    "dbname": Config.DB_NAME,
}

# 根据环境变量启用数据库 SSL 连接
if Config.DB_SSL_ENABLED:
    db.configure_ssl(enable=True, cert_dir=Config.DB_SSL_CERT_DIR)
    print(f"[安全] 数据库 SSL 已启用（证书目录: {Config.DB_SSL_CERT_DIR}）")
else:
    print("[信息] 数据库 SSL 未启用（设置 DB_SSL_ENABLED=true 以启用）")

# 打印当前数据库连接用户（便于确认已切换为最小权限账号）
print(f"[信息] 数据库连接用户: {Config.DB_USER}@{Config.DB_HOST}:{Config.DB_PORT}/{Config.DB_NAME}")

app = Flask(__name__)
app.config.from_object(Config)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=8)

# 会话超时配置（秒）
SESSION_IDLE_TIMEOUT = 1800  # 30 分钟无操作自动超时
SESSION_ABSOLUTE_TIMEOUT = 28800  # 8 小时绝对超时

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# 图片魔数（文件头特征字节），防止后缀伪造上传
IMAGE_MAGIC_BYTES = {
    b'\x89PNG\r\n\x1a\n': 'png',
    b'\xff\xd8\xff': 'jpg',
    b'GIF87a': 'gif',
    b'GIF89a': 'gif',
}

def validate_image_signature(file_stream):
    """校验文件头魔数，确认是真实图片文件"""
    file_stream.seek(0)
    header = file_stream.read(8)
    file_stream.seek(0)
    for magic, _ in IMAGE_MAGIC_BYTES.items():
        if header.startswith(magic):
            return True
    return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def _role_wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                flash('请先登录', 'warning')
                return redirect(url_for('login'))
            if session['user']['role'] not in roles:
                flash('权限不足', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return _role_wrapper

@app.context_processor
def inject_user():
    return dict(current_user=session.get('user'))

@app.context_processor
def inject_now():
    return dict(now=datetime.now())

# ---------- CSRF 防护 & 请求上下文 ----------
CSRF_EXEMPT = {'login', 'logout', 'static'}

def generate_csrf_token():
    token = str(uuid.uuid4())
    session['csrf_token'] = token
    return token

@app.before_request
def before_request():
    # 强制 HTTPS（生产环境配置，开发环境可跳过）
    if os.environ.get('FORCE_HTTPS', 'false').lower() == 'true':
        if not request.is_secure and request.headers.get('X-Forwarded-Proto', 'https') != 'https':
            return redirect(request.url.replace('http://', 'https://', 1), code=301)

    # 设置请求上下文（IP 和 User-Agent），供 db_manager.write_log 使用
    db.set_request_context(
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')
    )

    # ========== 会话安全检查（已登录用户）==========
    if 'user' in session and request.endpoint not in ('login', 'logout', 'static'):
        now = time.time()

        # 1. 会话绝对超时检查（从登录开始算，8小时强制下线）
        login_time = session.get('_login_time', now)
        if (now - login_time) > SESSION_ABSOLUTE_TIMEOUT:
            session.clear()
            flash('登录已超过8小时，请重新登录', 'warning')
            return redirect(url_for('login'))

        # 2. 会话空闲超时检查（30分钟无操作自动超时）
        last_activity = session.get('_last_activity', now)
        if (now - last_activity) > SESSION_IDLE_TIMEOUT:
            session.clear()
            flash('会话已超时，请重新登录', 'warning')
            return redirect(url_for('login'))

        # 更新最后活跃时间
        session['_last_activity'] = now

        # 3. 单设备登录检查（防止同一账号多处登录）
        session_token = session.get('session_token')
        if session_token and not db.validate_user_session(session['user']['username'], session_token):
            session.clear()
            flash('您的账号已在其他地方登录，当前会话已下线', 'warning')
            return redirect(url_for('login'))

        # 更新服务端会话活跃时间
        if session_token:
            db.update_session_activity(session['user']['username'], session_token)

    # ========== CSRF 验证 ==========
    if request.method in ('POST', 'PUT', 'DELETE'):
        if request.endpoint and request.endpoint in CSRF_EXEMPT:
            return
        token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'message': 'CSRF Token 无效，请刷新页面后重试'}), 403
            flash('CSRF Token 无效，请刷新页面后重试', 'danger')
            return redirect(url_for('login'))

@app.context_processor
def inject_csrf_token():
    return {'csrf_token': session.get('csrf_token', '')}

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' https:; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com https://cdn.bootcdn.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.bootcdn.net; "
        "img-src 'self' data: https://api.dicebear.com; "
        "font-src 'self' https://cdn.jsdelivr.net https://cdn.bootcdn.net; "
        "connect-src 'self'"
    )
    return response

# ---------- 登录速率限制 ----------
_login_attempts = {}  # {ip_or_username: [timestamp, ...]}

def _check_rate_limit(key, limit=10, window=60):
    """基于时间窗口的速率限制，超限返回剩余等待秒数，否则返回 0"""
    now = time.time()
    attempts = [t for t in _login_attempts.get(key, []) if now - t < window]
    if len(attempts) >= limit:
        return int(window - (now - attempts[0]))
    attempts.append(now)
    _login_attempts[key] = attempts
    return 0

# ---------- 验证码 ----------
@app.route('/captcha/image')
def captcha_image():
    text = captcha_utils.generate_captcha_text()
    session['captcha_text'] = text
    img = captcha_utils.generate_captcha_image(text)
    return send_file(img, mimetype='image/png')

def captcha_action_required(f):
    """装饰器：关键操作需验证码（5分钟内有效，之后需重新验证）"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        now = time.time()
        captcha_verified = session.get('captcha_verified_at', 0)
        # 5 分钟内已验证过，直接放行
        if captcha_verified and (now - captcha_verified) < 300:
            session.pop('captcha_text', None)
            return f(*args, **kwargs)
        # 正在提交验证码
        captcha_input = (request.form.get('captcha') or request.args.get('captcha') or '').strip().upper()
        if captcha_input and captcha_input == session.get('captcha_text', ''):
            session['captcha_verified_at'] = now
            session.pop('captcha_text', None)
            return f(*args, **kwargs)
        if captcha_input:
            flash('验证码错误', 'danger')
        return _render_captcha_page(request.path, dict(request.args))
    return decorated_function

def _render_captcha_page(target_url, params):
    """渲染关键操作验证码确认页"""
    return render_template('captcha_confirm.html', target_url=target_url, params=params)

# ---------- Login ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()
        if not username or not password or not role:
            flash('请填写用户名、密码并选择角色', 'danger')
            return render_template('login.html')
        # 速率限制：单IP 20次/分钟，单用户名 10次/5分钟
        ip_key = f"ip:{request.remote_addr}"
        user_key = f"user:{username}"
        ip_block = _check_rate_limit(ip_key, limit=20, window=60)
        user_block = _check_rate_limit(user_key, limit=10, window=300)
        if ip_block or user_block:
            wait = max(ip_block, user_block)
            flash(f'操作过于频繁，请 {wait} 秒后再试', 'danger')
            return render_template('login.html')
        # 验证码校验
        captcha_input = request.form.get('captcha', '').strip().upper()
        if not captcha_input or captcha_input != session.get('captcha_text', ''):
            flash('验证码错误', 'danger')
            return render_template('login.html')
        session.pop('captcha_text', None)
        user = db.login(username, password, role)
        if user:
            if user.get('locked'):
                remaining = user['remaining']
                minutes = remaining // 60
                seconds = remaining % 60
                flash(f'账户已被锁定，请{minutes}分{seconds}秒后再试', 'danger')
                return render_template('login.html', locked_remaining=remaining)
            session['user'] = dict(user)
            # 会话安全：生成会话令牌，记录登录时间和活跃时间
            session_token = str(uuid.uuid4())
            session['session_token'] = session_token
            session.permanent = True
            session['_login_time'] = time.time()
            session['_last_activity'] = time.time()
            db.create_user_session(
                username=user['username'],
                session_token=session_token,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')
            )
            generate_csrf_token()
            flash(f'欢迎，{user["real_name"]}', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('用户名、密码或角色不匹配', 'danger')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    # 清除服务端会话记录
    if 'user' in session:
        db.remove_user_session(session['user']['username'])
    session.clear()
    flash('已退出登录', 'info')
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user' in session:
        user = session['user']
        if user['role'] == '销售员':
            return redirect(url_for('charts_page'))
        elif user['role'] == '药房管理员':
            return redirect(url_for('shopmanager_dashboard'))
        else:
            return redirect(url_for('charts_page'))
    return redirect(url_for('login'))
# ---------- Dashboard ----------
@app.route('/dashboard')
@login_required
def dashboard():
    user = session['user']
    if user['role'] == '药房管理员':
        return redirect(url_for('shopmanager_dashboard'))
    if user['role'] == '系统管理员':
        return redirect(url_for('charts_page'))
    if user['role'] == '销售员':
        return redirect(url_for('charts_page'))
    # 销售员仪表盘
    sales_rows, _ = db.get_sales_orders(1, 10000, '', '全部')
    med_rows, _ = db.search_medicines({}, 1, 10000)
    low_rows, exp_rows = db.get_inventory_warnings('全部')
    total_sales_amount = round(sum(float(r['actual_amount']) for r in sales_rows), 2)
    total_med_count = len(med_rows)
    stores = set(r['store_name'] for r in med_rows if r['store_name'])
    extra_stats = db.get_salesman_dashboard(user['username'], user['store_name'])
    return render_template('dashboard.html',
                           total_sales_amount=total_sales_amount,
                           total_sales_count=len(sales_rows),
                           total_med_count=total_med_count,
                           total_store_count=len(stores),
                           low_warn_count=len(low_rows),
                           exp_warn_count=len(exp_rows),
                           suggestion_pending=0,
                           extra_stats=extra_stats)

# ---------- 图表分析（核心页面）----------
@app.route('/charts')
@login_required
def charts_page():
    user = session['user']
    extra_stats = {}
    if user['role'] == '销售员':
        salesman_stats = db.get_salesman_dashboard(user['username'], user['store_name'])
        total_orders = db.query_one("""
            SELECT COUNT(*) AS count, COALESCE(SUM(actual_amount), 0) AS amount
            FROM sales_orders
            WHERE cashier=%s
        """, (user['username'],))
        store_employees = db.query_one("""
            SELECT COUNT(*) AS count
            FROM users
            WHERE store_name=%s AND role='销售员' AND is_active=TRUE
        """, (user['store_name'],))
        last_login = db.query_one("""
            SELECT last_login FROM users WHERE username=%s
        """, (user['username'],))
        extra_stats = {
            'today_orders': salesman_stats['今日订单数'],
            'today_sales': salesman_stats['今日销售额'],
            'total_orders': total_orders['count'],
            'total_sales': float(total_orders['amount']),
            'store_count': 1,
            'employee_count': store_employees['count'],
            'last_login': last_login['last_login'] if last_login and last_login['last_login'] else '首次登录'
        }
    return render_template('charts.html', extra_stats=extra_stats)

@app.route('/api/chart_data')
@login_required
def chart_data():
    days = request.args.get('days', 7, type=int)
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    user = session['user']
    role = user['role']
    store_name = user['store_name']
    username = user['username']

    if role == '系统管理员':
        selected_store = request.args.get('store_name', '').strip()
        total_sales = float(db.query_one("SELECT COALESCE(SUM(actual_amount),0) FROM sales_orders")["coalesce"])
        total_orders = db.query_one("SELECT COUNT(*) AS c FROM sales_orders")["c"]
        store_count = db.query_one("SELECT COUNT(*) AS c FROM stores")["c"]
        salesman_count = db.query_one("SELECT COUNT(*) AS c FROM users WHERE role='销售员' AND is_active=TRUE")["c"]
        med_count = db.query_one("SELECT COUNT(*) AS c FROM medicines")["c"]
        low_stock_count = db.query_one("SELECT COUNT(*) AS c FROM medicines WHERE stock <= warning_stock")["c"]

        store_sales = db.query_all("""
            SELECT so.store_name, COALESCE(SUM(so.actual_amount),0) AS sales,
                   s.id AS store_id
            FROM sales_orders so
            JOIN stores s ON so.store_name = s.pharmacy_name
            WHERE so.created_at >= %s AND so.created_at <= %s
            GROUP BY so.store_name, s.id
            ORDER BY sales DESC
        """, (start_date, end_date))

        if selected_store and selected_store != '全部':
            trend = db.query_all("""
                SELECT created_at::date as sale_date, SUM(actual_amount) AS amount
                FROM sales_orders
                WHERE store_name = %s AND created_at >= %s AND created_at <= %s
                GROUP BY sale_date ORDER BY sale_date
            """, (selected_store, start_date, end_date))
            trend_profit = db.query_all("""
                SELECT so.created_at::date as sale_date,
                       COALESCE(SUM(si.amount - si.quantity * m.purchase_price), 0) AS profit
                FROM sales_orders so
                JOIN sales_items si ON so.id = si.order_id
                JOIN medicines m ON si.medicine_id = m.id
                WHERE so.store_name = %s AND so.created_at >= %s AND so.created_at <= %s
                GROUP BY so.created_at::date ORDER BY sale_date
            """, (selected_store, start_date, end_date))
        else:
            trend = db.query_all("""
                SELECT created_at::date as sale_date, SUM(actual_amount) AS amount
                FROM sales_orders
                WHERE created_at >= %s AND created_at <= %s
                GROUP BY sale_date ORDER BY sale_date
            """, (start_date, end_date))
            trend_profit = db.query_all("""
                SELECT so.created_at::date as sale_date,
                       COALESCE(SUM(si.amount - si.quantity * m.purchase_price), 0) AS profit
                FROM sales_orders so
                JOIN sales_items si ON so.id = si.order_id
                JOIN medicines m ON si.medicine_id = m.id
                WHERE so.created_at >= %s AND so.created_at <= %s
                GROUP BY so.created_at::date ORDER BY sale_date
            """, (start_date, end_date))

        cat_stock = db.query_all("""
            SELECT c.name, COALESCE(SUM(m.stock),0) AS stock
            FROM medicines m JOIN categories c ON m.category_id = c.id
            GROUP BY c.name ORDER BY stock DESC
        """)
        low_stock, near_expiry = db.get_inventory_warnings('全部')

        return jsonify({
            'cards': {
                'total_sales': total_sales,
                'total_orders': total_orders,
                'store_count': store_count,
                'salesman_count': salesman_count,
                'medicine_count': med_count,
                'low_stock_count': low_stock_count
            },
            'store_sales': store_sales,
            'sales_trend': [{'date': str(r['sale_date']), 'amount': float(r['amount'])} for r in trend],
            'sales_trend_profit': [{'date': str(r['sale_date']), 'profit': float(r['profit'])} for r in trend_profit],
            'category_stock': [{'name': r['name'], 'value': int(r['stock'])} for r in cat_stock],
            'warnings': {'low_stock': low_stock, 'near_expiry': near_expiry}
        })

    else:
        # ---------- 旧格式：销售员/药房管理员图表界面 ----------
        sales_sql = "SELECT * FROM sales_orders WHERE created_at >= %s AND created_at <= %s"
        params = [start_date, end_date]
        if role == '药房管理员':
            sales_sql += " AND store_name = %s"
            params.append(store_name)
        elif role == '销售员':
            sales_sql += " AND store_name = %s AND cashier = %s"
            params.extend([store_name, username])
        sales_rows = db.query_all(sales_sql, params)

        med_filters = {} if role == '系统管理员' else {'store_name': store_name}
        med_rows, _ = db.search_medicines(med_filters, 1, 10000)

        pay_map = {}
        store_amount_map = {}
        day_amount_map = {}
        day_profit_map = {}
        cat_stock_map = {}
        medicine_sales_map = {}
        for r in sales_rows:
            pay = r['payment_method'] or '未知'
            pay_map[pay] = pay_map.get(pay, 0) + 1
            store = r['store_name'] or '未知门店'
            store_amount_map[store] = store_amount_map.get(store, 0) + float(r['actual_amount'])
            day = str(r['created_at'])[:10]
            day_amount_map[day] = day_amount_map.get(day, 0) + float(r['actual_amount'])
            order_items = db.get_sale_order_items(r['order_no'])
            for item in order_items:
                med_name = item['name']
                medicine_sales_map[med_name] = medicine_sales_map.get(med_name, 0) + int(item['sold_quantity'])
                med_price = db.query_one("SELECT purchase_price FROM medicines WHERE id = %s", (item['medicine_id'],))
                purchase_price = float(med_price['purchase_price']) if med_price else 0
                item_profit = float(item['amount']) - purchase_price * int(item['sold_quantity'])
                day_profit_map[day] = day_profit_map.get(day, 0) + item_profit
        for r in med_rows:
            cname = r['category_name'] if r['category_name'] else '未分类'
            cat_stock_map[cname] = cat_stock_map.get(cname, 0) + int(r['stock'])

        pay_data = sorted(pay_map.items(), key=lambda x: x[1], reverse=True)
        store_data = sorted(store_amount_map.items(), key=lambda x: x[1], reverse=True)
        cat_data = sorted(cat_stock_map.items(), key=lambda x: x[1], reverse=True)[:8]
        day_data = sorted(day_amount_map.items(), key=lambda x: x[0])
        day_profit_data = sorted(day_profit_map.items(), key=lambda x: x[0])
        medicine_sales_data = sorted(medicine_sales_map.items(), key=lambda x: x[1], reverse=True)[:8]

        week_start = end_date - timedelta(days=end_date.weekday())
        w_params = [week_start]
        m_params = [end_date.replace(day=1)]
        if role == '药房管理员':
            week_sql = "SELECT COUNT(*) AS order_count, COALESCE(SUM(actual_amount),0) AS total_amount FROM sales_orders WHERE created_at >= %s AND store_name=%s"
            month_sql = "SELECT COUNT(*) AS order_count FROM sales_orders WHERE created_at >= %s AND store_name=%s"
            w_params.append(store_name)
            m_params.append(store_name)
        elif role == '销售员':
            week_sql = "SELECT COUNT(*) AS order_count, COALESCE(SUM(actual_amount),0) AS total_amount FROM sales_orders WHERE created_at >= %s AND store_name=%s AND cashier=%s"
            month_sql = "SELECT COUNT(*) AS order_count FROM sales_orders WHERE created_at >= %s AND store_name=%s AND cashier=%s"
            w_params.extend([store_name, username])
            m_params.extend([store_name, username])
        else:
            week_sql = "SELECT COUNT(*) AS order_count, COALESCE(SUM(actual_amount),0) AS total_amount FROM sales_orders WHERE created_at >= %s"
            month_sql = "SELECT COUNT(*) AS order_count FROM sales_orders WHERE created_at >= %s"

        week_sales = db.query_one(week_sql, w_params)
        month_sales = db.query_one(month_sql, m_params)

        return jsonify({
            'pay_data': pay_data,
            'store_data': store_data,
            'cat_data': cat_data,
            'day_data': day_data,
            'day_profit_data': day_profit_data,
            'medicine_sales_data': medicine_sales_data,
            'total_med_count': len(med_rows),
            'week_order_count': week_sales['order_count'] if week_sales else 0,
            'week_total_amount': float(week_sales['total_amount']) if week_sales else 0.0,
            'month_order_count': month_sales['order_count'] if month_sales else 0
        })

# 下钻：门店销售员列表（修正括号）
@app.route('/api/store/<int:store_id>/salesmen')
@login_required
def store_salesmen(store_id):
    if session['user']['role'] != '系统管理员':
        return jsonify({'error': '权限不足'}), 403
    store = db.query_one("SELECT pharmacy_name FROM stores WHERE id=%s", (store_id,))
    if not store:
        return jsonify({'error': '门店不存在'}), 404
    salesmen = db.query_all("SELECT username, real_name FROM users WHERE store_name=%s AND role='销售员' AND is_active=TRUE", (store['pharmacy_name'],))
    return jsonify(salesmen)

@app.route('/api/salesman/<username>/orders')
@login_required
def salesman_orders(username):
    if session['user']['role'] not in ['系统管理员', '药房管理员']:
        return jsonify({'error': '权限不足'}), 403
    page = request.args.get('page', 1, type=int)
    page_size = 10
    orders = db.query_all("""
        SELECT order_no, actual_amount, payment_method, created_at
        FROM sales_orders WHERE cashier=%s
        ORDER BY created_at DESC LIMIT %s OFFSET %s
    """, (username, page_size, (page-1)*page_size))
    total = db.query_one("SELECT COUNT(*) AS c FROM sales_orders WHERE cashier=%s", (username,))["c"]
    return jsonify({'orders': orders, 'total': total, 'page': page})

# ---------- 门店管理 ----------
@app.route('/stores')
@login_required
@role_required('系统管理员')
def stores_page():
    page = request.args.get('page', 1, type=int)
    keyword = request.args.get('keyword', '')
    stores, total = db.get_stores(page, 10, keyword)
    return render_template('stores.html', stores=stores, page=page, total=total, keyword=keyword)

@app.route('/api/stores', methods=['GET', 'POST'])
@login_required
@role_required('系统管理员')
def api_stores():
    if request.method == 'GET':
        page = request.args.get('page', 1, type=int)
        keyword = request.args.get('keyword', '')
        stores, total = db.get_stores(page, 10, keyword)
        return jsonify({'data': stores, 'total': total, 'page': page})
    data = request.get_json()
    try:
        db.add_store(data['pharmacy_code'], data['pharmacy_name'],
                     data['location'], data.get('business_status', True), data.get('business_hours', ''))
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/stores/<int:sid>', methods=['PUT', 'DELETE'])
@login_required
@role_required('系统管理员')
def api_store_modify(sid):
    if request.method == 'PUT':
        data = request.get_json()
        try:
            db.update_store(sid, data['pharmacy_code'], data['pharmacy_name'],
                            data['location'], data.get('business_status', True), data.get('business_hours', ''))
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
    else:
        try:
            db.delete_store(sid)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

# ---------- 用户管理（增强）----------
@app.route('/users')
@login_required
@role_required('系统管理员')
def users():
    page = request.args.get('page', 1, type=int)
    keyword = request.args.get('keyword', '').strip()
    store_name = request.args.get('store_name', '').strip()
    rows, total = db.get_users(page, app.config['PAGE_SIZE'], keyword, store_name)
    stores = db.get_all_stores()
    return render_template('users.html', users=rows, page=page, total=total, keyword=keyword,
                           current_store=store_name, stores=stores)

@app.route('/user/add', methods=['POST'])
@login_required
@role_required('系统管理员')
def add_user():
    data = request.form
    try:
        db.add_user(data['username'], data['password'], data['role'], data['real_name'],
                    data['phone'], data['store_name'])
        flash('用户添加成功', 'success')
    except Exception as e:
        flash(str(e), 'danger')
    return redirect(url_for('users'))

@app.route('/user/edit/<int:uid>', methods=['POST'])
@login_required
@role_required('系统管理员')
def edit_user(uid):
    data = request.form
    try:
        db.update_user(uid, data['username'], data['password'], data['role'],
                       data['real_name'], data['phone'], data['store_name'],
                       data.get('is_active') == '1')
        flash('用户更新成功', 'success')
    except Exception as e:
        flash(str(e), 'danger')
    return redirect(url_for('users'))

@app.route('/user/delete/<int:uid>')
@login_required
@role_required('系统管理员')
@captcha_action_required
def delete_user(uid):
    db.delete_user(uid)
    flash('用户已删除，ID已自动重整', 'success')
    return redirect(url_for('users'))

# ---------- 药品管理（系统管理员和药房管理员共用）----------
@app.route('/medicines')
@login_required
def medicines():
    user = session['user']
    page = request.args.get('page', 1, type=int)
    filters = {
        'keyword': request.args.get('keyword', ''),
        'store_name': request.args.get('store_name', '全部'),
        'manufacturer': request.args.get('manufacturer', ''),
        'category_id': request.args.get('category_id', ''),
        'pmin': request.args.get('pmin', ''),
        'pmax': request.args.get('pmax', ''),
        'smin': request.args.get('smin', ''),
        'smax': request.args.get('smax', ''),
        'stock_status': request.args.get('stock_status', ''),
        'is_rx': request.args.get('is_rx', '')
    }
    if user['role'] == '药房管理员':
        filters['store_name'] = user['store_name']
    rows, total = db.search_medicines(filters, page, app.config['PAGE_SIZE'])
    categories = db.get_categories()
    stores = db.get_store_names()
    return render_template('medicines.html', medicines=rows, page=page, total=total,
                           filters=filters, categories=categories, stores=stores)

# ---------- 药品总览（系统管理员专用）----------
@app.route('/medicine_overview')
@login_required
@role_required('系统管理员')
def medicine_overview():
    page = request.args.get('page', 1, type=int)
    keyword = request.args.get('keyword', '').strip()
    store_filter = request.args.get('store', '全部').strip()
    filters = {
        'keyword': keyword,
        'store_name': store_filter if store_filter != '全部' else '',
    }
    rows, total = db.search_medicines(filters, page, 20)
    # 获取门店列表（从 stores 表，保证包含所有门店）
    all_stores = db.get_all_stores()
    stores = [s['pharmacy_name'] for s in all_stores]
    return render_template('medicine_overview.html',
                           medicines=rows,
                           page=page,
                           total=total,
                           page_size=20,
                           keyword=keyword,
                           stores=stores,
                           current_store=store_filter)

@app.route('/medicine/add', methods=['POST'])
@login_required
@role_required('药房管理员', '系统管理员')
def add_medicine():
    form = request.form
    image_path = ''
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename) and validate_image_signature(file):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            filename = f"{timestamp}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_path = f"/static/uploads/{filename}"
    db.add_medicine(
        code=form['code'], name=form['name'], generic_name=form['generic_name'],
        category_id=int(form['category_id']), spec=form['spec'], unit=form['unit'],
        manufacturer=form['manufacturer'], approval_no=form['approval_no'],
        is_rx=form.get('is_rx') == '1', price=float(form['price']),
        stock=int(form['stock']), warning_stock=int(form['warning_stock']),
        store_name=form['store_name'], description=form['description'],
        usage_method=form['usage_method'], adverse_reaction=form['adverse_reaction'],
        storage_condition=form['storage_condition'], image_path=image_path
    )
    flash('药品添加成功', 'success')
    return redirect(url_for('medicines'))

@app.route('/medicine/edit/<int:mid>', methods=['POST'])
@login_required
@role_required('药房管理员', '系统管理员')
def edit_medicine(mid):
    form = request.form
    med = db.get_medicine_detail(mid)
    image_path = med['image_path'] or ''
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename) and validate_image_signature(file):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            filename = f"{timestamp}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_path = f"/static/uploads/{filename}"
    db.update_medicine(
        mid, code=form['code'], name=form['name'], generic_name=form['generic_name'],
        category_id=int(form['category_id']), spec=form['spec'], unit=form['unit'],
        manufacturer=form['manufacturer'], approval_no=form['approval_no'],
        is_rx=form.get('is_rx') == '1', price=float(form['price']),
        stock=int(form['stock']), warning_stock=int(form['warning_stock']),
        store_name=form['store_name'], description=form['description'],
        usage_method=form['usage_method'], adverse_reaction=form['adverse_reaction'],
        storage_condition=form['storage_condition'], image_path=image_path
    )
    flash('药品更新成功', 'success')
    return redirect(url_for('medicines'))

@app.route('/medicine/delete/<int:mid>')
@login_required
@captcha_action_required
def delete_medicine(mid):
    result = db.delete_medicine(mid)
    if result == 'soft':
        flash('药品已停用（存在销售记录）', 'info')
    else:
        flash('药品已删除', 'success')
    next_url = request.args.get('next') or url_for('medicines')
    return redirect(next_url)

@app.route('/medicine/<int:mid>')
@login_required
def medicine_detail(mid):
    med = db.get_medicine_detail(mid)
    if request.args.get('json'):
        return jsonify(med)
    if not med:
        flash('药品不存在', 'danger')
        return redirect(url_for('medicines'))
    return render_template('medicine_detail.html', med=med)

# ---------- 价格审批请求 ----------
@app.route('/price_request/create', methods=['POST'])
@login_required
def create_price_request():
    form = request.form
    medicine_id = int(form['medicine_id'])
    new_price = float(form['new_price'])
    reason = form['reason']
    ok, msg = db.create_price_request(medicine_id, new_price, reason, session['user']['username'])
    flash(msg, 'success' if ok else 'danger')
    next_url = form.get('next') or request.referrer or url_for('medicines')
    return redirect(next_url)

# ---------- 销售记录 ----------
@app.route('/sales_orders')
@login_required
def sales_orders():
    page = request.args.get('page', 1, type=int)
    year = request.args.get('year', '').strip()
    month = request.args.get('month', '').strip()
    user = session['user']
    cashier = '' if user['role'] == '系统管理员' else user['username']
    store = '全部' if user['role'] == '系统管理员' else user['store_name']
    rows, total = db.get_sales_orders(page, app.config['PAGE_SIZE'], cashier, store, year, month)
    total_profit = db.get_sales_total_profit(cashier, store, year, month)
    return render_template('sales_orders.html',
                           orders=rows,
                           page=page,
                           total=total,
                           total_profit=total_profit,
                           selected_year=year,
                           selected_month=month)

# 药房管理员专用销售统计API
@app.route('/api/shopmanager/sales_stats')
@login_required
def api_shopmanager_sales_stats():
    user = session['user']
    if user['role'] != '药房管理员':
        return jsonify({'error': '权限不足'}), 403
    store_name = user['store_name']
    today = datetime.now().date()
    first_day = today.replace(day=1)
    next_month = (first_day.replace(day=28) + timedelta(days=4)).replace(day=1)
    last_day = next_month - timedelta(days=1)

    month_sales = db.query_one("""
        SELECT COALESCE(SUM(actual_amount), 0) AS total
        FROM sales_orders
        WHERE store_name = %s AND created_at BETWEEN %s AND %s
    """, (store_name, first_day, last_day))['total']

    month_cost = db.query_one("""
        SELECT COALESCE(SUM(si.quantity * m.purchase_price), 0) AS cost
        FROM sales_orders so
        JOIN sales_items si ON so.id = si.order_id
        JOIN medicines m ON si.medicine_id = m.id
        WHERE so.store_name = %s AND so.created_at BETWEEN %s AND %s
    """, (store_name, first_day, last_day))['cost']

    month_profit = month_sales - month_cost
    month_orders = db.query_one("""
        SELECT COUNT(*) AS cnt
        FROM sales_orders
        WHERE store_name = %s AND created_at BETWEEN %s AND %s
    """, (store_name, first_day, last_day))['cnt']

    category_sales = db.query_all("""
        SELECT c.name AS category, COALESCE(SUM(si.amount), 0) AS amount
        FROM sales_orders so
        JOIN sales_items si ON so.id = si.order_id
        JOIN medicines m ON si.medicine_id = m.id
        LEFT JOIN categories c ON m.category_id = c.id
        WHERE so.store_name = %s AND so.created_at BETWEEN %s AND %s
        GROUP BY c.name
        ORDER BY amount DESC
    """, (store_name, first_day, last_day))

    days = request.args.get('days', 7, type=int)
    start_date = today - timedelta(days=days - 1)
    date_list = []
    current = start_date
    while current <= today:
        date_list.append(current)
        current += timedelta(days=1)

    rows = db.query_all("""
        SELECT 
            created_at::date as sale_date,
            COALESCE(SUM(actual_amount), 0) AS amount,
            COALESCE((
                SELECT SUM(si2.quantity * m2.purchase_price)
                FROM sales_items si2
                JOIN medicines m2 ON si2.medicine_id = m2.id
                WHERE si2.order_id = so.id
            ), 0) AS cost
        FROM sales_orders so
        WHERE so.store_name = %s AND so.created_at >= %s
        GROUP BY created_at::date, so.id
    """, (store_name, start_date))

    amount_map = {}
    profit_map = {}
    for row in rows:
        d = row['sale_date']
        amount_map[d] = amount_map.get(d, 0.0) + float(row['amount'])
        profit_map[d] = profit_map.get(d, 0.0) + (float(row['amount']) - float(row['cost']))

    daily_sales = [{'date': d.strftime('%Y-%m-%d'), 'amount': amount_map.get(d, 0.0)} for d in date_list]
    daily_profit = [{'date': d.strftime('%Y-%m-%d'), 'profit': profit_map.get(d, 0.0)} for d in date_list]

    payment_dist = db.query_all("""
        SELECT payment_method, COALESCE(SUM(actual_amount), 0) AS amount
        FROM sales_orders
        WHERE store_name = %s AND created_at BETWEEN %s AND %s
        GROUP BY payment_method
        ORDER BY amount DESC
    """, (store_name, first_day, last_day))

    top_medicines = db.query_all("""
        SELECT m.name, COALESCE(SUM(si.amount), 0) AS amount
        FROM sales_orders so
        JOIN sales_items si ON so.id = si.order_id
        JOIN medicines m ON si.medicine_id = m.id
        WHERE so.store_name = %s AND so.created_at BETWEEN %s AND %s
        GROUP BY m.name
        ORDER BY amount DESC
        LIMIT 5
    """, (store_name, first_day, last_day))

    recent_orders = db.query_all("""
        SELECT 
            so.order_no, 
            so.actual_amount, 
            so.payment_method, 
            so.cashier,
            TO_CHAR(so.created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at,
            COALESCE(SUM(si.quantity * m.purchase_price), 0) AS cost,
            so.actual_amount - COALESCE(SUM(si.quantity * m.purchase_price), 0) AS profit
        FROM sales_orders so
        JOIN sales_items si ON so.id = si.order_id
        JOIN medicines m ON si.medicine_id = m.id
        WHERE so.store_name = %s
        GROUP BY so.order_no, so.actual_amount, so.payment_method, so.cashier, so.created_at
        ORDER BY so.created_at DESC
        LIMIT 10
    """, (store_name,))

    user_info = db.query_one("SELECT last_login FROM users WHERE username = %s", (user['username'],))
    last_login = user_info['last_login'] if user_info and user_info['last_login'] else None

    return jsonify({
        'month_sales': float(month_sales),
        'month_profit': float(month_profit),
        'month_orders': month_orders,
        'category_sales': [{'name': r['category'] or '未分类', 'value': float(r['amount'])} for r in category_sales],
        'daily_sales': daily_sales,
        'daily_profit': daily_profit,
        'payment_dist': [{'name': r['payment_method'] or '未知', 'value': float(r['amount'])} for r in payment_dist],
        'top_medicines': [{'name': r['name'], 'value': float(r['amount'])} for r in top_medicines],
        'recent_orders': recent_orders,
        'last_login': last_login.strftime('%Y-%m-%d %H:%M:%S') if last_login else '首次登录'
    })

@app.route('/api/shopmanager/salesman_stats')
@login_required
def api_salesman_stats():
    user = session['user']
    if user['role'] != '药房管理员':
        return jsonify({'error': '权限不足'}), 403
    store_name = user['store_name']
    salesman = request.args.get('salesman', '')
    salesmen = db.query_all("""
        SELECT username, real_name FROM users
        WHERE store_name = %s AND role = '销售员' AND is_active = TRUE
    """, (store_name,))
    if not salesman and salesmen:
        salesman = salesmen[0]['username']
    today = datetime.now().date()
    first_day = today.replace(day=1)
    next_month = (first_day.replace(day=28) + timedelta(days=4)).replace(day=1)
    last_day = next_month - timedelta(days=1)

    # 本月统计（销售额、订单数）
    month_stats = db.query_one("""
        SELECT 
            COALESCE(SUM(actual_amount), 0) AS total_amount,
            COUNT(*) AS order_count
        FROM sales_orders
        WHERE cashier = %s AND created_at BETWEEN %s AND %s
    """, (salesman, first_day, last_day))

    # 本月每日销售额和利润（连续日期）
    date_list = []
    current = first_day
    while current <= last_day:
        date_list.append(current)
        current += timedelta(days=1)

    # 查询每日销售额和成本（明确使用表别名，避免歧义）
    rows = db.query_all("""
        SELECT 
            so.created_at::date as sale_date,
            COALESCE(SUM(so.actual_amount), 0) AS amount,
            COALESCE(SUM(si.quantity * m.purchase_price), 0) AS cost
        FROM sales_orders so
        LEFT JOIN sales_items si ON so.id = si.order_id
        LEFT JOIN medicines m ON si.medicine_id = m.id
        WHERE so.cashier = %s AND so.created_at >= %s AND so.created_at <= %s
        GROUP BY so.created_at::date
    """, (salesman, first_day, last_day))

    amount_map = {row['sale_date']: float(row['amount']) for row in rows}
    profit_map = {row['sale_date']: float(row['amount']) - float(row['cost']) for row in rows}

    daily_sales = [{'date': d.strftime('%Y-%m-%d'), 'amount': amount_map.get(d, 0.0)} for d in date_list]
    daily_profit = [{'date': d.strftime('%Y-%m-%d'), 'profit': profit_map.get(d, 0.0)} for d in date_list]

    # 本店排名（按本月销售额）
    ranking = db.query_all("""
        SELECT cashier, SUM(actual_amount) AS total
        FROM sales_orders
        WHERE store_name = %s AND created_at BETWEEN %s AND %s
        GROUP BY cashier
        ORDER BY total DESC
    """, (store_name, first_day, last_day))
    rank = next((i+1 for i, r in enumerate(ranking) if r['cashier'] == salesman), None)

    # 最近交易记录（增加利润列）
    recent_orders = db.query_all("""
        SELECT 
            so.order_no, 
            so.actual_amount, 
            so.payment_method, 
            so.created_at,
            COALESCE((
                SELECT SUM(si.quantity * m.purchase_price)
                FROM sales_items si
                JOIN medicines m ON si.medicine_id = m.id
                WHERE si.order_id = so.id
            ), 0) AS cost,
            (so.actual_amount - COALESCE((
                SELECT SUM(si.quantity * m.purchase_price)
                FROM sales_items si
                JOIN medicines m ON si.medicine_id = m.id
                WHERE si.order_id = so.id
            ), 0)) AS profit
        FROM sales_orders so
        WHERE so.cashier = %s
        ORDER BY so.created_at DESC
        LIMIT 10
    """, (salesman,))

    # 格式化时间
    for o in recent_orders:
        o['created_at'] = o['created_at'].strftime('%Y-%m-%d %H:%M:%S') if o['created_at'] else ''

    return jsonify({
        'salesmen': [{'username': s['username'], 'real_name': s['real_name']} for s in salesmen],
        'selected': salesman,
        'month_amount': float(month_stats['total_amount']),
        'month_orders': month_stats['order_count'],
        'rank': rank,
        'daily_sales': daily_sales,
        'daily_profit': daily_profit,   # 利润趋势数据
        'recent_orders': recent_orders
    })

# ---------- 库存预警 ----------
@app.route('/inventory_warning')
@login_required
@role_required('药房管理员', '系统管理员')
def inventory_warning():
    user = session['user']
    if user['role'] == '药房管理员':
        store = user['store_name']
    else:
        store = request.args.get('store', '全部')
    low_rows, exp_rows = db.get_inventory_warnings(store)
    stores = db.get_store_names()
    return render_template('inventory_warning.html', low_rows=low_rows,
                           exp_rows=exp_rows, store=store, stores=stores)

# ---------- 出入库管理 ----------
@app.route('/stock_io')
@login_required
@role_required('药房管理员', '系统管理员')
def stock_io():
    user = session['user']
    store_name = user['store_name'] if user['role'] == '药房管理员' else '全部'
    logs = db.get_inventory_logs(store_name)
    suppliers = db.get_suppliers()
    stores = db.get_store_names()
    total = len(logs)   # 添加这行
    return render_template('stock_io.html', logs=logs, suppliers=suppliers, stores=stores, total=total)

@app.route('/stock_in', methods=['POST'])
@login_required
@role_required('药房管理员', '系统管理员')
def stock_in():
    form = request.form
    items = [{
        'medicine_id': int(form['medicine_id']),
        'batch_no': form['batch_no'],
        'quantity': int(form['quantity']),
        'purchase_price': float(form['purchase_price']),
        'production_date': form['production_date'],
        'expiry_date': form['expiry_date']
    }]
    ok, msg = db.create_stock_in_order(
        int(form['supplier_id']), form['store_name'],
        session['user']['username'], items
    )
    if ok:
        flash(f'入库成功，单号：{msg}', 'success')
    else:
        flash(f'入库失败：{msg}', 'danger')
        # 修改下一行：根据用户角色重定向到相应页面
    if session['user']['role'] == '药房管理员':
        return redirect(url_for('shopmanager_stock_io'))
    else:
        return redirect(url_for('stock_io'))

@app.route('/stock_out', methods=['POST'])
@login_required
@role_required('药房管理员', '系统管理员')
def stock_out():
    form = request.form
    ok, msg = db.create_stock_out_order(
        int(form['medicine_id']), int(form['quantity']), form['out_type'],
        form['remark'], session['user']['username'], session['user']['store_name']
    )
    if ok:
        flash(f'出库成功，单号：{msg}', 'success')
    else:
        flash(f'出库失败：{msg}', 'danger')
    # 根据用户角色重定向到对应的页面
    user = session['user']
    if user['role'] == '药房管理员':
        return redirect(url_for('shopmanager_stock_io'))
    else:
        return redirect(url_for('stock_io'))

# ---------- 调拨管理 ----------
@app.route('/transfer')
@login_required
@role_required('系统管理员', '药房管理员')
def transfer():
    status = request.args.get('status', '全部')
    orders = db.get_transfer_orders(status)
    stores = db.get_store_names()
    return render_template('transfer.html', orders=orders, status=status, stores=stores)

@app.route('/transfer/create', methods=['POST'])
@login_required
@role_required('药房管理员')
def create_transfer():
    form = request.form
    ok, msg = db.create_transfer_order(
        int(form['medicine_id']), int(form['quantity']),
        form['from_store'], form['to_store'],
        session['user']['username'], form.get('remark', '')
    )
    if ok:
        flash(f'调拨申请已提交，单号：{msg}', 'success')
    else:
        flash(f'提交失败：{msg}', 'danger')
    return redirect(url_for('transfer'))

@app.route('/transfer/approve/<int:oid>')
@login_required
@role_required('系统管理员')
def approve_transfer(oid):
    passed = request.args.get('passed', '1') == '1'
    remark = request.args.get('remark', '')
    ok, msg = db.approve_transfer_order(oid, session['user']['username'], passed, remark)
    if ok:
        flash(msg, 'success')
    else:
        flash(msg, 'danger')
    return redirect(url_for('transfer'))

# ---------- 价格审批 ----------
@app.route('/price_requests')
@login_required
def price_requests():
    status = request.args.get('status', '全部')
    reqs = db.get_price_requests(status)
    return render_template('price_requests.html', reqs=reqs, status=status)

@app.route('/price_request/approve/<int:rid>')
@login_required
@role_required('系统管理员')
def approve_price_request(rid):
    passed = request.args.get('passed', '1') == '1'
    remark = request.args.get('remark', '')
    ok, msg = db.approve_price_request(rid, session['user']['username'], passed, remark)
    flash(msg, 'success' if ok else 'danger')
    return redirect(url_for('price_requests'))

# ---------- 基础资料 ----------
@app.route('/categories_suppliers')
@login_required
@role_required('药房管理员', '系统管理员')
def categories_suppliers():
    categories = db.get_categories()
    suppliers = db.get_suppliers()
    return render_template('categories_suppliers.html', categories=categories, suppliers=suppliers)

@app.route('/category/add', methods=['POST'])
@login_required
def add_category():
    db.add_category(request.form['name'], request.form.get('description', ''))
    flash('分类添加成功', 'success')
    return redirect(url_for('categories_suppliers'))

@app.route('/supplier/add', methods=['POST'])
@login_required
def add_supplier():
    form = request.form
    db.add_supplier(form['name'], form['contact_person'], form['phone'],
                    form['address'], int(form.get('rating', 5)), True)
    flash('供应商添加成功', 'success')
    return redirect(url_for('categories_suppliers'))

# ---------- 药品建议 ----------
@app.route('/suggestions')
@login_required
def suggestions():
    status = request.args.get('status', '全部')
    rows = db.get_suggestions(session['user']['role'], session['user']['username'], status)
    return render_template('suggestions.html', suggestions=rows, status=status)

@app.route('/suggestion/submit', methods=['POST'])
@login_required
def submit_suggestion():
    form = request.form
    db.submit_suggestion(
        medicine_name=form['medicine_name'], medicine_type=form['medicine_type'],
        suggest_qty=int(form['suggest_qty']), estimate_price=float(form['estimate_price']),
        reason=form['reason'], supplier_suggestion=form.get('supplier_suggestion', ''),
        submitter=session['user']['username'], store_name=session['user']['store_name']
    )
    flash('建议已提交', 'success')
    return redirect(url_for('suggestions'))

@app.route('/suggestion/approve/<int:sid>')
@login_required
@role_required('系统管理员')
def approve_suggestion(sid):
    passed = request.args.get('passed', '1') == '1'
    reply = request.args.get('reply', '')
    ok, msg = db.approve_suggestion(sid, session['user']['username'], passed, reply)
    flash(msg, 'success' if ok else 'danger')
    return redirect(url_for('suggestions'))

# ---------- 销售开单 ----------
@app.route('/sale')
@login_required
@role_required('销售员', '药房管理员')
def sale():
    user = session['user']
    filters = {
        'keyword': request.args.get('keyword', ''),
        'store_name': user['store_name'],
        'manufacturer': request.args.get('manufacturer', ''),
        'category_id': request.args.get('category_id', ''),
        'stock_status': '有库存',
        'is_rx': request.args.get('is_rx', '')
    }
    rows, _ = db.search_medicines(filters, 1, 100)
    categories = db.get_categories()
    return render_template('sale.html', medicines=rows, categories=categories, filters=filters)

@app.route('/sale/checkout', methods=['POST'])
@login_required
def checkout():
    try:
        if not request.is_json:
            return jsonify({"success": False, "message": "请使用JSON格式提交数据"}), 400
        data = request.get_json()
        items = data.get('items', [])
        payment_method = data.get('payment_method', '现金')
        if not items:
            return jsonify({"success": False, "message": "购物车为空"}), 400
        converted_items = []
        for item in items:
            converted_items.append({
                "medicine_id": item["id"],
                "quantity": item["quantity"]
            })
        ok, result = db.create_sale_order(
            items=converted_items,
            cashier=session['user']['username'],
            store_name=session['user']['store_name'],
            payment_method=payment_method
        )
        if ok:
            return jsonify({"success": True, "order_id": result})
        else:
            return jsonify({"success": False, "message": result}), 400
    except Exception as e:
        print(f"结算接口崩溃: {str(e)}")
        return jsonify({"success": False, "message": f"服务器错误: {str(e)}"}), 500

# ---------- 退货 ----------
@app.route('/returns')
@login_required
def returns():
    rows = db.get_return_orders()
    user = session['user']
    if user['role'] == '销售员':
        rows = [r for r in rows if r['store_name'] == user['store_name']]
    elif user['role'] == '药房管理员':
        rows = [r for r in rows if r['store_name'] == user['store_name']]
    return render_template('returns.html', returns=rows)

@app.route('/api/sale_order/<order_no>')
@login_required
def get_sale_order_detail(order_no):
    try:
        user = session['user']
        order = db.query_one("""
            SELECT id, order_no, total_amount, actual_amount, payment_method,
                   payment_status, cashier, store_name, created_at
            FROM sales_orders
            WHERE order_no = %s
        """, (order_no,))
        if not order:
            return jsonify({"success": False, "message": "订单不存在"}), 404
        if user['role'] == '销售员' and order['store_name'] != user['store_name']:
            return jsonify({"success": False, "message": "只能查看本门店的订单"}), 403
        items = db.get_sale_order_items(order_no)
        total_profit = 0
        items_with_profit = []
        for item in items:
            med = db.query_one("SELECT purchase_price FROM medicines WHERE id = %s", (item['medicine_id'],))
            purchase_price = float(med['purchase_price']) if med else 0
            profit = float(item['amount']) - purchase_price * int(item['sold_quantity'])
            total_profit += profit
            item_dict = dict(item)
            item_dict['profit'] = round(profit, 2)
            items_with_profit.append(item_dict)
        order_dict = dict(order)
        order_dict['profit'] = round(total_profit, 2)
        return jsonify({
            "success": True,
            "order": order_dict,
            "items": items_with_profit
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/return_order_detail/<return_no>')
@login_required
def api_return_order_detail(return_no):
    try:
        detail = db.get_return_order_detail(return_no)
        if not detail:
            return jsonify({"success": False, "message": "退货订单不存在"}), 404
        return jsonify({
            "success": True,
            "return_order": detail['return_order'],
            "items": detail['items']
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/return/create', methods=['POST'])
@login_required
def create_return():
    try:
        if request.is_json:
            data = request.get_json()
            sale_order_no = data.get('sale_order_no', '').strip()
            items = data.get('items', [])
            reason = data.get('reason', '').strip()
            if not sale_order_no:
                return jsonify({"success": False, "message": "请输入原销售单号"}), 400
            if not items or len(items) == 0:
                return jsonify({"success": False, "message": "请选择要退货的药品"}), 400
            user = session['user']
            if user['role'] == '销售员':
                sale_order = db.query_one(
                    "SELECT store_name FROM sales_orders WHERE order_no = %s",
                    (sale_order_no,)
                )
                if not sale_order:
                    return jsonify({"success": False, "message": "原销售订单不存在"}), 400
                if sale_order['store_name'] != user['store_name']:
                    return jsonify({"success": False, "message": "只能对本门店的订单进行退货"}), 400
            ok, msg = db.create_return_order(
                sale_order_no, items, reason,
                session['user']['username'], session['user']['store_name']
            )
            if ok:
                return jsonify({"success": True, "message": f"退货成功，单号：{msg}", "return_no": msg})
            else:
                return jsonify({"success": False, "message": msg}), 400
        else:
            form = request.form
            items = [{
                'medicine_id': int(form['medicine_id']),
                'quantity': int(form['quantity'])
            }]
            ok, msg = db.create_return_order(
                form['sale_order_no'], items, form['reason'],
                session['user']['username'], session['user']['store_name']
            )
            if ok:
                flash(f'退货成功，单号：{msg}', 'success')
            else:
                flash(f'退货失败：{msg}', 'danger')
            return redirect(url_for('returns'))
    except Exception as e:
        import traceback
        traceback.print_exc()
        if request.is_json:
            return jsonify({"success": False, "message": f"服务器错误: {str(e)}"}), 500
        else:
            flash(f'服务器错误：{str(e)}', 'danger')
            return redirect(url_for('returns'))

# ---------- 审计日志 ----------
@app.route('/logs')
@login_required
@role_required('系统管理员')
def logs():
    page = request.args.get('page', 1, type=int)
    keyword = request.args.get('keyword', '')
    rows, total = db.get_logs(page, app.config['PAGE_SIZE'], keyword)
    return render_template('logs.html', logs=rows, page=page, total=total, keyword=keyword)

# ---------- 安全看板 ----------
@app.route('/security_dashboard')
@login_required
@role_required('系统管理员')
def security_dashboard():
    return render_template('security_dashboard.html')

@app.route('/api/security_data')
@login_required
@role_required('系统管理员')
def security_data():
    days = request.args.get('days', 7, type=int)
    overview = db.get_security_overview()
    trend = db.get_login_trend(days)
    ips = db.get_suspicious_ips(days)
    events, _ = db.get_security_events(1, 30)
    distribution = db.get_action_distribution(days)
    return jsonify({
        'overview': overview,
        'trend': trend,
        'suspicious_ips': [dict(r) for r in ips],
        'events': [dict(r) for r in events],
        'distribution': [dict(r) for r in distribution],
    })

# ---------- 导出 ----------
@app.route('/export/medicines')
@login_required
def export_medicines():
    filters = {k: request.args.get(k, '') for k in ['keyword', 'store_name', 'manufacturer', 'category_id']}
    rows, _ = db.search_medicines(filters, 1, 10000)
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', '编码', '名称', '通用名', '分类', '规格', '单位', '厂家', '处方', '价格', '库存', '预警库存', '门店'])
    for r in rows:
        cw.writerow([r['id'], r['code'], r['name'], r['generic_name'], r['category_name'],
                     r['spec'], r['unit'], r['manufacturer'], '是' if r['is_rx'] else '否',
                     r['price'], r['stock'], r['warning_stock'], r['store_name']])
    output = si.getvalue().encode('utf-8-sig')
    return send_file(io.BytesIO(output), mimetype='text/csv', as_attachment=True, download_name='medicines.csv')

# ==================== 药房管理员专用页面 ====================
@app.route('/shopmanager_dashboard')
@login_required
def shopmanager_dashboard():
    return render_template('shopmanager_dashboard.html')

@app.route('/shopmanager/medicines_fixed')
@login_required
def shopmanager_medicines_fixed():
    user = session['user']
    if user['role'] != '药房管理员':
        return redirect(url_for('dashboard'))
    keyword = request.args.get('keyword', '')
    category_id = request.args.get('category_id', '')
    page = request.args.get('page', 1, type=int)
    page_size = 15
    filters = {
        'keyword': keyword,
        'store_name': user['store_name'],
        'category_id': category_id,
    }
    medicines, total = db.search_medicines(filters, page, page_size)
    categories = db.get_categories()
    return render_template('shopmanager_medicines_fixed.html',
                           medicines=medicines,
                           categories=categories,
                           total=total,
                           page=page,
                           page_size=page_size,
                           keyword=keyword,
                           category_id=category_id)

@app.route('/shopmanager/sales_records')
@login_required
def shopmanager_sales_records():
    user = session['user']
    if user['role'] != '药房管理员':
        return redirect(url_for('dashboard'))
    store_name = user['store_name']
    salesmen = db.query_all(
        "SELECT username, real_name FROM users WHERE store_name=%s AND role='销售员' AND is_active=TRUE",
        (store_name,)
    )
    selected = request.args.get('salesman', salesmen[0]['username'] if salesmen else '')
    return_records = db.get_return_orders_by_store(store_name)
    return render_template('shopmanager_sales_records.html',
                           salesmen=salesmen,
                           selected=selected,
                           return_records=return_records)

@app.route('/shopmanager/inventory_warning')
@login_required
def shopmanager_inventory_warning():
    user = session['user']
    if user['role'] != '药房管理员':
        return redirect(url_for('dashboard'))
    low_rows, exp_rows = db.get_inventory_warnings(user['store_name'])
    return render_template('shopmanager_inventory_warning.html',
                           low_rows=low_rows,
                           exp_rows=exp_rows)

@app.route('/shopmanager/stock_io')
@login_required
def shopmanager_stock_io():
    user = session['user']
    if user['role'] != '药房管理员':
        return redirect(url_for('dashboard'))
    logs = db.get_inventory_logs(user['store_name'])
    suppliers = db.get_suppliers()
    medicines, _ = db.search_medicines({'store_name': user['store_name']}, 1, 10000)
    return render_template('shopmanager_stock_io.html',
                           logs=logs,
                           suppliers=suppliers,
                           medicines=medicines)

# ---------- 直接调价 API ----------
@app.route('/api/medicine/update_price_direct', methods=['POST'])
@login_required
@role_required('药房管理员', '系统管理员')
def update_medicine_price_direct():
    medicine_id = request.form.get('medicine_id')
    new_price = request.form.get('new_price')
    next_url = request.form.get('next') or url_for('shopmanager_medicines_fixed')
    if not medicine_id or not new_price:
        flash('参数不全', 'danger')
        return redirect(next_url)
    try:
        new_price = float(new_price)
    except:
        flash('价格格式错误', 'danger')
        return redirect(next_url)

    user = session['user']
    med = db.query_one("SELECT id, store_name FROM medicines WHERE id=%s", (medicine_id,))
    if not med:
        flash('药品不存在', 'danger')
        return redirect(next_url)
    if user['role'] == '药房管理员' and med['store_name'] != user['store_name']:
        flash('无权限修改其他门店药品', 'danger')
        return redirect(next_url)

    db.execute("UPDATE medicines SET price=%s, updated_at=CURRENT_TIMESTAMP WHERE id=%s", (new_price, medicine_id))
    db.write_log(user['username'], '直接调价', f"药品ID={medicine_id}, 新价格={new_price}")
    flash('价格修改成功', 'success')
    return redirect(next_url)

# ==================== 销售员专用页面和API ====================

@app.route('/staff')
@login_required
def staff_page():
    user = session['user']
    if user['role'] != '销售员':
        return redirect(url_for('dashboard'))
    return render_template('staff.html', user=user)

@app.route('/api/drugs')
@login_required
def api_drugs():
    user = session['user']
    if user['role'] != '销售员':
        return jsonify({'code': 403, 'msg': '权限不足'})
    keyword = request.args.get('keyword', '').strip()
    like = f'%{keyword}%'
    sql = """
        SELECT id, code AS drug_code, name AS drug_name, manufacturer, price, stock, is_rx AS is_prescription
        FROM medicines
        WHERE (name ILIKE %s OR code ILIKE %s OR manufacturer ILIKE %s)
          AND is_active = TRUE
          AND store_name = %s
        ORDER BY id
    """
    rows = db.query_all(sql, (like, like, like, user['store_name']))
    return jsonify({'code': 200, 'data': rows})

@app.route('/api/checkout', methods=['POST'])
@login_required
def api_checkout():
    user = session['user']
    if user['role'] != '销售员':
        return jsonify({'code': 403, 'msg': '权限不足'})
    data = request.get_json()
    cart_items = data.get('cart_items', [])
    payment_method = data.get('payment_method', '现金')
    if not cart_items:
        return jsonify({'code': 400, 'msg': '购物车为空'})
    # 转换格式以复用现有的 create_sale_order
    items = [{'medicine_id': item['drug_id'], 'quantity': item['quantity']} for item in cart_items]
    ok, result = db.create_sale_order(items, user['username'], user['store_name'], payment_method)
    if ok:
        total = sum(item['price'] * item['quantity'] for item in cart_items)
        return jsonify({
            'code': 200,
            'msg': '结算成功',
            'sale_no': result,
            'payment_no': 'PAY' + datetime.now().strftime('%Y%m%d%H%M%S'),
            'total': total,
            'payment_method': payment_method,
            'payment_status': '成功'
        })
    else:
        return jsonify({'code': 500, 'msg': result})

@app.route('/api/sales')
@login_required
def api_sales():
    user = session['user']
    if user['role'] != '销售员':
        return jsonify({'code': 403, 'msg': '权限不足'})
    rows = db.get_sales_by_staff(user['username'])
    return jsonify({'code': 200, 'data': rows})

@app.route('/api/suggestions/add', methods=['POST'])
@login_required
def api_add_suggestion():
    user = session['user']
    if user['role'] != '销售员':
        return jsonify({'code': 403, 'msg': '权限不足'})
    data = request.get_json()
    ok, msg = db.add_suggestion(
        drug_name=data.get('drug_name', ''),
        drug_type=data.get('drug_type', ''),
        quantity=data.get('quantity', 0),
        estimated_price=data.get('estimated_price', 0),
        reason=data.get('reason', ''),
        supplier_suggestion=data.get('supplier_suggestion', ''),
        submitter=user['username'],
        store_name=user['store_name']
    )
    if ok:
        return jsonify({'code': 200, 'msg': '提交成功'})
    else:
        return jsonify({'code': 500, 'msg': msg})

@app.route('/api/suggestions')
@login_required
def api_get_suggestions():
    user = session['user']
    if user['role'] != '销售员':
        return jsonify({'code': 403, 'msg': '权限不足'})
    rows = db.get_suggestions_by_staff(user['username'])
    return jsonify({'code': 200, 'data': rows})

@app.route('/api/medicines/search')
@login_required
def api_medicines_search():
    """药品模糊搜索接口（用于入库时选择药品）"""
    keyword = request.args.get('keyword', '').strip()
    store_name = session['user']['store_name']
    sql = """
        SELECT id, code, name, manufacturer, price, stock, purchase_price
        FROM medicines
        WHERE (name ILIKE %s OR code ILIKE %s OR manufacturer ILIKE %s)
          AND store_name = %s
          AND is_active = TRUE
        ORDER BY name
        LIMIT 50
    """
    like = f'%{keyword}%'
    rows = db.query_all(sql, (like, like, like, store_name))
    return jsonify(rows)

if __name__ == '__main__':
    # 生产环境务必设置环境变量 FLASK_DEBUG=false
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)

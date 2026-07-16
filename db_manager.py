import psycopg2
import psycopg2.extras
import json
import uuid
import time
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib

import os

DB_CONFIG = {
    "host": os.environ.get('DB_HOST', 'localhost'),
    "port": int(os.environ.get('DB_PORT', 15432)),
    "user": os.environ.get('DB_USER', 'druguser'),
    "password": os.environ.get('DB_PASSWORD'),  # ← 不设默认值！
    "dbname": os.environ.get('DB_NAME', 'drugstore'),
}

# 同样加上检查
if not DB_CONFIG["password"]:
    raise ValueError("❌ 环境变量 DB_PASSWORD 未设置！")

# SSL 连接配置开关（由 app.py 在启动时设置）
SSL_ENABLED = False
SSL_CONFIG = {
    "sslmode": "require",
    "sslcert": None,
    "sslkey": None,
    "sslrootcert": None,
}

import sys
safe_config = {**DB_CONFIG, "password": "******"}
print("=== DB_CONFIG LOADED ===", safe_config, file=sys.stderr)
# 请求上下文（由 app.py 的 before_request 设置）
_request_context = {}

def set_request_context(ip_address=None, user_agent=None):
    _request_context['ip_address'] = ip_address
    _request_context['user_agent'] = user_agent

def get_conn():
    """获取数据库连接（支持 SSL）"""
    config = DB_CONFIG.copy()
    if SSL_ENABLED:
        config.update({
            k: v for k, v in SSL_CONFIG.items() if v is not None
        })
    return psycopg2.connect(**config)

def query_all(sql, params=None):
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params or ())
        rows = cur.fetchall()
        cur.close()
        return rows
    finally:
        conn.close()

def query_one(sql, params=None):
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params or ())
        row = cur.fetchone()
        cur.close()
        return row
    finally:
        conn.close()

def execute(sql, params=None):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(sql, params or ())
        conn.commit()
        cur.close()
    finally:
        conn.close()

def execute_insert(sql, params=None):
    """执行 INSERT 并返回自增主键 ID"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(sql, params or ())
        row_id = cur.fetchone()[0]  # 必须在 commit 前获取
        conn.commit()
        cur.close()
        return row_id
    finally:
        conn.close()

def write_log(username, action, detail, ip_address=None, user_agent=None,
              table_name=None, record_id=None, old_value=None, new_value=None):
    ip = ip_address or _request_context.get('ip_address')
    ua = user_agent or _request_context.get('user_agent')
    execute("""
        INSERT INTO audit_logs (username, action, detail, ip_address, user_agent, table_name, record_id, old_value, new_value)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
     """, (username, action, detail, ip, ua, table_name, record_id,
          json.dumps(old_value, ensure_ascii=False, default=str) if old_value else None,
          json.dumps(new_value, ensure_ascii=False, default=str) if new_value else None))

# ==================== 数据加密 ====================

def _get_encryption_key(key_name='master_key'):
    """从 encryption_keys 表获取密钥并派生为 256 位"""
    row = query_one(
        "SELECT key_value FROM encryption_keys WHERE key_name=%s",
        (key_name,)
    )
    if not row:
        raise ValueError(f"加密密钥 '{key_name}' 未找到")
    # 使用 SHA-256 将任意长度密钥派生为 32 字节
    return hashlib.sha256(row['key_value'].encode()).digest()

def aes_encrypt_field(plaintext, key_name='master_key'):
    """使用 AES-256-CBC 加密敏感字段（Python 端实现，无需 pgcrypto）
    返回格式: 'iv_hex:ciphertext_hex'
    """
    if not plaintext:
        return None
    try:
        key = _get_encryption_key(key_name)
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv.hex() + ':' + ciphertext.hex()
    except Exception as e:
        print(f"[加密错误] {e}", file=__import__('sys').stderr)
        return None

def aes_decrypt_field(ciphertext_with_iv, key_name='master_key'):
    """解密被 aes_encrypt_field 加密的数据（Python 端实现）"""
    if not ciphertext_with_iv:
        return None
    try:
        key = _get_encryption_key(key_name)
        parts = ciphertext_with_iv.split(':')
        if len(parts) != 2:
            return None
        iv = bytes.fromhex(parts[0])
        ciphertext = bytes.fromhex(parts[1])
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext.decode()
    except Exception as e:
        print(f"[解密错误] {e}", file=__import__('sys').stderr)
        return None

def configure_ssl(enable=True, cert_dir=None):
    """配置数据库 SSL 连接
    Args:
        enable: 是否启用 SSL
        cert_dir: 证书目录路径，包含 ca.crt, client.crt, client.key
    """
    global SSL_ENABLED, SSL_CONFIG
    SSL_ENABLED = enable
    if enable and cert_dir:
        import os
        ca_path = os.path.join(cert_dir, 'ca.crt')
        cert_path = os.path.join(cert_dir, 'client.crt')
        key_path = os.path.join(cert_dir, 'client.key')
        if os.path.exists(ca_path):
            SSL_CONFIG['sslrootcert'] = ca_path
        if os.path.exists(cert_path):
            SSL_CONFIG['sslcert'] = cert_path
        if os.path.exists(key_path):
            SSL_CONFIG['sslkey'] = key_path

# ==================== 会话管理 ====================

def create_user_session(username, session_token, ip_address=None, user_agent=None):
    """创建或更新用户会话（踢掉旧会话）"""
    execute("DELETE FROM user_sessions WHERE username = %s", (username,))
    execute("""
        INSERT INTO user_sessions (username, session_token, ip_address, user_agent)
        VALUES (%s, %s, %s, %s)
    """, (username, session_token, ip_address, user_agent))

def validate_user_session(username, session_token):
    """验证会话令牌是否有效（是否已被新登录踢下线）"""
    row = query_one("SELECT session_token FROM user_sessions WHERE username = %s", (username,))
    return row is not None and row['session_token'] == session_token

def update_session_activity(username, session_token=None):
    """更新会话最后活跃时间"""
    if session_token:
        execute("UPDATE user_sessions SET last_activity = CURRENT_TIMESTAMP WHERE username = %s AND session_token = %s",
                (username, session_token))
    else:
        execute("UPDATE user_sessions SET last_activity = CURRENT_TIMESTAMP WHERE username = %s", (username,))

def remove_user_session(username):
    """用户登出时清除会话记录"""
    execute("DELETE FROM user_sessions WHERE username = %s", (username,))

def cleanup_expired_sessions(hours=48):
    """清理超过指定小时数的过期会话"""
    execute("DELETE FROM user_sessions WHERE last_activity < CURRENT_TIMESTAMP - INTERVAL '%s hours'", (hours,))

def login(username, password, role):
    import sys
    from datetime import datetime, timedelta
    user = query_one("""
        SELECT id, username, password, role, real_name, phone, store_name, is_active,
               login_attempts, locked_until
        FROM users WHERE username=%s AND role=%s
    """, (username, role))
    if not user:
        print(f"[LOGIN DEBUG] 未找到用户: username={username}, role={role}", file=sys.stderr)
        write_log(username, "登录失败", "用户不存在或角色不匹配")
        return None
    if not user['is_active']:
        print(f"[LOGIN DEBUG] 用户已禁用: username={username}", file=sys.stderr)
        write_log(username, "登录失败", "账户已禁用")
        return None

    # 检查账户是否被锁定
    if user['locked_until'] and user['locked_until'] > datetime.now():
        remaining = int((user['locked_until'] - datetime.now()).total_seconds())
        print(f"[LOGIN DEBUG] 账户已锁定: username={username}, 剩余{remaining}秒", file=sys.stderr)
        return {'locked': True, 'remaining': remaining}

    if check_password_hash(user['password'], password):
        # 登录成功：重置失败计数和锁定状态
        execute("UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = %s", (user['id'],))
        write_log(username, "登录成功", f"{role} 登录系统")
        return {
            'id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'real_name': user['real_name'],
            'phone': user['phone'],
            'store_name': user['store_name']
        }
    elif user['password'] == password:
        hashed = generate_password_hash(password)
        execute("UPDATE users SET password = %s, login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = %s", (hashed, user['id']))
        write_log(username, "登录成功（密码已升级）", f"{role} 登录系统")
        return {
            'id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'real_name': user['real_name'],
            'phone': user['phone'],
            'store_name': user['store_name']
        }

    # 登录失败：增加失败计数
    attempts = (user['login_attempts'] or 0) + 1
    if attempts >= 5:
        execute("UPDATE users SET login_attempts = %s, locked_until = %s WHERE id = %s",
                (attempts, datetime.now() + timedelta(minutes=5), user['id']))
        write_log(username, "账户锁定", f"连续{attempts}次登录失败，锁定5分钟")
    else:
        execute("UPDATE users SET login_attempts = %s WHERE id = %s", (attempts, user['id']))
    write_log(username, "登录失败", f"密码错误（第{attempts}次）")
    print(f"[LOGIN DEBUG] 密码不匹配: username={username}, attempts={attempts}", file=sys.stderr)
    return None

# ---------- 门店管理 ----------
def get_stores(page=1, page_size=10, keyword=""):
    where = ["1=1"]
    params = []
    if keyword.strip():
        # 只按门店名称和编号搜索，不再搜索 manager_name
        where.append("(pharmacy_name ILIKE %s OR pharmacy_code ILIKE %s)")
        kw = f"%{keyword.strip()}%"
        params.extend([kw, kw])
    where_sql = " AND ".join(where)
    total = query_one(f"SELECT COUNT(*) AS c FROM stores WHERE {where_sql}", tuple(params))["c"]
    offset = (page - 1) * page_size
    rows = query_all(f"""
        SELECT id, pharmacy_code, pharmacy_name, location,
               business_status, business_hours, created_at
        FROM stores WHERE {where_sql} ORDER BY id LIMIT %s OFFSET %s
    """, tuple(params + [page_size, offset]))
    return rows, total

def get_all_stores():
    return query_all("SELECT id, pharmacy_name FROM stores ORDER BY id")

def add_store(pharmacy_code, pharmacy_name, location, business_status, business_hours):
    # 检查药店编号是否已存在
    exists = query_one("SELECT id FROM stores WHERE pharmacy_code = %s", (pharmacy_code,))
    if exists:
        raise ValueError("药店编号已存在，请使用其他编号")
    # 检查药店名称是否已存在
    exists_name = query_one("SELECT id FROM stores WHERE pharmacy_name = %s", (pharmacy_name,))
    if exists_name:
        raise ValueError("药店名称已存在，请使用其他名称")
    new_id = execute_insert("""
        INSERT INTO stores (pharmacy_code, pharmacy_name, location, business_status, business_hours)
        VALUES (%s,%s,%s,%s,%s) RETURNING id
    """, (pharmacy_code, pharmacy_name, location, business_status, business_hours))
    write_log("admin", "新增门店", pharmacy_name,
              table_name='stores', record_id=new_id,
              new_value={'pharmacy_code': pharmacy_code, 'pharmacy_name': pharmacy_name,
                         'location': location})

def update_store(sid, pharmacy_code, pharmacy_name, location, business_status, business_hours):
    # 检查药店编号是否已被其他门店使用
    exists = query_one("SELECT id FROM stores WHERE pharmacy_code = %s AND id != %s", (pharmacy_code, sid))
    if exists:
        raise ValueError("药店编号已存在，请使用其他编号")
    # 检查药店名称是否已被其他门店使用
    exists_name = query_one("SELECT id FROM stores WHERE pharmacy_name = %s AND id != %s", (pharmacy_name, sid))
    if exists_name:
        raise ValueError("药店名称已存在，请使用其他名称")
    # 查询旧门店名称和修改前数据
    old = query_one("SELECT * FROM stores WHERE id = %s", (sid,))

    execute("""
        UPDATE stores SET pharmacy_code=%s, pharmacy_name=%s, location=%s,
            business_status=%s, business_hours=%s, updated_at=CURRENT_TIMESTAMP
        WHERE id=%s
    """, (pharmacy_code, pharmacy_name, location, business_status, business_hours, sid))
    write_log("admin", "修改门店", f"id={sid} {pharmacy_name}",
              table_name='stores', record_id=sid,
              old_value=dict(old) if old else None,
              new_value={'pharmacy_code': pharmacy_code, 'pharmacy_name': pharmacy_name,
                         'location': location, 'business_status': business_status})

    # 如果门店名称发生变化，处理旧门店的药房管理员绑定
    if old and old['pharmacy_name'] != pharmacy_name:
        execute("UPDATE users SET store_name = '' WHERE store_name = %s AND role = '药房管理员' AND is_active = TRUE",
                (old['pharmacy_name'],))

def delete_store(sid):
    store = query_one("SELECT * FROM stores WHERE id = %s", (sid,))
    execute("DELETE FROM stores WHERE id=%s", (sid,))
    write_log("admin", "删除门店", f"id={sid}",
              table_name='stores', record_id=sid,
              old_value=dict(store) if store else None)
    if store:
        execute("UPDATE users SET is_active = FALSE WHERE store_name = %s AND role = '药房管理员'", (store['pharmacy_name'],))
        write_log("system", "禁用药房管理员", f"门店 {store['pharmacy_name']} 对应的药房管理员已禁用")

# ---------- 用户管理（增强）----------
def get_users(page_num=1, page_size=20, keyword="", store_name_filter=""):
    where = ["1=1"]
    params = []
    if keyword.strip():
        where.append("(username ILIKE %s OR real_name ILIKE %s OR role ILIKE %s OR store_name ILIKE %s)")
        kw = f"%{keyword.strip()}%"
        params.extend([kw, kw, kw, kw])
    if store_name_filter:
        where.append("store_name = %s")
        params.append(store_name_filter)
    where_sql = " AND ".join(where)
    total = query_one(f"SELECT COUNT(*) AS c FROM users WHERE {where_sql}", tuple(params))["c"]
    offset = (page_num - 1) * page_size
    rows = query_all(f"""
        SELECT id, username, password, role, real_name, phone, store_name, is_active, NULL as created_at
        FROM users WHERE {where_sql} ORDER BY id LIMIT %s OFFSET %s
    """, tuple(params + [page_size, offset]))
    return rows, total

def check_store_manager_exists(store_name, exclude_uid=None):
    """检查指定门店是否已经存在活跃的药房管理员，返回用户记录或 None"""
    sql = "SELECT id, real_name FROM users WHERE store_name=%s AND role='药房管理员' AND is_active=TRUE"
    params = [store_name]
    if exclude_uid:
        sql += " AND id != %s"
        params.append(exclude_uid)
    return query_one(sql, params)

def validate_password_strength(password):
    """密码复杂度校验：至少8位，包含大写字母、小写字母、数字、特殊字符中的至少三类"""
    if len(password) < 8:
        raise ValueError("密码长度至少为8位")
    categories = 0
    if any(c.isupper() for c in password):
        categories += 1
    if any(c.islower() for c in password):
        categories += 1
    if any(c.isdigit() for c in password):
        categories += 1
    if any(not c.isalnum() for c in password):
        categories += 1
    if categories < 3:
        raise ValueError("密码需包含大写字母、小写字母、数字、特殊字符中的至少三类")

def add_user(username, password, role, real_name, phone, store_name):
    validate_password_strength(password)
    if role == '药房管理员' and not store_name:
        raise ValueError("药房管理员必须分配门店")
    if role == '药房管理员' and store_name:
        existing = check_store_manager_exists(store_name)
        if existing:
            raise ValueError("此门店已有店长")
    # 检查用户名是否已存在
    exists = query_one("SELECT id FROM users WHERE username = %s", (username,))
    if exists:
        raise ValueError("用户名已存在，请使用其他用户名")
    hashed = generate_password_hash(password)
    # 对手机号进行 AES 加密存储（若 pgcrypto 扩展可用）
    phone_enc = aes_encrypt_field(phone) if phone else None
    new_id = execute_insert("""
        INSERT INTO users (username, password, role, real_name, phone, phone_encrypted, store_name, is_active)
        VALUES (%s,%s,%s,%s,%s,%s,%s,TRUE) RETURNING id
    """, (username, hashed, role, real_name, phone, phone_enc, store_name))
    write_log("admin", "新增用户", f"{username}/{role}/{store_name}",
              table_name='users', record_id=new_id,
              new_value={'username': username, 'role': role, 'real_name': real_name,
                         'phone': phone, 'store_name': store_name})

def update_user(uid, username, password, role, real_name, phone, store_name, is_active):
    if role == '药房管理员' and not store_name:
        raise ValueError("药房管理员必须分配门店")
    if role == '药房管理员' and store_name:
        existing = check_store_manager_exists(store_name, exclude_uid=uid)
        if existing:
            raise ValueError("此门店已有店长")
    # 获取修改前数据
    before = query_one("SELECT username, role, real_name, phone, store_name, is_active FROM users WHERE id=%s", (uid,))
    # 对手机号加密（如 pgcrypto 可用）
    phone_enc = aes_encrypt_field(phone) if phone else None
    if password.strip():
        validate_password_strength(password)
        hashed = generate_password_hash(password)
        execute("""UPDATE users SET username=%s, password=%s, role=%s, real_name=%s, phone=%s, phone_encrypted=%s, store_name=%s, is_active=%s WHERE id=%s""",
                (username, hashed, role, real_name, phone, phone_enc, store_name, is_active, uid))
    else:
        execute("""UPDATE users SET username=%s, role=%s, real_name=%s, phone=%s, phone_encrypted=%s, store_name=%s, is_active=%s WHERE id=%s""",
                (username, role, real_name, phone, phone_enc, store_name, is_active, uid))
    after = {'username': username, 'role': role, 'real_name': real_name,
             'phone': phone, 'store_name': store_name, 'is_active': is_active}
    write_log("admin", "修改用户", f"id={uid}, username={username}",
              table_name='users', record_id=uid,
              old_value=dict(before) if before else None,
              new_value=after)

def delete_user(uid):
    """删除用户，清理门店外键，并尝试重整用户ID"""
    # 获取用户信息（为后续门店清理和日志记录做准备）
    user = query_one("SELECT * FROM users WHERE id = %s", (uid,))

    # 1. 直接清理所有引用该用户的门店记录（manager_user_id 外键）
    execute("UPDATE stores SET manager_user_id = NULL WHERE manager_user_id = %s", (uid,))

    # 2. 删除用户
    execute("DELETE FROM users WHERE id = %s", (uid,))
    write_log("admin", "删除用户", f"id={uid}",
              table_name='users', record_id=uid,
              old_value=dict(user) if user else None)

    # 3. 尝试重整ID（如果失败，不影响主流程）
    try:
        reorganize_user_ids()
    except Exception as e:
        print(f"警告：用户ID重整失败（已记录），错误: {e}")
        # 可选：将错误写入专门的日志表或文件，这里仅打印
# ---------- 以下函数保持原样，未做修改 ----------
def get_store_names():
    rows = query_all("SELECT DISTINCT store_name FROM medicines WHERE store_name IS NOT NULL AND store_name <> '' ORDER BY store_name")
    return [r["store_name"] for r in rows]

def get_categories():
    return query_all("SELECT id, name, description FROM categories ORDER BY id")

def add_category(name, description):
    execute("INSERT INTO categories (name, description) VALUES (%s,%s)", (name, description))

def update_category(cid, name, description):
    execute("UPDATE categories SET name=%s, description=%s WHERE id=%s", (name, description, cid))

def delete_category(cid):
    execute("DELETE FROM categories WHERE id=%s", (cid,))

def get_suppliers():
    return query_all("SELECT id, name, contact_person, phone, address, rating, is_active, created_at FROM suppliers ORDER BY id")

def add_supplier(name, contact_person, phone, address, rating=5, is_active=True):
    execute("INSERT INTO suppliers (name, contact_person, phone, address, rating, is_active) VALUES (%s,%s,%s,%s,%s,%s)",
            (name, contact_person, phone, address, rating, is_active))

def update_supplier(sid, name, contact_person, phone, address, rating, is_active):
    execute("UPDATE suppliers SET name=%s, contact_person=%s, phone=%s, address=%s, rating=%s, is_active=%s WHERE id=%s",
            (name, contact_person, phone, address, rating, is_active, sid))

def delete_supplier(sid):
    execute("DELETE FROM suppliers WHERE id=%s", (sid,))

def get_medicine_detail(mid):
    return query_one("""
        SELECT m.id, m.code, m.name, m.generic_name, c.name AS category_name,
               m.category_id, m.spec, m.unit, m.manufacturer, m.approval_no, m.is_rx,
               m.price, m.purchase_price, m.stock, m.warning_stock, m.store_name, m.description,
               m.usage_method, m.adverse_reaction, m.storage_condition, m.image_path,
               m.created_at, m.updated_at
        FROM medicines m LEFT JOIN categories c ON m.category_id = c.id
        WHERE m.id=%s
    """, (mid,))

def search_medicines(filters, page_num=1, page_size=15, sort_field="id", sort_dir="asc"):
    sort_map = {"id":"m.id","code":"m.code","name":"m.name","manufacturer":"m.manufacturer","price":"m.price","stock":"m.stock","store_name":"m.store_name"}
    if sort_field not in sort_map:
        sort_field = "id"
    order_col = sort_map[sort_field]
    order_dir_val = str(sort_dir).strip().lower()
    order_dir = "DESC" if order_dir_val == "desc" else "ASC"
    where = ["1=1", "(m.is_active IS NULL OR m.is_active = TRUE)"]
    params = []
    keyword = (filters.get("keyword") or "").strip()
    if keyword:
        where.append("(m.name ILIKE %s OR m.code ILIKE %s OR m.manufacturer ILIKE %s OR m.generic_name ILIKE %s)")
        kw = f"%{keyword}%"
        params.extend([kw, kw, kw, kw])
    store_name = (filters.get("store_name") or "").strip()
    if store_name and store_name != "全部":
        where.append("m.store_name=%s")
        params.append(store_name)
    manufacturer = (filters.get("manufacturer") or "").strip()
    if manufacturer:
        where.append("m.manufacturer ILIKE %s")
        params.append(f"%{manufacturer}%")
    category_id = filters.get("category_id")
    if category_id and str(category_id).strip() not in ("", "全部"):
        where.append("m.category_id=%s")
        params.append(int(category_id))
    pmin = str(filters.get("pmin") or "").strip()
    if pmin:
        where.append("m.price >= %s")
        params.append(float(pmin))
    pmax = str(filters.get("pmax") or "").strip()
    if pmax:
        where.append("m.price <= %s")
        params.append(float(pmax))
    smin = str(filters.get("smin") or "").strip()
    if smin:
        where.append("m.stock >= %s")
        params.append(int(smin))
    smax = str(filters.get("smax") or "").strip()
    if smax:
        where.append("m.stock <= %s")
        params.append(int(smax))
    stock_status = (filters.get("stock_status") or "").strip()
    if stock_status == "低库存":
        where.append("m.stock <= m.warning_stock")
    elif stock_status == "无库存":
        where.append("m.stock = 0")
    elif stock_status == "有库存":
        where.append("m.stock > 0")
    is_rx = filters.get("is_rx")
    if str(is_rx) == "1":
        where.append("m.is_rx=TRUE")
    elif str(is_rx) == "0":
        where.append("m.is_rx=FALSE")
    where_sql = " AND ".join(where)
    total = query_one(f"SELECT COUNT(*) AS c FROM medicines m LEFT JOIN categories c ON m.category_id = c.id WHERE {where_sql}", tuple(params))["c"]
    offset = (page_num - 1) * page_size
    rows = query_all(f"""
        SELECT m.id, m.code, m.name, m.generic_name, COALESCE(c.name,'') AS category_name,
               m.spec, m.unit, m.manufacturer, m.approval_no, m.is_rx,
               m.price, m.purchase_price, m.stock, m.warning_stock, m.store_name,
               m.image_path, m.updated_at
        FROM medicines m LEFT JOIN categories c ON m.category_id = c.id
        WHERE {where_sql} ORDER BY {order_col} {order_dir} LIMIT %s OFFSET %s
    """, tuple(params + [page_size, offset]))
    return rows, total

def add_medicine(code, name, generic_name, category_id, spec, unit, manufacturer,
                 approval_no, is_rx, price, stock, warning_stock, store_name,
                 description, usage_method, adverse_reaction, storage_condition, image_path=""):
    import random
    purchase_price = round(price * (0.6 + random.random() * 0.25), 2)
    new_id = execute_insert("""
        INSERT INTO medicines
        (code, name, generic_name, category_id, spec, unit, manufacturer, approval_no,
         is_rx, price, purchase_price, stock, warning_stock, store_name, description, usage_method,
         adverse_reaction, storage_condition, image_path, updated_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,CURRENT_TIMESTAMP) RETURNING id
    """, (code, name, generic_name, category_id, spec, unit, manufacturer, approval_no,
          is_rx, price, purchase_price, stock, warning_stock, store_name, description, usage_method,
          adverse_reaction, storage_condition, image_path))
    write_log("manager", "新增药品", f"{code}/{name}/{store_name}",
              table_name='medicines', record_id=new_id,
              new_value={'code': code, 'name': name, 'price': price,
                         'stock': stock, 'store_name': store_name})

def update_medicine(mid, code, name, generic_name, category_id, spec, unit, manufacturer,
                    approval_no, is_rx, price, stock, warning_stock, store_name,
                    description, usage_method, adverse_reaction, storage_condition, image_path=""):
    before = query_one("SELECT code, name, price, stock, store_name FROM medicines WHERE id=%s", (mid,))
    execute("""
        UPDATE medicines SET code=%s, name=%s, generic_name=%s, category_id=%s, spec=%s, unit=%s,
            manufacturer=%s, approval_no=%s, is_rx=%s, price=%s, stock=%s,
            warning_stock=%s, store_name=%s, description=%s, usage_method=%s,
            adverse_reaction=%s, storage_condition=%s, image_path=%s, updated_at=CURRENT_TIMESTAMP
        WHERE id=%s
    """, (code, name, generic_name, category_id, spec, unit, manufacturer, approval_no,
          is_rx, price, stock, warning_stock, store_name, description, usage_method,
          adverse_reaction, storage_condition, image_path, mid))
    write_log("manager", "修改药品", f"id={mid}/{code}/{name}",
              table_name='medicines', record_id=mid,
              old_value=dict(before) if before else None,
              new_value={'code': code, 'name': name, 'price': price,
                         'stock': stock, 'store_name': store_name})

def delete_medicine(mid):
    before = query_one("SELECT code, name, price, stock, store_name FROM medicines WHERE id=%s", (mid,))
    sales = query_one("SELECT COUNT(*) as c FROM sales_items WHERE medicine_id=%s", (mid,))
    count = sales["c"] if sales else 0
    if count > 0:
        execute("UPDATE medicines SET is_active=FALSE WHERE id=%s", (mid,))
        write_log("manager", "停用药品", f"id={mid}（已有销售记录）",
                  table_name='medicines', record_id=mid,
                  old_value=dict(before) if before else None)
        return "soft"
    else:
        execute("DELETE FROM medicine_batches WHERE medicine_id=%s", (mid,))
        execute("DELETE FROM medicines WHERE id=%s", (mid,))
        write_log("manager", "删除药品", f"id={mid}",
                  table_name='medicines', record_id=mid,
                  old_value=dict(before) if before else None)
        return "hard"

def get_batches(medicine_id=None):
    sql = """
        SELECT b.id, b.medicine_id, m.code, m.name AS medicine_name,
               b.batch_no, b.supplier_id, COALESCE(s.name,'') AS supplier_name,
               b.production_date, b.expiry_date, b.quantity, b.remain_quantity,
               b.purchase_price, b.store_name, b.created_at
        FROM medicine_batches b JOIN medicines m ON b.medicine_id = m.id
        LEFT JOIN suppliers s ON b.supplier_id = s.id
    """
    params = []
    if medicine_id:
        sql += " WHERE b.medicine_id=%s"
        params.append(medicine_id)
    sql += " ORDER BY b.id DESC"
    return query_all(sql, tuple(params))

def create_stock_in_order(supplier_id, store_name, created_by, items):
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        order_no = "IN" + datetime.now().strftime("%Y%m%d%H%M%S")
        total_amount = 0
        for it in items:
            total_amount += float(it["purchase_price"]) * int(it["quantity"])
        cur.execute("""
            INSERT INTO stock_in_orders (order_no, supplier_id, store_name, status, total_amount, created_by)
            VALUES (%s,%s,%s,'已入库',%s,%s) RETURNING id
        """, (order_no, supplier_id, store_name, total_amount, created_by))
        order_id = cur.fetchone()["id"]
        for it in items:
            medicine_id = int(it["medicine_id"])
            batch_no = it["batch_no"]
            qty = int(it["quantity"])
            price = float(it["purchase_price"])
            amount = qty * price
            production_date = it.get("production_date") or None
            expiry_date = it.get("expiry_date") or None
            med = query_one("SELECT stock FROM medicines WHERE id=%s", (medicine_id,))
            before_stock = med["stock"] if med else 0
            after_stock = before_stock + qty
            cur.execute("""
                INSERT INTO stock_in_items (order_id, medicine_id, batch_no, quantity, purchase_price, amount, production_date, expiry_date)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (order_id, medicine_id, batch_no, qty, price, amount, production_date, expiry_date))
            cur.execute("UPDATE medicines SET stock = stock + %s, updated_at=CURRENT_TIMESTAMP WHERE id=%s", (qty, medicine_id))
            cur.execute("""
                INSERT INTO medicine_batches (medicine_id, batch_no, supplier_id, production_date, expiry_date, quantity, remain_quantity, purchase_price, store_name)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (medicine_id, batch_no, supplier_id, production_date, expiry_date, qty, qty, price, store_name))
            cur.execute("""
                INSERT INTO inventory_logs (medicine_id, change_type, change_qty, before_stock, after_stock, ref_type, ref_id, store_name, operator_name, remark)
                VALUES (%s,'入库',%s,%s,%s,'stock_in',%s,%s,%s,%s)
            """, (medicine_id, qty, before_stock, after_stock, order_id, store_name, created_by, f"入库单号={order_no}"))
        conn.commit()
        cur.close()
        write_log(created_by, "创建入库单", f"order_no={order_no}, total_amount={total_amount}")
        return True, order_no
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        conn.close()

def create_stock_out_order(medicine_id, quantity, out_type, remark, operator_name, store_name):
    if quantity <= 0:
        return False, "数量必须大于0"
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT id, code, name, stock, store_name FROM medicines WHERE id=%s FOR UPDATE", (medicine_id,))
        med = cur.fetchone()
        if not med:
            return False, "药品不存在"
        if med["stock"] < quantity:
            return False, "库存不足"
        if med["store_name"] != store_name:
            return False, "该药品不属于当前门店"
        before_stock = med["stock"]
        after_stock = before_stock - quantity
        order_no = "OUT" + datetime.now().strftime("%Y%m%d%H%M%S")
        cur.execute("UPDATE medicines SET stock=%s, updated_at=CURRENT_TIMESTAMP WHERE id=%s", (after_stock, medicine_id))
        cur.execute("""
            INSERT INTO inventory_logs (medicine_id, change_type, change_qty, before_stock, after_stock, ref_type, ref_id, store_name, operator_name, remark)
            VALUES (%s,%s,%s,%s,%s,'stock_out',NULL,%s,%s,%s)
        """, (medicine_id, out_type, -quantity, before_stock, after_stock, store_name, operator_name,
              f"{out_type}: {remark} (单号{order_no})"))
        conn.commit()
        write_log(operator_name, "快速出库", f"药品ID={medicine_id}, 数量={quantity}, 类型={out_type}")
        return True, order_no
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        conn.close()

def get_stock_in_orders(page_num=1, page_size=20):
    total = query_one("SELECT COUNT(*) AS c FROM stock_in_orders")["c"]
    offset = (page_num - 1) * page_size
    rows = query_all("""
        SELECT o.id, o.order_no, o.store_name, o.status, o.total_amount, o.created_by,
               o.created_at, COALESCE(s.name,'') AS supplier_name
        FROM stock_in_orders o LEFT JOIN suppliers s ON o.supplier_id = s.id
        ORDER BY o.id DESC LIMIT %s OFFSET %s
    """, (page_size, offset))
    return rows, total

def get_inventory_logs(store_name="全部"):
    if store_name == "全部":
        return query_all("""
            SELECT id, medicine_id, change_type, change_qty, before_stock, after_stock,
                   store_name, operator_name, remark, created_at
            FROM inventory_logs ORDER BY id DESC LIMIT 200
        """)
    else:
        return query_all("""
            SELECT id, medicine_id, change_type, change_qty, before_stock, after_stock,
                   store_name, operator_name, remark, created_at
            FROM inventory_logs WHERE store_name = %s ORDER BY id DESC LIMIT 200
        """, (store_name,))

def create_price_request(medicine_id, new_price, reason, request_by):
    med = query_one("SELECT price FROM medicines WHERE id=%s", (medicine_id,))
    if not med:
        return False, "药品不存在"
    old_price = float(med["price"])
    execute("""
        INSERT INTO price_change_requests (medicine_id, old_price, new_price, reason, status, request_by)
        VALUES (%s,%s,%s,%s,'待审批',%s)
    """, (medicine_id, old_price, new_price, reason, request_by))
    write_log(request_by, "发起价格审批", f"medicine_id={medicine_id}, {old_price}->{new_price}")
    return True, "申请已提交"

def get_price_requests(status="全部"):
    if status == "全部":
        return query_all("""
            SELECT p.id, p.medicine_id, m.name AS medicine_name, m.code,
                   p.old_price, p.new_price, p.reason, p.status,
                   p.request_by, p.approve_by, p.approve_remark,
                   p.requested_at, p.approved_at
            FROM price_change_requests p JOIN medicines m ON p.medicine_id = m.id
            ORDER BY p.id DESC
        """)
    return query_all("""
        SELECT p.id, p.medicine_id, m.name AS medicine_name, m.code,
               p.old_price, p.new_price, p.reason, p.status,
               p.request_by, p.approve_by, p.approve_remark,
               p.requested_at, p.approved_at
        FROM price_change_requests p JOIN medicines m ON p.medicine_id = m.id
        WHERE p.status=%s ORDER BY p.id DESC
    """, (status,))

def approve_price_request(req_id, approve_by, passed=True, remark=""):
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT id, medicine_id, old_price, new_price, status FROM price_change_requests WHERE id=%s", (req_id,))
        req = cur.fetchone()
        if not req:
            return False, "申请不存在"
        if req["status"] != "待审批":
            return False, "该申请已处理"
        if passed:
            final_remark = remark.strip() or "审批通过，可以执行"
            cur.execute("UPDATE medicines SET price=%s, updated_at=CURRENT_TIMESTAMP WHERE id=%s", (req["new_price"], req["medicine_id"]))
            cur.execute("""
                UPDATE price_change_requests SET status='已通过', approve_by=%s, approve_remark=%s, approved_at=CURRENT_TIMESTAMP WHERE id=%s
            """, (approve_by, final_remark, req_id))
            conn.commit()
            write_log(approve_by, "审批价格调整", f"req_id={req_id}, 价格通过 {req['old_price']}->{req['new_price']}",
                      table_name='price_change_requests', record_id=req_id,
                      new_value={'medicine_id': req['medicine_id'], 'old_price': float(req['old_price']),
                                 'new_price': float(req['new_price']), 'status': '已通过'})
            return True, "审批通过"
        else:
            final_remark = remark.strip() or "审批驳回"
            cur.execute("""
                UPDATE price_change_requests SET status='已驳回', approve_by=%s, approve_remark=%s, approved_at=CURRENT_TIMESTAMP WHERE id=%s
            """, (approve_by, final_remark, req_id))
            conn.commit()
            write_log(approve_by, "审批价格调整", f"req_id={req_id}, 价格驳回 {req['old_price']}->{req['new_price']}",
                      table_name='price_change_requests', record_id=req_id,
                      new_value={'medicine_id': req['medicine_id'], 'old_price': float(req['old_price']),
                                 'new_price': float(req['new_price']), 'status': '已驳回'})
            return True, "已驳回"
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        conn.close()

def create_transfer_order(medicine_id, quantity, from_store, to_store, created_by, remark=""):
    if from_store == to_store:
        return False, "调出门店和调入门店不能相同"
    med = query_one("SELECT id, stock, store_name, name FROM medicines WHERE id=%s", (medicine_id,))
    if not med:
        return False, "药品不存在"
    if med["store_name"] != from_store:
        return False, "该药品不属于调出门店"
    if med["stock"] < int(quantity):
        return False, "库存不足"
    order_no = "TR" + datetime.now().strftime("%Y%m%d%H%M%S")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO stock_transfer_orders (order_no, medicine_id, quantity, from_store, to_store, status, created_by, remark)
            VALUES (%s,%s,%s,%s,%s,'待处理',%s,%s) RETURNING id
        """, (order_no, medicine_id, quantity, from_store, to_store, created_by, remark))
        oid = cur.fetchone()[0]
        cur.execute("INSERT INTO stock_transfer_items (transfer_order_id, medicine_id, quantity) VALUES (%s,%s,%s)",
                    (oid, medicine_id, quantity))
        conn.commit()
        cur.close()
        write_log(created_by, "创建调拨单", f"order_no={order_no}, {from_store}->{to_store}, qty={quantity}")
        return True, order_no
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        conn.close()

def get_transfer_orders(status="全部"):
    if status == "全部":
        return query_all("""
            SELECT t.id, t.order_no, t.medicine_id, m.name AS medicine_name, m.code,
                   t.quantity, t.from_store, t.to_store, t.status,
                   t.created_by, t.approved_by, t.remark, t.created_at, t.approved_at
            FROM stock_transfer_orders t JOIN medicines m ON t.medicine_id = m.id
            ORDER BY t.id DESC
        """)
    return query_all("""
        SELECT t.id, t.order_no, t.medicine_id, m.name AS medicine_name, m.code,
               t.quantity, t.from_store, t.to_store, t.status,
               t.created_by, t.approved_by, t.remark, t.created_at, t.approved_at
        FROM stock_transfer_orders t JOIN medicines m ON t.medicine_id = m.id
        WHERE t.status=%s ORDER BY t.id DESC
    """, (status,))

def approve_transfer_order(order_id, approved_by, passed=True, remark=""):
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM stock_transfer_orders WHERE id=%s", (order_id,))
        order = cur.fetchone()
        if not order:
            return False, "调拨单不存在"
        if order["status"] != "待处理":
            return False, "该调拨单已处理"
        if not passed:
            cur.execute("""
                UPDATE stock_transfer_orders SET status='已驳回', approved_by=%s, approved_at=CURRENT_TIMESTAMP, remark=%s
                WHERE id=%s
            """, (approved_by, remark or "审批驳回", order_id))
            conn.commit()
            write_log(approved_by, "审批调拨单", f"order_id={order_id}, passed=False")
            return True, "已驳回"
        qty = int(order["quantity"])
        medicine_id = int(order["medicine_id"])
        from_store = order["from_store"]
        to_store = order["to_store"]
        cur.execute("""
            SELECT id, stock, code, name, generic_name, category_id, spec, unit, manufacturer,
                   approval_no, is_rx, price, warning_stock, description, usage_method,
                   adverse_reaction, storage_condition, image_path
            FROM medicines WHERE id=%s FOR UPDATE
        """, (medicine_id,))
        source_med = cur.fetchone()
        if not source_med or source_med["stock"] < qty:
            return False, "库存不足"
        source_before = source_med["stock"]
        source_after = source_before - qty
        cur.execute("UPDATE medicines SET stock=%s, updated_at=CURRENT_TIMESTAMP WHERE id=%s", (source_after, medicine_id))
        cur.execute("SELECT id, stock FROM medicines WHERE code=%s AND store_name=%s FOR UPDATE",
                    (source_med["code"], to_store))
        target_med = cur.fetchone()
        if target_med:
            target_before = target_med["stock"]
            target_after = target_before + qty
            cur.execute("UPDATE medicines SET stock=%s, updated_at=CURRENT_TIMESTAMP WHERE id=%s", (target_after, target_med["id"]))
            target_id = target_med["id"]
        else:
            cur.execute("""
                INSERT INTO medicines (code, name, generic_name, category_id, spec, unit, manufacturer, approval_no, is_rx,
                         price, purchase_price, stock, warning_stock, store_name, description, usage_method, adverse_reaction,
                         storage_condition, image_path, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,CURRENT_TIMESTAMP) RETURNING id
            """, (source_med["code"], source_med["name"], source_med["generic_name"], source_med["category_id"],
                  source_med["spec"], source_med["unit"], source_med["manufacturer"], source_med["approval_no"],
                  source_med["is_rx"], source_med["price"], source_med["purchase_price"], qty, source_med["warning_stock"],
                  to_store, source_med["description"], source_med["usage_method"], source_med["adverse_reaction"],
                  source_med["storage_condition"], source_med["image_path"]))
            target_id = cur.fetchone()["id"]
            target_before = 0
            target_after = qty
        cur.execute("""
            UPDATE stock_transfer_orders SET status='已通过', approved_by=%s, approved_at=CURRENT_TIMESTAMP, remark=%s
            WHERE id=%s
        """, (approved_by, remark or "审批通过", order_id))
        cur.execute("""
            INSERT INTO inventory_logs (medicine_id, change_type, change_qty, before_stock, after_stock, ref_type, ref_id, store_name, operator_name, remark)
            VALUES (%s,'调出',%s,%s,%s,'transfer',%s,%s,%s,%s)
        """, (medicine_id, -qty, source_before, source_after, order_id, from_store, approved_by, f"调拨到{to_store}"))
        cur.execute("""
            INSERT INTO inventory_logs (medicine_id, change_type, change_qty, before_stock, after_stock, ref_type, ref_id, store_name, operator_name, remark)
            VALUES (%s,'调入',%s,%s,%s,'transfer',%s,%s,%s,%s)
        """, (target_id, qty, target_before, target_after, order_id, to_store, approved_by, f"从{from_store}调入"))
        conn.commit()
        write_log(approved_by, "审批调拨单", f"order_id={order_id}, passed=True")
        return True, "调拨审批通过"
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        conn.close()

def get_inventory_warnings(store_name="全部"):
    where = ["1=1"]
    params = []
    if store_name != "全部":
        where.append("m.store_name=%s")
        params.append(store_name)
    low_stock_rows = query_all(f"""
        SELECT m.id, m.code, m.name, m.manufacturer, m.stock, m.warning_stock,
               m.store_name, '低库存' AS warning_type
        FROM medicines m WHERE {' AND '.join(where)} AND m.stock <= m.warning_stock
        ORDER BY m.stock ASC, m.id ASC
    """, tuple(params))
    near_expiry_rows = query_all("""
        SELECT m.id, m.code, m.name, m.manufacturer, b.remain_quantity AS stock,
               m.warning_stock, b.store_name,
               CASE WHEN b.expiry_date < CURRENT_DATE THEN '已过期'
                    WHEN b.expiry_date <= CURRENT_DATE + INTERVAL '30 day' THEN '近效期'
               END AS warning_type,
               b.batch_no, b.expiry_date
        FROM medicine_batches b JOIN medicines m ON b.medicine_id = m.id
        WHERE b.remain_quantity > 0 AND (b.expiry_date < CURRENT_DATE OR b.expiry_date <= CURRENT_DATE + INTERVAL '30 day')
        ORDER BY b.expiry_date ASC
    """)
    return low_stock_rows, near_expiry_rows

def submit_suggestion(medicine_name, medicine_type, suggest_qty, estimate_price, reason,
                      supplier_suggestion, submitter, store_name):
    execute("""
        INSERT INTO drug_suggestions (medicine_name, medicine_type, suggest_qty, estimate_price, reason, supplier_suggestion, submitter, store_name, status)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'待审批')
    """, (medicine_name, medicine_type, suggest_qty, estimate_price, reason, supplier_suggestion, submitter, store_name))
    write_log(submitter, "提交药品建议", medicine_name)

def get_suggestions(role, username, status="全部"):
    where = ["1=1"]
    params = []
    if role != "系统管理员":
        where.append("submitter=%s")
        params.append(username)
    if status != "全部":
        where.append("status=%s")
        params.append(status)
    where_sql = " AND ".join(where)
    return query_all(f"""
        SELECT id, medicine_name, medicine_type, suggest_qty, estimate_price,
               reason, supplier_suggestion, submitter, store_name, status,
               admin_reply, replied_by, submitted_at, replied_at
        FROM drug_suggestions WHERE {where_sql} ORDER BY id DESC
    """, tuple(params))

def approve_suggestion(suggestion_id, admin_name, passed=True, reply=""):
    row = query_one("SELECT id, status FROM drug_suggestions WHERE id=%s", (suggestion_id,))
    if not row or row["status"] != "待审批":
        return False, "建议不存在或已处理"
    if passed:
        final_reply = reply.strip() or "审批通过，可以采购"
        execute("""
            UPDATE drug_suggestions SET status='已通过', admin_reply=%s, replied_by=%s, replied_at=CURRENT_TIMESTAMP WHERE id=%s
        """, (final_reply, admin_name, suggestion_id))
        write_log(admin_name, "审批药品建议", f"id={suggestion_id}, passed=True")
        return True, "审批通过"
    else:
        final_reply = reply.strip() or "审批驳回"
        execute("""
            UPDATE drug_suggestions SET status='已驳回', admin_reply=%s, replied_by=%s, replied_at=CURRENT_TIMESTAMP WHERE id=%s
        """, (final_reply, admin_name, suggestion_id))
        write_log(admin_name, "审批药品建议", f"id={suggestion_id}, passed=False")
        return True, "已驳回"

def create_sale_order(items, cashier, store_name, payment_method="现金"):
    if not items:
        return False, "销售明细不能为空"
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        total_amount = 0
        med_list = []
        for item in items:
            medicine_id = int(item["medicine_id"])
            qty = int(item["quantity"])
            if qty <= 0:
                return False, "销售数量必须大于0"
            cur.execute("SELECT id, code, name, price, stock, store_name FROM medicines WHERE id=%s FOR UPDATE", (medicine_id,))
            med = cur.fetchone()
            if not med:
                return False, f"药品ID={medicine_id} 不存在"
            if med["stock"] < qty:
                return False, f"{med['name']} 库存不足"
            if med["store_name"] != store_name:
                return False, f"{med['name']} 不属于当前门店"
            amount = float(med["price"]) * qty
            total_amount += amount
            med_list.append((med, qty, amount))
        order_no = "SO" + datetime.now().strftime("%Y%m%d%H%M%S")
        cur.execute("""
            INSERT INTO sales_orders (order_no, total_amount, actual_amount, payment_method, payment_status, cashier, store_name)
            VALUES (%s,%s,%s,%s,'已支付',%s,%s) RETURNING id
        """, (order_no, total_amount, total_amount, payment_method, cashier, store_name))
        order_id = cur.fetchone()["id"]
        for med, qty, amount in med_list:
            before_stock = med["stock"]
            after_stock = before_stock - qty
            cur.execute("INSERT INTO sales_items (order_id, medicine_id, quantity, unit_price, amount) VALUES (%s,%s,%s,%s,%s)",
                        (order_id, med["id"], qty, med["price"], amount))
            cur.execute("UPDATE medicines SET stock = stock - %s, updated_at=CURRENT_TIMESTAMP WHERE id=%s", (qty, med["id"]))
            cur.execute("""
                INSERT INTO inventory_logs (medicine_id, change_type, change_qty, before_stock, after_stock, ref_type, ref_id, store_name, operator_name, remark)
                VALUES (%s,'销售',%s,%s,%s,'sale',%s,%s,%s,%s)
            """, (med["id"], -qty, before_stock, after_stock, order_id, store_name, cashier, f"销售单号={order_no}"))
        cur.execute("INSERT INTO payments (order_no, pay_type, pay_amount, pay_status, operator_name) VALUES (%s,%s,%s,'成功',%s)",
                    (order_no, payment_method, total_amount, cashier))
        conn.commit()
        cur.close()
        write_log(cashier, "销售开单", f"order_no={order_no}, amount={total_amount}")
        return True, order_no
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        conn.close()

def get_sales_orders(page_num=1, page_size=20, cashier="", store_name="全部", year="", month=""):
    where = ["1=1"]
    params = []
    if cashier.strip():
        where.append("so.cashier=%s")
        params.append(cashier.strip())
    if store_name != "全部":
        where.append("so.store_name=%s")
        params.append(store_name)
    if year.strip():
        where.append("EXTRACT(YEAR FROM so.created_at) = %s")
        params.append(int(year.strip()))
    if month.strip():
        where.append("EXTRACT(MONTH FROM so.created_at) = %s")
        params.append(int(month.strip()))
    where_sql = " AND ".join(where)
    total = query_one(f"SELECT COUNT(*) AS c FROM sales_orders so WHERE {where_sql}", tuple(params))["c"]
    offset = (page_num - 1) * page_size
    rows = query_all(f"""
        SELECT so.id, so.order_no, so.total_amount, so.actual_amount, so.payment_method,
               so.payment_status, so.cashier, so.store_name, so.created_at,
               COALESCE(SUM(si.amount - si.quantity * m.purchase_price), 0) AS profit
        FROM sales_orders so
        LEFT JOIN sales_items si ON so.id = si.order_id
        LEFT JOIN medicines m ON si.medicine_id = m.id
        WHERE {where_sql}
        GROUP BY so.id, so.order_no, so.total_amount, so.actual_amount, so.payment_method,
                 so.payment_status, so.cashier, so.store_name, so.created_at
        ORDER BY so.id DESC LIMIT %s OFFSET %s
    """, tuple(params + [page_size, offset]))
    return rows, total

def get_sales_total_profit(cashier="", store_name="全部", year="", month=""):
    where = ["1=1"]
    params = []
    if cashier.strip():
        where.append("so.cashier=%s")
        params.append(cashier.strip())
    if store_name != "全部":
        where.append("so.store_name=%s")
        params.append(store_name)
    if year.strip():
        where.append("EXTRACT(YEAR FROM so.created_at) = %s")
        params.append(int(year.strip()))
    if month.strip():
        where.append("EXTRACT(MONTH FROM so.created_at) = %s")
        params.append(int(month.strip()))
    where_sql = " AND ".join(where)
    result = query_one(f"""
        SELECT COALESCE(SUM(sub.profit), 0) AS total_profit
        FROM (
            SELECT COALESCE(SUM(si.amount - si.quantity * m.purchase_price), 0) AS profit
            FROM sales_orders so
            LEFT JOIN sales_items si ON so.id = si.order_id
            LEFT JOIN medicines m ON si.medicine_id = m.id
            WHERE {where_sql}
            GROUP BY so.id
        ) sub
    """, tuple(params))
    return float(result['total_profit']) if result else 0

def get_sale_order_items(order_no):
    return query_all("""
        SELECT si.id, so.order_no, m.id AS medicine_id, m.code, m.name, 
               si.quantity AS sold_quantity, si.unit_price, si.amount
        FROM sales_items si JOIN sales_orders so ON si.order_id = so.id
        JOIN medicines m ON si.medicine_id = m.id
        WHERE so.order_no=%s ORDER BY si.id
    """, (order_no,))

def create_return_order(sale_order_no, items, reason, operator_name, store_name):
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        import random
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3]
        random_suffix = random.randint(100, 999)
        return_no = f"RT{timestamp}{random_suffix}"
        total_refund_amount = 0
        return_items = []
        for item in items:
            medicine_id = int(item['medicine_id'])
            quantity = int(item['quantity'])
            if quantity <= 0:
                return False, "退货数量必须大于0"
            cur.execute("""
                SELECT si.id, si.quantity, si.unit_price, m.name
                FROM sales_items si JOIN sales_orders so ON si.order_id = so.id
                JOIN medicines m ON si.medicine_id = m.id
                WHERE so.order_no=%s AND m.id=%s
            """, (sale_order_no, medicine_id))
            row = cur.fetchone()
            if not row:
                return False, f"未找到药品ID={medicine_id}的销售记录"
            if quantity > int(row["quantity"]):
                return False, f"退货数量不能超过原销售数量"
            refund_amount = float(row["unit_price"]) * quantity
            total_refund_amount += refund_amount
            return_items.append({
                'medicine_id': medicine_id, 'medicine_name': row['name'],
                'quantity': quantity, 'unit_price': row['unit_price'], 'refund_amount': refund_amount
            })
        cur.execute("""
            INSERT INTO return_orders (order_no, sale_order_no, total_refund_amount, reason, operator_name, store_name)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (return_no, sale_order_no, total_refund_amount, reason, operator_name, store_name))
        for item in return_items:
            medicine_id = item['medicine_id']
            quantity = item['quantity']
            refund_amount = item['refund_amount']
            cur.execute("""
                INSERT INTO return_items (return_order_no, medicine_id, quantity, unit_price, refund_amount)
                VALUES (%s,%s,%s,%s,%s)
            """, (return_no, medicine_id, quantity, item['unit_price'], refund_amount))
            cur.execute("SELECT stock FROM medicines WHERE id=%s FOR UPDATE", (medicine_id,))
            med = cur.fetchone()
            before_stock = med["stock"]
            after_stock = before_stock + quantity
            cur.execute("UPDATE medicines SET stock = stock + %s, updated_at=CURRENT_TIMESTAMP WHERE id=%s", (quantity, medicine_id))
            cur.execute("""
                INSERT INTO inventory_logs (medicine_id, change_type, change_qty, before_stock, after_stock, ref_type, ref_id, store_name, operator_name, remark)
                VALUES (%s,'退货',%s,%s,%s,'return',NULL,%s,%s,%s)
            """, (medicine_id, quantity, before_stock, after_stock, store_name, operator_name, f"退货单号={return_no}"))
        conn.commit()
        cur.close()
        write_log(operator_name, "退货处理", f"return_no={return_no}, sale_order_no={sale_order_no}, 总退款={total_refund_amount}")
        return True, return_no
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        conn.close()

def get_return_orders():
    return query_all("""
        SELECT r.id, r.order_no, r.sale_order_no, r.total_refund_amount, r.reason,
               r.operator_name, r.store_name, r.created_at,
               so.cashier AS sales_operator
        FROM return_orders r
        LEFT JOIN sales_orders so ON r.sale_order_no = so.order_no
        ORDER BY r.id DESC
    """)

def get_return_order_detail(return_no):
    return_order = query_one("""
        SELECT r.id, r.order_no, r.sale_order_no, r.total_refund_amount, r.reason,
               r.operator_name, r.store_name, r.created_at,
               so.cashier AS sales_operator
        FROM return_orders r
        LEFT JOIN sales_orders so ON r.sale_order_no = so.order_no
        WHERE r.order_no = %s
    """, (return_no,))
    if not return_order:
        return None
    items = query_all("""
        SELECT ri.id, ri.medicine_id, m.name AS medicine_name, m.code,
               ri.quantity, ri.unit_price, ri.refund_amount
        FROM return_items ri JOIN medicines m ON ri.medicine_id = m.id
        WHERE ri.return_order_no = %s ORDER BY ri.id
    """, (return_no,))
    return {'return_order': dict(return_order), 'items': [dict(item) for item in items]}

def get_dashboard_stats(role, store_name="全部"):
    if role == "系统管理员":
        return {
            "用户总数": query_one("SELECT COUNT(*) AS c FROM users")["c"],
            "药品总数": query_one("SELECT COUNT(*) AS c FROM medicines")["c"],
            "今日销售单": query_one("SELECT COUNT(*) AS c FROM sales_orders WHERE created_at::date = CURRENT_DATE")["c"],
            "低库存预警": query_one("SELECT COUNT(*) AS c FROM medicines WHERE stock <= warning_stock")["c"],
            "待审批建议": query_one("SELECT COUNT(*) AS c FROM drug_suggestions WHERE status='待审批'")["c"]
        }
    elif role == "药房管理员":
        return {
            "本店药品数": query_one("SELECT COUNT(*) AS c FROM medicines WHERE store_name=%s", (store_name,))["c"],
            "低库存数量": query_one("SELECT COUNT(*) AS c FROM medicines WHERE store_name=%s AND stock <= warning_stock", (store_name,))["c"],
            "今日入库单": query_one("SELECT COUNT(*) AS c FROM stock_in_orders WHERE store_name=%s AND created_at::date = CURRENT_DATE", (store_name,))["c"],
            "待处理调拨": query_one("SELECT COUNT(*) AS c FROM stock_transfer_orders WHERE status='待处理' AND (from_store=%s OR to_store=%s)", (store_name, store_name))["c"],
            "待审价格单": query_one("SELECT COUNT(*) AS c FROM price_change_requests WHERE status='待审批'")["c"]
        }
    else:
        return {"今日订单数": 0, "今日销售额": 0, "可售药品数": 0, "我的退货单": 0}

def get_salesman_dashboard(username, store_name):
    order_row = query_one("SELECT COUNT(*) AS c FROM sales_orders WHERE cashier=%s AND created_at::date = CURRENT_DATE", (username,))
    amount_row = query_one("SELECT COALESCE(SUM(actual_amount),0) AS s FROM sales_orders WHERE cashier=%s AND created_at::date = CURRENT_DATE", (username,))
    med_row = query_one("SELECT COUNT(*) AS c FROM medicines WHERE store_name=%s AND stock > 0", (store_name,))
    return_row = query_one("SELECT COUNT(*) AS c FROM return_orders WHERE operator_name=%s AND created_at::date = CURRENT_DATE", (username,))
    return {
        "今日订单数": order_row["c"],
        "今日销售额": float(amount_row["s"]),
        "可售药品数": med_row["c"],
        "我的退货单": return_row["c"]
    }

def get_logs(page_num=1, page_size=30, keyword=""):
    where = ["1=1"]
    params = []
    if keyword.strip():
        kw = f"%{keyword.strip()}%"
        where.append("(username ILIKE %s OR action ILIKE %s OR detail ILIKE %s)")
        params.extend([kw, kw, kw])
    where_sql = " AND ".join(where)
    total = query_one(f"SELECT COUNT(*) AS c FROM audit_logs WHERE {where_sql}", tuple(params))["c"]
    offset = (page_num - 1) * page_size
    rows = query_all(f"""
        SELECT id, username, action, detail, created_at
        FROM audit_logs WHERE {where_sql} ORDER BY id DESC LIMIT %s OFFSET %s
    """, tuple(params + [page_size, offset]))
    return rows, total

def get_return_orders_by_store(store_name):
    return query_all("""
        SELECT 
            r.order_no, 
            r.sale_order_no, 
            r.total_refund_amount, 
            r.reason,
            r.operator_name AS return_operator,
            so.cashier AS sales_operator,
            r.created_at
        FROM return_orders r
        LEFT JOIN sales_orders so ON r.sale_order_no = so.order_no
        WHERE r.store_name = %s
        ORDER BY r.created_at DESC
    """, (store_name,))

def upgrade_passwords_to_hash():
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT id, username, password FROM users")
        users = cur.fetchall()
        updated_count = 0
        for user in users:
            pwd = user['password']
            if pwd.startswith('scrypt:') or pwd.startswith('$'):
                continue
            hashed = generate_password_hash(pwd)
            cur.execute("UPDATE users SET password = %s WHERE id = %s", (hashed, user['id']))
            updated_count += 1
            print(f"[密码升级] 用户 {user['username']} 密码已哈希化")
        conn.commit()
        cur.close()
        if updated_count > 0:
            print(f"[密码升级] 共升级 {updated_count} 个用户的密码为哈希值")
        else:
            print("[密码升级] 所有密码已是哈希值，无需升级")
    except Exception as e:
        print(f"[密码升级] 发生错误：{e}")
        conn.rollback()
    finally:
        conn.close()

'''def sync_store_manager(pharmacy_name, manager_name):
    if not manager_name or not pharmacy_name:
        return
    existing = query_one("""
        SELECT id, username, real_name FROM users
        WHERE store_name = %s AND role = '药房管理员' AND is_active = TRUE
    """, (pharmacy_name,))
    if existing:
        if existing['real_name'] != manager_name:
            execute("""
                UPDATE users SET real_name = %s WHERE id = %s
            """, (manager_name, existing['id']))
            write_log("system", "同步药房管理员", f"门店 {pharmacy_name} 药房管理员姓名更新为 {manager_name}")
    else:
        username = f"mgr_{pharmacy_name}"
        base_username = username
        counter = 1
        while query_one("SELECT id FROM users WHERE username = %s", (username,)):
            username = f"{base_username}{counter}"
            counter += 1
        hashed = generate_password_hash("123456")
        execute("""
            INSERT INTO users (username, password, role, real_name, phone, store_name, is_active)
            VALUES (%s, %s, '药房管理员', %s, '', %s, TRUE)
        """, (username, hashed, manager_name, pharmacy_name))
        write_log("system", "自动创建药房管理员", f"用户名 {username} 门店 {pharmacy_name}")
'''
def reorganize_user_ids():
    """
    重新整理用户表的ID，使其从1开始连续无间隙。
    通过临时移除外键约束、重排ID、然后恢复约束来实现，无需超级用户权限。
    """
    conn = get_conn()
    try:
        cur = conn.cursor()

        # 1. 查询外键约束名称（根据你的环境可能需要调整）
        cur.execute("""
            SELECT conname
            FROM pg_constraint
            WHERE conrelid = 'stores'::regclass
              AND confrelid = 'users'::regclass
              AND contype = 'f'
        """)
        constraint_rows = cur.fetchall()
        if not constraint_rows:
            # 没有外键约束，直接进行ID重排
            _do_reorganize_without_fk(cur, conn)
            return
        constraint_name = constraint_rows[0][0]

        # 2. 删除外键约束
        cur.execute(f"ALTER TABLE stores DROP CONSTRAINT {constraint_name}")

        # 3. 进行ID重排（此时没有外键约束，可自由修改主键和外键）
        _do_reorganize_without_fk(cur, conn)

        # 4. 重建外键约束
        cur.execute(f"""
            ALTER TABLE stores
            ADD CONSTRAINT {constraint_name}
            FOREIGN KEY (manager_user_id) REFERENCES users(id)
            ON UPDATE NO ACTION ON DELETE SET NULL
        """)

        conn.commit()
        print("用户ID重整完成")
    except Exception as e:
        conn.rollback()
        print(f"重排用户ID失败: {e}")
        raise
    finally:
        conn.close()

def _do_reorganize_without_fk(cur, conn):
    """实际的ID重排逻辑，假设此时没有外键约束"""
    import psycopg2

    # 1. 将所有用户的 ID 临时增加一个大偏移量
    OFFSET = 1000000
    cur.execute("UPDATE users SET id = id + %s", (OFFSET,))
    cur.execute("UPDATE stores SET manager_user_id = manager_user_id + %s WHERE manager_user_id IS NOT NULL", (OFFSET,))

    # 2. 获取排序后的临时ID
    cur.execute("SELECT id FROM users ORDER BY id")
    temp_ids = [row[0] for row in cur.fetchall()]

    # 3. 重排为 1,2,3...
    for new_id, temp_id in enumerate(temp_ids, start=1):
        if new_id != temp_id:
            cur.execute("UPDATE users SET id = %s WHERE id = %s", (new_id, temp_id))
            cur.execute("UPDATE stores SET manager_user_id = %s WHERE manager_user_id = %s", (new_id, temp_id))

    # 4. 重置序列
    max_id = len(temp_ids)
    cur.execute("SELECT setval('users_id_seq', %s)", (max_id,))




def get_drugs(keyword):
    # 已在上面的 API 中直接调用 query_all，可不单独写函数
    pass

def create_sale_order_for_staff(cart_items, cashier, store_name, payment_method):
    # 类似于原有的 create_sale_order，但返回格式不同
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        total_amount = 0
        for item in cart_items:
            drug_id = item['drug_id']
            qty = item['quantity']
            cur.execute("SELECT price, stock FROM drugs WHERE id=%s FOR UPDATE", (drug_id,))
            drug = cur.fetchone()
            if not drug:
                return False, "药品不存在"
            if drug['stock'] < qty:
                return False, "库存不足"
            total_amount += float(drug['price']) * qty
        # 生成销售单号
        order_no = "SO" + datetime.now().strftime("%Y%m%d%H%M%S")
        cur.execute("""
            INSERT INTO sales_orders (order_no, total_amount, actual_amount, payment_method, payment_status, cashier, store_name)
            VALUES (%s, %s, %s, %s, '已支付', %s, %s) RETURNING id
        """, (order_no, total_amount, total_amount, payment_method, cashier, store_name))
        order_id = cur.fetchone()['id']
        for item in cart_items:
            drug_id = item['drug_id']
            qty = item['quantity']
            cur.execute("SELECT price FROM drugs WHERE id=%s", (drug_id,))
            price = cur.fetchone()['price']
            amount = price * qty
            cur.execute("INSERT INTO sales_items (order_id, medicine_id, quantity, unit_price, amount) VALUES (%s, %s, %s, %s, %s)",
                        (order_id, drug_id, qty, price, amount))
            cur.execute("UPDATE drugs SET stock = stock - %s WHERE id=%s", (qty, drug_id))
            # 库存日志
            cur.execute("INSERT INTO inventory_logs (medicine_id, change_type, change_qty, before_stock, after_stock, ref_type, ref_id, store_name, operator_name, remark) VALUES (%s,'销售',%s,%s,%s,'sale',%s,%s,%s,%s)",
                        (drug_id, -qty, drug['stock']+qty, drug['stock'], order_id, store_name, cashier, f"销售单号={order_no}"))
        conn.commit()
        return True, {'order_no': order_no, 'total': total_amount}
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        conn.close()


def add_suggestion(drug_name, drug_type, quantity, estimated_price, reason, supplier_suggestion, submitter, store_name):
    execute("""
        INSERT INTO drug_suggestions (medicine_name, medicine_type, suggest_qty, estimate_price, reason, supplier_suggestion, submitter, store_name, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, '待审批')
    """, (drug_name, drug_type, quantity, estimated_price, reason, supplier_suggestion, submitter, store_name))
    return True, "提交成功"

def get_suggestions_by_staff(username):
    return query_all("""
        SELECT id, medicine_name AS drug_name, medicine_type AS drug_type, suggest_qty AS quantity,
               estimate_price AS estimated_price, reason, supplier_suggestion, status,
               admin_reply AS admin_comment, replied_at AS reviewed_at, submitted_at AS created_at
        FROM drug_suggestions
        WHERE submitter = %s
        ORDER BY submitted_at DESC
    """, (username,))
# ==================== 销售员专用函数 ====================

def get_sales_by_staff(username):
    """获取指定销售员的所有销售记录"""
    return query_all("""
        SELECT so.id, so.order_no, so.total_amount, so.payment_method, so.payment_status, so.created_at,
               so.cashier, so.store_name,
               (SELECT pay_type FROM payments WHERE order_no = so.order_no LIMIT 1) AS payment_no,
               '已完成' AS status
        FROM sales_orders so
        WHERE so.cashier = %s
        ORDER BY so.created_at DESC
    """, (username,))


def add_suggestion(drug_name, drug_type, quantity, estimated_price, reason, supplier_suggestion, submitter, store_name):
    """提交药品建议（复用 drug_suggestions 表）"""
    try:
        execute("""
            INSERT INTO drug_suggestions (medicine_name, medicine_type, suggest_qty, estimate_price, reason,
                supplier_suggestion, submitter, store_name, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, '待审批')
        """, (drug_name, drug_type, quantity, estimated_price, reason, supplier_suggestion, submitter, store_name))
        return True, "提交成功"
    except Exception as e:
        return False, str(e)

def get_suggestions_by_staff(username):
    """获取销售员自己提交的建议列表"""
    return query_all("""
        SELECT id, medicine_name AS drug_name, medicine_type AS drug_type, suggest_qty AS quantity,
               estimate_price AS estimated_price, reason, supplier_suggestion, status,
               admin_reply AS admin_comment, replied_at AS reviewed_at, submitted_at AS created_at
        FROM drug_suggestions
        WHERE submitter = %s
        ORDER BY submitted_at DESC
    """, (username,))

# ==================== 安全看板查询 ====================

def get_security_overview():
    """安全概览：今日统计 + 核心指标"""
    today = datetime.now().date()
    yesterday_24h = datetime.now() - timedelta(hours=24)
    return {
        'today_success': query_one(
            "SELECT COUNT(*) AS c FROM audit_logs WHERE action='登录成功' AND created_at::date = %s", (today,))['c'],
        'today_fail': query_one(
            "SELECT COUNT(*) AS c FROM audit_logs WHERE action='登录失败' AND created_at::date = %s", (today,))['c'],
        'locked_count': query_one(
            "SELECT COUNT(*) AS c FROM users WHERE locked_until > CURRENT_TIMESTAMP")['c'],
        'unique_ips': query_one(
            "SELECT COUNT(DISTINCT ip_address) AS c FROM audit_logs WHERE created_at::date = %s AND ip_address IS NOT NULL", (today,))['c'],
        'total_events': query_one(
            "SELECT COUNT(*) AS c FROM audit_logs WHERE created_at::date = %s", (today,))['c'],
        'last_24h_events': query_one(
            "SELECT COUNT(*) AS c FROM audit_logs WHERE created_at >= %s", (yesterday_24h,))['c'],
    }

def get_login_trend(days=7):
    """登录趋势：每天成功/失败次数（openGauss 兼容）"""
    start_date = datetime.now() - timedelta(days=days)
    rows = query_all("""
        SELECT created_at::date AS d,
               COUNT(CASE WHEN action = '登录成功' THEN 1 END) AS success,
               COUNT(CASE WHEN action = '登录失败' THEN 1 END) AS fail
        FROM audit_logs
        WHERE action IN ('登录成功', '登录失败')
          AND created_at >= %s
        GROUP BY d ORDER BY d
    """, (start_date,))
    return [{'date': str(r['d']), 'success': r['success'], 'fail': r['fail']} for r in rows]

def get_suspicious_ips(days=7, min_attempts=5):
    """异常IP：失败登录次数超过阈值的IP（openGauss 兼容）"""
    start_date = datetime.now() - timedelta(days=days)
    return query_all("""
        SELECT ip_address,
               COUNT(CASE WHEN action = '登录失败' THEN 1 END) AS fail_count,
               COUNT(CASE WHEN action = '登录成功' THEN 1 END) AS success_count,
               COUNT(*) AS total_attempts,
               MAX(created_at) AS last_seen
        FROM audit_logs
        WHERE action IN ('登录成功', '登录失败')
          AND ip_address IS NOT NULL
          AND created_at >= %s
        GROUP BY ip_address
        HAVING COUNT(CASE WHEN action = '登录失败' THEN 1 END) >= %s
        ORDER BY fail_count DESC
    """, (start_date, min_attempts))

def get_security_events(page=1, page_size=20):
    """最近安全事件列表"""
    offset = (page - 1) * page_size
    total = query_one(
        "SELECT COUNT(*) AS c FROM audit_logs WHERE action IN ('登录失败', '登录成功', '账户锁定', '删除用户', '修改用户')")['c']
    rows = query_all("""
        SELECT id, username, action, detail, ip_address, created_at
        FROM audit_logs
        WHERE action IN ('登录失败', '登录成功', '账户锁定', '删除用户', '修改用户')
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
    """, (page_size, offset))
    return rows, total

def get_action_distribution(days=7):
    """操作类型分布（用于饼图，openGauss 兼容）"""
    start_date = datetime.now() - timedelta(days=days)
    return query_all("""
        SELECT action, COUNT(*) AS cnt
        FROM audit_logs
        WHERE created_at >= %s
        GROUP BY action
        ORDER BY cnt DESC
        LIMIT 10
    """, (start_date,))

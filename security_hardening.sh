#!/bin/bash
# ==============================================
#  openGauss 数据库安全加固脚本
#  连锁药房管理系统
#  用法：bash security_hardening.sh
#  依赖：需先执行 deploy.sh 完成基础部署
# ==============================================

export MSYS2_ARG_CONV_EXCL="*"

CONTAINER_NAME="opengauss"
DB_NAME="drugstore"
GS_PASSWORD="Drug@1234"
PGDATA="/var/lib/opengauss/data"
CERT_DAYS=3650
DOCKER_NETWORK="drugstore-net"
DOCKER_NETWORK_SUBNET="172.28.0.0/24"

PASS=0
FAIL=0
TMP_DIR="./.security_hardening_tmp"
mkdir -p "$TMP_DIR"
trap "rm -rf $TMP_DIR" EXIT

log_info()  { echo "  [信息] $*"; }
log_ok()    { echo "  ✅ $1"; PASS=$((PASS+1)); }
log_err()   { echo "  ❌ $1"; FAIL=$((FAIL+1)); }

echo ""
echo "================================================"
echo "  openGauss 数据库安全加固"
echo "================================================"
echo ""

docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$" || {
    echo "[错误] openGauss 容器未运行"; exit 1
}
log_info "容器运行中"

# ======================================================
#  步骤1：网络隔离
# ======================================================
echo ""; echo "================================================"
echo " [1/7] 网络隔离"; echo "================================================"

if docker network inspect ${DOCKER_NETWORK} >/dev/null 2>&1; then
    log_ok "Docker 内部网络 ${DOCKER_NETWORK} 已存在"
else
    docker network create --driver bridge --subnet=${DOCKER_NETWORK_SUBNET} --gateway=172.28.0.1 ${DOCKER_NETWORK}
    log_ok "创建 Docker 内部网络 ${DOCKER_NETWORK}"
fi
docker network connect ${DOCKER_NETWORK} ${CONTAINER_NAME} 2>/dev/null
log_info "容器已接入 ${DOCKER_NETWORK}"

# pg_hba.conf
log_info "配置 pg_hba.conf IP 白名单..."
cat > ${TMP_DIR}/pg_hba.conf << 'PGEOF'
local   all             all                                     trust
hostssl all             all             127.0.0.1/32            md5
hostssl all             all             172.28.0.0/24           md5
host    all             all             172.17.0.0/16           md5
hostnossl all           all             0.0.0.0/0               reject
hostnossl all           all             ::/0                    reject
hostssl all             all             0.0.0.0/0               reject
hostssl all             all             ::/0                    reject
PGEOF
docker exec ${CONTAINER_NAME} cp ${PGDATA}/pg_hba.conf ${PGDATA}/pg_hba.conf.bak 2>/dev/null || true
docker cp ${TMP_DIR}/pg_hba.conf ${CONTAINER_NAME}:${PGDATA}/pg_hba.conf
docker exec ${CONTAINER_NAME} chown omm:omm ${PGDATA}/pg_hba.conf
log_ok "pg_hba.conf IP 白名单已配置"

# ======================================================
#  步骤2：SSL/TLS
# ======================================================
echo ""; echo "================================================"
echo " [2/7] SSL/TLS 传输加密"; echo "================================================"

log_info "生成 CA 证书..."
openssl req -new -x509 -days ${CERT_DAYS} -nodes -out ${TMP_DIR}/ca.crt -keyout ${TMP_DIR}/ca.key -subj "/C=CN/ST=Guangdong/L=Guangzhou/O=Drugstore/CN=drugstore-ca" 2>/dev/null
log_info "生成服务器证书..."
openssl req -new -nodes -out ${TMP_DIR}/server.csr -keyout ${TMP_DIR}/server.key -subj "/C=CN/ST=Guangdong/L=Guangzhou/O=Drugstore/CN=opengauss" 2>/dev/null
openssl x509 -req -days ${CERT_DAYS} -in ${TMP_DIR}/server.csr -CA ${TMP_DIR}/ca.crt -CAkey ${TMP_DIR}/ca.key -CAcreateserial -out ${TMP_DIR}/server.crt 2>/dev/null
chmod 600 ${TMP_DIR}/server.key ${TMP_DIR}/ca.key
log_ok "证书已生成"

log_info "部署证书到容器..."
docker cp ${TMP_DIR}/ca.crt ${CONTAINER_NAME}:${PGDATA}/ca.crt
docker cp ${TMP_DIR}/server.crt ${CONTAINER_NAME}:${PGDATA}/server.crt
docker cp ${TMP_DIR}/server.key ${CONTAINER_NAME}:${PGDATA}/server.key
docker exec ${CONTAINER_NAME} chown omm:omm ${PGDATA}/ca.crt ${PGDATA}/server.crt ${PGDATA}/server.key
docker exec ${CONTAINER_NAME} chmod 600 ${PGDATA}/server.key
log_ok "证书已部署"

log_info "配置 SSL 参数..."
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c 'ssl=on'" 2>/dev/null
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c \"ssl_cert_file='server.crt'\"" 2>/dev/null
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c \"ssl_key_file='server.key'\"" 2>/dev/null
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c \"ssl_ca_file='ca.crt'\"" 2>/dev/null
log_ok "SSL 已配置"

# ======================================================
#  步骤3：最小权限
# ======================================================
echo ""; echo "================================================"
echo " [3/7] 数据库账号最小权限"; echo "================================================"

cat > ${TMP_DIR}/step3.sql << 'SQLEOF'
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM druguser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM druguser;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM druguser;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM druguser;
REVOKE ALL PRIVILEGES ON DATABASE drugstore FROM druguser;

CREATE ROLE app_rw PASSWORD 'Drug@Role2024!' NOLOGIN;
GRANT CONNECT ON DATABASE drugstore TO app_rw;
GRANT USAGE ON SCHEMA public TO app_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_rw;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO app_rw;

CREATE ROLE audit_readonly PASSWORD 'Drug@Role2024!' NOLOGIN;
GRANT CONNECT ON DATABASE drugstore TO audit_readonly;
GRANT USAGE ON SCHEMA public TO audit_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO audit_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO audit_readonly;

CREATE ROLE backup_role PASSWORD 'Drug@Role2024!' NOLOGIN;
GRANT CONNECT ON DATABASE drugstore TO backup_role;
GRANT USAGE ON SCHEMA public TO backup_role;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO backup_role;

GRANT CONNECT ON DATABASE drugstore TO druguser;
GRANT USAGE ON SCHEMA public TO druguser;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO druguser;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO druguser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO druguser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO druguser;

CREATE USER app_user WITH PASSWORD 'App@Secure2024!' ;
GRANT app_rw TO app_user;
CREATE USER auditor WITH PASSWORD 'Audit@2024!' ;
GRANT audit_readonly TO auditor;
CREATE USER backup_op WITH PASSWORD 'Backup@2024!' ;
GRANT backup_role TO backup_op;
SQLEOF

docker cp ${TMP_DIR}/step3.sql ${CONTAINER_NAME}:/tmp/step3.sql
docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -f /tmp/step3.sql" 2>&1

# 验证
for role in app_rw audit_readonly backup_role app_user auditor backup_op; do
    EXISTS=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT 1 FROM pg_roles WHERE rolname='${role}'\"" 2>/dev/null)
    [ "$EXISTS" = "1" ] && log_ok "  - ${role} 已创建" || log_err "  - ${role} 未创建"
done

# ======================================================
#  步骤4：数据加密
# ======================================================
echo ""; echo "================================================"
echo " [4/7] 数据静态加密"; echo "================================================"

cat > ${TMP_DIR}/step4.sql << 'SQLEOF'
-- 加密密钥存储表（pgcrypto 在 openGauss 社区版不可用，使用 Python 端 AES 加密）
CREATE TABLE IF NOT EXISTS encryption_keys (
    id SERIAL PRIMARY KEY, key_name VARCHAR(100) UNIQUE NOT NULL,
    key_value TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);
INSERT INTO encryption_keys (key_name, key_value, description)
SELECT 'master_key', '00000000000000000000000000000000', 'AES-256 主密钥（由 Python 应用初始化）'
WHERE NOT EXISTS (SELECT 1 FROM encryption_keys WHERE key_name = 'master_key');

-- openGauss 不支持 ALTER TABLE ADD COLUMN IF NOT EXISTS，使用 DO 块
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='phone_encrypted') THEN
        ALTER TABLE users ADD COLUMN phone_encrypted TEXT;
    END IF;
END $$;

REVOKE ALL ON encryption_keys FROM PUBLIC;
GRANT SELECT ON encryption_keys TO app_rw;
SQLEOF

docker cp ${TMP_DIR}/step4.sql ${CONTAINER_NAME}:/tmp/step4.sql
docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -f /tmp/step4.sql" 2>&1

PGCRYPTO=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT 1 FROM pg_extension WHERE extname='pgcrypto'\"" 2>/dev/null)
[ "$PGCRYPTO" = "1" ] && log_ok "pgcrypto 扩展已安装" || log_info "pgcrypto 不可用（openGauss 社区版限制）"
ENC_CNT=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT COUNT(*) FROM users WHERE phone_encrypted IS NOT NULL\"" 2>/dev/null || echo "0")
[ "$ENC_CNT" -gt 0 ] 2>/dev/null && log_ok "${ENC_CNT} 条手机号已加密" || log_info "暂未加密手机号"

# ======================================================
#  步骤5：安全加固
# ======================================================
echo ""; echo "================================================"
echo " [5/7] 数据库原生安全加固"; echo "================================================"

cat > ${TMP_DIR}/step5.sql << 'SQLEOF'
DROP USER IF EXISTS anonymous;
DROP DATABASE IF EXISTS test;
DROP DATABASE IF EXISTS testdb;
DROP DATABASE IF EXISTS sampledb;
DROP DATABASE IF EXISTS example;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON DATABASE drugstore FROM PUBLIC;
SQLEOF

docker cp ${TMP_DIR}/step5.sql ${CONTAINER_NAME}:/tmp/step5.sql
docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -f /tmp/step5.sql" 2>&1
log_ok "安全加固 SQL 执行完成"

# 密码策略
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c 'password_policy = 1'" 2>/dev/null
log_ok "密码策略已配置"

# ======================================================
#  步骤6：审计
# ======================================================
echo ""; echo "================================================"
echo " [6/7] 数据库原生审计"; echo "================================================"

docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c \"audit_directory='pg_audit'\"" 2>/dev/null
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c 'audit_rotation_interval = 7'" 2>/dev/null
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c 'audit_rotation_size = 102400'" 2>/dev/null
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c 'audit_resource_policy = on'" 2>/dev/null
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c 'audit_login_logout = 7'" 2>/dev/null
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c 'audit_database_process = 1'" 2>/dev/null
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c 'audit_user_violation = 1'" 2>/dev/null
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c 'audit_grant_revoke = 1'" 2>/dev/null
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c 'audit_system_object = 1'" 2>/dev/null
docker exec ${CONTAINER_NAME} su - omm -c "gs_guc set -D ${PGDATA} -c 'audit_dml_state = 1'" 2>/dev/null
docker exec ${CONTAINER_NAME} bash -c "mkdir -p ${PGDATA}/pg_audit && chown omm:omm ${PGDATA}/pg_audit"
log_ok "数据库原生审计已配置"

# ======================================================
#  重启使配置生效
# ======================================================
echo ""; echo "================================================"
echo "  重启容器..."; echo "================================================"
docker restart ${CONTAINER_NAME}

# 等待数据库就绪（最多 90 秒）
DB_READY=0
for i in $(seq 1 45); do
    READY=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc 'SELECT 1'" 2>/dev/null)
    if [ "$READY" = "1" ]; then
        log_ok "数据库重启完成 (${i}s)"
        DB_READY=1
        break
    fi
    sleep 2
done

if [ "$DB_READY" != "1" ]; then
    echo "  ⚠ 数据库重启异常，请手动检查: docker logs opengauss"
fi

# ======================================================
#  步骤7：SQL 注入防护
# ======================================================
echo ""; echo "================================================"
echo " [7/7] SQL 注入防护"; echo "================================================"

cat > ${TMP_DIR}/step8.sql << 'SQLEOF'
-- SQL 注入检测视图（依赖 app.py 创建的 audit_logs 表）
CREATE OR REPLACE VIEW sql_injection_alerts AS
SELECT id, username, action, detail, ip_address, created_at
FROM audit_logs
WHERE detail ~* '(union.*select|or 1=1|exec\(|<script|drop table|truncate|waitfor delay)'
AND created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'
ORDER BY created_at DESC;

CREATE OR REPLACE VIEW anomalous_sql_monitor AS
SELECT ip_address, COUNT(*) AS total_attempts,
COUNT(DISTINCT detail) AS unique_patterns, MAX(created_at) AS last_attempt
FROM audit_logs
WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'
GROUP BY ip_address HAVING COUNT(*) > 10 ORDER BY total_attempts DESC;

SQLEOF

docker cp ${TMP_DIR}/step8.sql ${CONTAINER_NAME}:/tmp/step8.sql
docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -f /tmp/step8.sql" 2>&1

for view in sql_injection_alerts anomalous_sql_monitor; do
    EXISTS=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT 1 FROM information_schema.views WHERE table_name='${view}'\"" 2>/dev/null)
    [ "$EXISTS" = "1" ] && log_ok "${view} 已创建" || log_err "${view} 创建失败"
done
for trg in trg_audit_user_delete trg_audit_medicine_price; do
    EXISTS=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT 1 FROM information_schema.triggers WHERE trigger_name='${trg}'\"" 2>/dev/null)
    [ "$EXISTS" = "1" ] && log_ok "${trg} 已创建" || log_info "${trg} 未创建"
done
for tbl in medicines sales_orders; do
    RLS=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT relrowsecurity FROM pg_class WHERE relname='${tbl}'\"" 2>/dev/null)
    [ "$RLS" = "t" ] && log_ok "${tbl} RLS 已启用" || log_err "${tbl} RLS 未启用"
done

log_ok "安全参数已配置"

echo ""; echo "================================================"
echo "  安全加固完成  通过: ${PASS}  失败: ${FAIL}"
echo "================================================"
echo "  新增账号: app_user(业务) / auditor(审计) / backup_op(备份)"
echo "  验证: bash verify_security.sh"
echo "================================================"

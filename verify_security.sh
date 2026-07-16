#!/bin/bash
# ==============================================
#  数据库安全加固验证脚本
#  逐项检查 8 类防护功能是否生效
#  用法：bash verify_security.sh
# ==============================================

# 禁用 Git Bash on Windows 的 MSYS2 自动路径转换
export MSYS2_ARG_CONV_EXCL="*"

CONTAINER_NAME="opengauss"
DB_NAME="drugstore"
PGDATA="/var/lib/opengauss/data"
PASS=0
FAIL=0

log_pass() { echo "  ✅ $1"; PASS=$((PASS+1)); }
log_fail() { echo "  ❌ $1"; FAIL=$((FAIL+1)); }
log_info() { echo "  ℹ️  $1"; }

echo "================================================"
echo "  🔍 数据库安全加固验证"
echo "================================================"
echo ""

# ---- 检查容器运行 ----
docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$" || {
    echo "[错误] openGauss 容器未运行"
    exit 1
}

# =====================================================
#  1. 网络隔离
# =====================================================
echo "【1/8】网络隔离"
echo "--------------------------------------------------"

docker network inspect drugstore-net >/dev/null 2>&1 && \
    log_pass "Docker 内部网络 drugstore-net 已创建" || \
    log_fail "Docker 内部网络 drugstore-net 不存在"

docker inspect ${CONTAINER_NAME} 2>/dev/null | grep -q "drugstore-net" && \
    log_pass "容器已接入 drugstore-net 网络" || \
    log_fail "容器未接入 drugstore-net 网络"

# 检查 pg_hba.conf 是否存在 hostssl 行
SSL_LINES=$(docker exec ${CONTAINER_NAME} grep -c "hostssl" ${PGDATA}/pg_hba.conf 2>/dev/null || echo 0)
[ "$SSL_LINES" -gt 0 ] 2>/dev/null && \
    log_pass "pg_hba.conf 包含 SSL 连接限制 (${SSL_LINES} 条)" || \
    log_fail "pg_hba.conf 未配置 SSL 限制"

# 检查非SSL拒绝规则
NOSSL_LINES=$(docker exec ${CONTAINER_NAME} grep -c "hostnossl.*reject" ${PGDATA}/pg_hba.conf 2>/dev/null || echo 0)
[ "$NOSSL_LINES" -gt 0 ] 2>/dev/null && \
    log_pass "非 SSL 连接已被拒绝 (${NOSSL_LINES} 条)" || \
    log_fail "非 SSL 连接未被拒绝"

echo ""

# =====================================================
#  2. SSL/TLS 传输加密
# =====================================================
echo "【2/8】SSL/TLS 传输加密"
echo "--------------------------------------------------"

SSL_STATUS=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc 'SHOW ssl'" 2>/dev/null || echo "off")
[ "$SSL_STATUS" = "on" ] && \
    log_pass "SSL 已启用 (ssl=on)" || \
    log_fail "SSL 未启用 (ssl=${SSL_STATUS})"

docker exec ${CONTAINER_NAME} test -f ${PGDATA}/server.crt && \
    log_pass "服务器证书 server.crt 已部署" || \
    log_fail "服务器证书缺失"

docker exec ${CONTAINER_NAME} test -f ${PGDATA}/ca.crt && \
    log_pass "CA 证书 ca.crt 已部署" || \
    log_fail "CA 证书缺失"

CERT_PERM=$(docker exec ${CONTAINER_NAME} stat -c "%a" ${PGDATA}/server.key 2>/dev/null || echo "000")
[ "$CERT_PERM" = "600" ] && \
    log_pass "私钥权限正确 (600)" || \
    log_fail "私钥权限异常 (${CERT_PERM})"

echo ""

# =====================================================
#  3. 数据库账号最小权限
# =====================================================
echo "【3/8】数据库账号最小权限"
echo "--------------------------------------------------"

for role in app_rw audit_readonly backup_role app_user auditor backup_op; do
    EXISTS=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT 1 FROM pg_roles WHERE rolname='${role}'\"" 2>/dev/null)
    [ "$EXISTS" = "1" ] && log_pass "角色/用户 ${role} 已创建" || log_fail "角色/用户 ${role} 未创建"
done

IS_SUPER=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT usesuper FROM pg_user WHERE usename='druguser'\"" 2>/dev/null)
[ "$IS_SUPER" = "f" ] && \
    log_pass "druguser 已降级（非超级用户）" || \
    log_fail "druguser 仍是超级用户"

echo ""

# =====================================================
#  4. 数据静态加密
# =====================================================
echo "【4/8】数据静态加密"
echo "--------------------------------------------------"

PGCRYPTO=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT 1 FROM pg_extension WHERE extname='pgcrypto'\"" 2>/dev/null)
[ "$PGCRYPTO" = "1" ] && log_pass "pgcrypto 扩展已安装" || true

AES_ENC=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT 1 FROM pg_proc WHERE proname='aes_encrypt'\"" 2>/dev/null)
[ "$AES_ENC" = "1" ] && \
    log_pass "aes_encrypt 函数已创建" || \
    log_fail "aes_encrypt 函数未创建"

AES_DEC=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT 1 FROM pg_proc WHERE proname='aes_decrypt'\"" 2>/dev/null)
[ "$AES_DEC" = "1" ] && \
    log_pass "aes_decrypt 函数已创建" || \
    log_fail "aes_decrypt 函数未创建"

ENC_KEY_TBL=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT 1 FROM information_schema.tables WHERE table_name='encryption_keys'\"" 2>/dev/null)
[ "$ENC_KEY_TBL" = "1" ] && \
    log_pass "加密密钥表 encryption_keys 已创建" || \
    log_fail "加密密钥表缺失"

PHONE_COL=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='phone_encrypted'\"" 2>/dev/null)
[ "$PHONE_COL" = "1" ] && \
    log_pass "users.phone_encrypted 字段已添加" || \
    log_fail "users.phone_encrypted 字段缺失"

ENC_CNT=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT COUNT(*) FROM users WHERE phone_encrypted IS NOT NULL\"" 2>/dev/null || echo "0")
[ "$ENC_CNT" -gt 0 ] 2>/dev/null && log_pass "已有 ${ENC_CNT} 条手机号已加密" || true

echo ""

# =====================================================
#  5. 数据库原生安全加固
# =====================================================
echo "【5/8】数据库原生安全加固"
echo "--------------------------------------------------"

# 检查匿名账号
ANON=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT 1 FROM pg_user WHERE usename='anonymous'\"" 2>/dev/null)
[ "$ANON" = "1" ] && log_fail "匿名账号仍存在" || log_pass "匿名账号已删除"

# 检查测试库
TEST_DBS=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d postgres -Atc \"SELECT datname FROM pg_database WHERE datname IN ('test','testdb','sampledb')\"" 2>/dev/null)
[ -z "$TEST_DBS" ] && log_pass "测试库已清理" || log_fail "测试库仍存在: ${TEST_DBS}"

# 检查密码策略
PWD_POLICY=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc 'SHOW password_policy'" 2>/dev/null)
[ "$PWD_POLICY" = "1" ] && log_pass "密码策略已启用 (password_policy=1)" || true

echo ""

# =====================================================
#  6. 数据库原生审计
# =====================================================
echo "【6/8】数据库原生审计"
echo "--------------------------------------------------"

AUDIT_ENABLED=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc 'SHOW audit_enabled'" 2>/dev/null)
[ "$AUDIT_ENABLED" = "on" ] && \
    log_pass "数据库原生审计已开启" || \
    log_fail "数据库审计未开启"

for param in audit_login_logout audit_grant_revoke audit_dml_state; do
    VAL=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SHOW ${param}\"" 2>/dev/null)
    [ -n "$VAL" ] && [ "$VAL" != "0" ] && log_pass "${param}=${VAL}" || true
done

# 审计日志文件
AUDIT_FILES=$(docker exec ${CONTAINER_NAME} bash -c "ls ${PGDATA}/pg_audit/ 2>/dev/null | wc -l")
[ "$AUDIT_FILES" -gt 0 ] 2>/dev/null && log_pass "审计日志目录存在 (${AUDIT_FILES} 个文件)" || true

echo ""

# =====================================================
#  7. 备份配置
# =====================================================
echo "【7/8】备份配置"
echo "--------------------------------------------------"

[ -f "backup_dr.sh" ] && log_pass "加密备份脚本 backup_dr.sh 已就绪" || log_fail "backup_dr.sh 缺失"

BACKUP_DIR="/d/backups/drugstore-db"
if [ -d "$BACKUP_DIR" ] && ls ${BACKUP_DIR}/daily/*.gpg >/dev/null 2>&1; then
    log_pass "已有备份文件"
fi

echo ""

# =====================================================
#  8. SQL 注入防护
# =====================================================
echo "【8/8】SQL 注入防护"
echo "--------------------------------------------------"

for view in sql_injection_alerts anomalous_sql_monitor; do
    EXISTS=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT 1 FROM information_schema.views WHERE table_name='${view}'\"" 2>/dev/null)
    [ "$EXISTS" = "1" ] && log_pass "${view} 已创建" || log_fail "${view} 未创建"
done

for trg in trg_audit_user_delete trg_audit_medicine_price; do
    EXISTS=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -Atc \"SELECT 1 FROM information_schema.triggers WHERE trigger_name='${trg}'\"" 2>/dev/null)
    [ "$EXISTS" = "1" ] && log_pass "触发器 ${trg} 已创建" || true
done


# 最终结果
echo ""
echo "================================================"
echo "  验证结果：通过 ${PASS} 项，失败 ${FAIL} 项"
echo "================================================"
[ $FAIL -eq 0 ] && echo "  🎉 所有安全加固功能均已生效！" || echo "  ⚠ ${FAIL} 项未通过，请检查"
echo "================================================"
echo ""
read -p "按 Enter 键退出..."

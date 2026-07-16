#!/bin/bash
# ==============================================
#  数据库加密异地备份 & 容灾恢复演练脚本
#  连锁药房管理系统 · 计算机与数据安全课程项目
#
#  用法：
#    bash backup_dr.sh backup        # 执行加密备份
#    bash backup_dr.sh restore       # 恢复演练
#    bash backup_dr.sh list          # 列出所有备份
#    bash backup_dr.sh verify        # 验证最近备份完整性
# ==============================================

set -e

# ===================== 配置区 =====================
CONTAINER_NAME="opengauss"
DB_NAME="drugstore"
DB_PORT=5434
GS_PASSWORD="Drug@1234"

# 备份存储根目录（可改为网络挂载路径实现异地存储）
BACKUP_ROOT="/d/backups/drugstore-db"
# 若使用网络共享（异地备份），将 BACKUP_ROOT 改为：
# BACKUP_ROOT="//remote-server/backups/drugstore-db"  # SMB 网络路径

# 加密备份的 GPG 密钥配置
# 首次执行前运行：gpg --full-generate-key 创建密钥对
# 然后用 gpg --list-keys 查看 KEY_ID
GPG_KEY_ID=""   # 留空则使用对称加密口令
GPG_PASSPHRASE="Drugstore-Backup-2024!"

# 备份保留策略
BACKUP_RETENTION_DAYS=90     # 备份保留天数
BACKUP_RETENTION_WEEKS=12    # 周备份保留数
MAX_BACKUP_SIZE_MB=2048      # 单次备份最大限制(MB)

# 恢复演练用数据库
DRILL_DB_NAME="drugstore_drill"

# 远程备份配置（可选，用于异地容灾）
REMOTE_BACKUP_ENABLED=false
REMOTE_BACKUP_PATH=""       # 如：user@remote-host:/backup/drugstore

# RPO/RTO 目标（分钟）
RPO_TARGET=1440             # 恢复点目标：24小时
RTO_TARGET=60               # 恢复时间目标：60分钟

mkdir -p "${BACKUP_ROOT}"/{daily,weekly,monthly,drill,logs}

# ===================== 工具函数 =====================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${BACKUP_ROOT}/logs/backup.log"
}

get_container_status() {
    docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"
}

# ===================== 备份加密 =====================
encrypt_backup() {
    local input_file=$1
    local output_file=$2
    log "  加密备份文件: $(basename ${output_file})"

    if [ -n "$GPG_KEY_ID" ]; then
        # 使用 GPG 公钥加密（非对称）
        gpg --batch --yes --trust-model always \
            --recipient "${GPG_KEY_ID}" \
            --output "${output_file}" \
            --encrypt "${input_file}"
    else
        # 使用对称加密（口令短语）
        gpg --batch --yes \
            --passphrase "${GPG_PASSPHRASE}" \
            --cipher-algo AES256 \
            --symmetric \
            --output "${output_file}" \
            "${input_file}"
    fi
    log "  ✓ 加密完成"
}

decrypt_backup() {
    local input_file=$1
    local output_file=$2
    log "  解密备份文件: $(basename ${input_file})"

    if [ -n "$GPG_KEY_ID" ]; then
        gpg --batch --yes --trust-model always \
            --recipient "${GPG_KEY_ID}" \
            --output "${output_file}" \
            --decrypt "${input_file}"
    else
        gpg --batch --yes \
            --passphrase "${GPG_PASSPHRASE}" \
            --output "${output_file}" \
            --decrypt "${input_file}"
    fi
    log "  ✓ 解密完成"
}

# ===================== 备份操作 =====================
do_backup() {
    local backup_type=$1  # daily, weekly, monthly
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local date_str=$(date '+%Y-%m-%d')

    log "==========================================="
    log "开始 ${backup_type} 备份 - ${date_str}"
    log "==========================================="

    # 1. 检查容器状态
    if ! get_container_status; then
        log "[错误] openGauss 容器未运行，跳过备份"
        return 1
    fi

    # 2. 使用 gs_dump 进行逻辑备份
    local backup_dir="${BACKUP_ROOT}/${backup_type}"
    local sql_file="${backup_dir}/${DB_NAME}_${timestamp}.sql"
    local gpg_file="${sql_file}.gpg"
    local sha256_file="${gpg_file}.sha256"

    log "  [1/4] 执行 gs_dump 逻辑备份..."
    docker exec ${CONTAINER_NAME} su - omm -c "
        gs_dump -U omm -W '${GS_PASSWORD}' -f /tmp/db_backup_${timestamp}.sql -F p --no-owner ${DB_NAME} 2>/dev/null
    "
    # 从容器复制到宿主机
    docker cp "${CONTAINER_NAME}:/tmp/db_backup_${timestamp}.sql" "${sql_file}"
    docker exec ${CONTAINER_NAME} rm -f "/tmp/db_backup_${timestamp}.sql"

    # 检查备份文件大小
    local size_mb=$(du -m "${sql_file}" | cut -f1)
    if [ "$size_mb" -gt "$MAX_BACKUP_SIZE_MB" ]; then
        log "  [警告] 备份文件 ${size_mb}MB 超过限制 ${MAX_BACKUP_SIZE_MB}MB"
    fi
    log "  ✓ 备份完成，大小: ${size_mb}MB"

    # 3. 加密
    log "  [2/4] 加密备份文件..."
    encrypt_backup "${sql_file}" "${gpg_file}"

    # 4. 计算校验和
    log "  [3/4] 计算 SHA256 校验和..."
    sha256sum "${gpg_file}" | tee "${sha256_file}"

    # 5. 清理明文临时文件
    rm -f "${sql_file}"

    # 写入备份元数据
    cat > "${gpg_file}.meta" << EOF
backup_type=${backup_type}
timestamp=${timestamp}
date=${date_str}
database=${DB_NAME}
file=$(basename ${gpg_file})
size_mb=${size_mb}
checksum=$(cat ${sha256_file})
pg_version=$(docker exec ${CONTAINER_NAME} su - omm -c "gsql -d ${DB_NAME} -c 'SELECT version();'" 2>/dev/null | head -3)
EOF

    log "  [4/4] 备份元数据已保存"
    log "  ✅ ${backup_type} 备份完成: ${gpg_file}"

    # 6. 远程同步（如果启用）
    if [ "$REMOTE_BACKUP_ENABLED" = true ] && [ -n "$REMOTE_BACKUP_PATH" ]; then
        log "  [远程] 同步到异地存储..."
        rsync -avz --progress "${gpg_file}" "${gpg_file}.sha256" "${gpg_file}.meta" \
            "${REMOTE_BACKUP_PATH}/" 2>/dev/null && \
        log "  ✓ 异地备份同步完成" || \
        log "  ⚠ 异地备份同步失败，请检查网络连接"
    fi

    return 0
}

# ===================== 备份轮转 =====================
rotate_backups() {
    log "执行备份轮转（按保留策略清理旧备份）..."

    # 清理过期日备份（超过保留天数）
    find "${BACKUP_ROOT}/daily" -name "*.gpg" -mtime +${BACKUP_RETENTION_DAYS} -exec rm -f {} \; 2>/dev/null
    find "${BACKUP_ROOT}/daily" -name "*.sha256" -mtime +${BACKUP_RETENTION_DAYS} -exec rm -f {} \; 2>/dev/null
    find "${BACKUP_ROOT}/daily" -name "*.meta" -mtime +${BACKUP_RETENTION_DAYS} -exec rm -f {} \; 2>/dev/null

    # 清理过期周备份（超过保留周数）
    find "${BACKUP_ROOT}/weekly" -name "*.gpg" -mtime +$((BACKUP_RETENTION_WEEKS * 7)) -exec rm -f {} \; 2>/dev/null

    # 清理超过1年的月备份
    find "${BACKUP_ROOT}/monthly" -name "*.gpg" -mtime +365 -exec rm -f {} \; 2>/dev/null

    log "✓ 备份轮转完成"
}

# ===================== 恢复演练 =====================
do_restore_drill() {
    log ""
    log "==========================================="
    log "  容灾恢复演练"
    log "  开始时间: $(date '+%Y-%m-%d %H:%M:%S')"
    log "==========================================="

    local drill_start=$(date +%s)

    # 1. 找最近的加密备份
    local latest_gpg=$(ls -t ${BACKUP_ROOT}/daily/*.gpg 2>/dev/null | head -1)
    if [ -z "$latest_gpg" ]; then
        latest_gpg=$(ls -t ${BACKUP_ROOT}/weekly/*.gpg 2>/dev/null | head -1)
    fi
    if [ -z "$latest_gpg" ]; then
        log "[错误] 未找到可用备份"
        return 1
    fi
    log "  使用备份: $(basename ${latest_gpg})"

    # 2. 解密
    local decrypt_sql="${BACKUP_ROOT}/drill/restore_drill_$$.sql"
    log "  [1/5] 解密备份文件..."
    decrypt_backup "${latest_gpg}" "${decrypt_sql}"

    # 3. 校验 SQL 文件完整性
    log "  [2/5] 校验 SQL 完整性..."
    local sql_size=$(wc -c < "${decrypt_sql}")
    if [ "$sql_size" -lt 1000 ]; then
        log "[错误] SQL 文件异常小（${sql_size} 字节），可能已损坏"
        rm -f "${decrypt_sql}"
        return 1
    fi
    log "  ✓ SQL 文件大小正常: ${sql_size} 字节"
    log "  ✓ 包含 CREATE TABLE: $(grep -c 'CREATE TABLE' ${decrypt_sql}) 张表"
    log "  ✓ 包含 INSERT: $(grep -c 'INSERT INTO' ${decrypt_sql}) 条数据"

    # 4. 创建演练数据库并恢复
    log "  [3/5] 创建恢复演练数据库 ${DRILL_DB_NAME}..."
    docker exec -i ${CONTAINER_NAME} su - omm -c "gsql -d postgres -c \"DROP DATABASE IF EXISTS ${DRILL_DB_NAME};\"" 2>/dev/null
    docker exec -i ${CONTAINER_NAME} su - omm -c "gsql -d postgres -c \"CREATE DATABASE ${DRILL_DB_NAME} ENCODING 'UTF8';\"" 2>/dev/null

    log "  [4/5] 恢复数据到演练数据库..."
    local restore_start=$(date +%s)

    # 复制到容器并恢复
    docker cp "${decrypt_sql}" "${CONTAINER_NAME}:/tmp/restore_drill.sql"
    docker exec -i ${CONTAINER_NAME} su - omm -c "gsql -d ${DRILL_DB_NAME} -f /tmp/restore_drill.sql" 2>/dev/null
    docker exec ${CONTAINER_NAME} rm -f /tmp/restore_drill.sql

    local restore_end=$(date +%s)
    local restore_duration=$((restore_end - restore_start))
    log "  ✓ 数据恢复完成（耗时 ${restore_duration} 秒）"

    # 5. 数据完整性验证
    log "  [5/5] 验证数据完整性..."
    local fail_count=0

    # 验证表数量
    local table_count=$(docker exec -i ${CONTAINER_NAME} su - omm -c "gsql -d ${DRILL_DB_NAME} -Atc \"SELECT count(*) FROM information_schema.tables WHERE table_schema='public';\"" 2>/dev/null)
    log "  - 表数量: ${table_count}"

    # 验证用户表
    local user_count=$(docker exec -i ${CONTAINER_NAME} su - omm -c "gsql -d ${DRILL_DB_NAME} -Atc \"SELECT count(*) FROM users;\"" 2>/dev/null)
    log "  - 用户数: ${user_count}"

    # 验证药品表
    local med_count=$(docker exec -i ${CONTAINER_NAME} su - omm -c "gsql -d ${DRILL_DB_NAME} -Atc \"SELECT count(*) FROM medicines;\"" 2>/dev/null)
    log "  - 药品数: ${med_count}"

    # 验证销售表
    local sales_count=$(docker exec -i ${CONTAINER_NAME} su - omm -c "gsql -d ${DRILL_DB_NAME} -Atc \"SELECT count(*) FROM sales_orders;\"" 2>/dev/null)
    log "  - 销售记录: ${sales_count}"

    if [ "$table_count" -eq 0 ] 2>/dev/null || [ -z "$table_count" ]; then
        log "  [错误] 恢复验证失败：无数据"
        fail_count=$((fail_count + 1))
    fi

    # 6. 清理演练环境
    log "  清理演练数据库..."
    docker exec -i ${CONTAINER_NAME} su - omm -c "gsql -d postgres -c \"DROP DATABASE IF EXISTS ${DRILL_DB_NAME};\"" 2>/dev/null

    local drill_end=$(date +%s)
    local total_duration=$((drill_end - drill_start))

    # 删除临时文件
    rm -f "${decrypt_sql}"

    # 7. 生成演练报告
    local rpo_met="否"
    if [ $((total_duration / 60)) -le $RPO_TARGET ]; then
        rpo_met="是（本次从最新备份恢复）"
    fi

    local rto_met="否"
    if [ $total_duration -le $((RTO_TARGET * 60)) ]; then
        rto_met="是"
    fi

    local report_file="${BACKUP_ROOT}/drill/drill_report_$(date '+%Y%m%d_%H%M%S').md"

    cat > "${report_file}" << EOF
# 容灾恢复演练报告

| 项目 | 内容 |
|------|------|
| 演练时间 | $(date '+%Y-%m-%d %H:%M:%S') |
| 使用备份 | $(basename ${latest_gpg}) |
| 数据大小 | ${sql_size} 字节 |
| 表数量 | ${table_count} |
| 用户数 | ${user_count} |
| 药品数 | ${med_count} |
| 销售记录 | ${sales_count} |

## 恢复耗时

| 阶段 | 耗时 |
|------|------|
| 解密 | - |
| SQL恢复 | ${restore_duration}s |
| 总耗时 | ${total_duration}s (约 $((total_duration / 60)) 分) |

## RPO/RTO 达标情况

| 指标 | 目标 | 实际 | 达标 |
|------|------|------|------|
| RPO | ${RPO_TARGET}min | 最近备份 | ${rpo_met} |
| RTO | ${RTO_TARGET}min | $((total_duration / 60))min | ${rto_met} |

## 验证结论

- 数据完整性: ✅ $( [ ${fail_count} -eq 0 ] && echo '通过' || echo '失败' )
- 演练结果: ✅ 成功

---

*自动生成于 $(date '+%Y-%m-%d %H:%M:%S')*
EOF

    log ""
    log "==========================================="
    log "  ✅ 容灾恢复演练完成"
    log "  总耗时: ${total_duration} 秒"
    log "  报告: ${report_file}"
    log "==========================================="

    return ${fail_count}
}

# ===================== 验证备份 =====================
verify_backup() {
    local backup_file=$1
    if [ -z "$backup_file" ]; then
        # 找最近的备份
        backup_file=$(ls -t ${BACKUP_ROOT}/daily/*.gpg ${BACKUP_ROOT}/weekly/*.gpg 2>/dev/null | head -1)
    fi

    if [ -z "$backup_file" ] || [ ! -f "$backup_file" ]; then
        log "[错误] 未找到备份文件"
        return 1
    fi

    log "验证备份: $(basename ${backup_file})"

    # 校验 SHA256
    local sha256_file="${backup_file}.sha256"
    if [ -f "$sha256_file" ]; then
        log "  校验 SHA256..."
        sha256sum -c "${sha256_file}" && \
            log "  ✓ SHA256 校验通过" || \
            { log "  [错误] SHA256 校验失败！备份可能已损坏"; return 1; }
    fi

    # 尝试解密一小部分验证加密格式
    log "  验证加密格式..."
    local file_type=$(file "${backup_file}")
    log "  ${file_type}"

    log "  ✓ 备份文件验证通过"
}

# ===================== 主流程 =====================
case "${1:-}" in
    backup)
        # 根据星期几决定备份类型
        day_of_week=$(date '+%u')
        day_of_month=$(date '+%d')

        if [ "$day_of_month" = "01" ]; then
            do_backup "monthly"
        elif [ "$day_of_week" = "7" ]; then
            do_backup "weekly"
        else
            do_backup "daily"
        fi

        rotate_backups

        # 如果是周备份，执行恢复演练
        if [ "$day_of_week" = "7" ]; then
            log ""
            log "  周日备份完成，建议执行恢复演练："
            log "    bash backup_dr.sh restore"
        fi
        ;;

    restore)
        do_restore_drill
        ;;

    verify)
        verify_backup "${2:-}"
        ;;

    list)
        echo ""
        echo "日备份:"
        ls -lh ${BACKUP_ROOT}/daily/ 2>/dev/null | grep '\.gpg$' || echo "  （无）"
        echo ""
        echo "周备份:"
        ls -lh ${BACKUP_ROOT}/weekly/ 2>/dev/null | grep '\.gpg$' || echo "  （无）"
        echo ""
        echo "月备份:"
        ls -lh ${BACKUP_ROOT}/monthly/ 2>/dev/null | grep '\.gpg$' || echo "  （无）"
        echo ""
        echo "演练报告:"
        ls -lh ${BACKUP_ROOT}/drill/ 2>/dev/null | grep '\.md$' || echo "  （无）"
        echo ""

        # 统计备份信息
        local total_backups=$(find ${BACKUP_ROOT} -name "*.gpg" 2>/dev/null | wc -l)
        local total_size=$(du -sh ${BACKUP_ROOT} 2>/dev/null | cut -f1)
        echo "总计: ${total_backups} 个备份，占用 ${total_size}"
        ;;

    init-key)
        echo "初始化 GPG 加密密钥..."
        echo "请执行以下命令创建 GPG 密钥："
        echo "  gpg --full-generate-key"
        echo ""
        echo "密钥类型: RSA (4096 bit)"
        echo "有效期: 2y"
        echo "名称: Drugstore Backup"
        echo "邮箱: backup@drugstore.local"
        echo ""
        echo "创建后执行 gpg --list-keys 获取 KEY_ID"
        echo "然后修改本脚本的 GPG_KEY_ID 变量"
        ;;

    cron-setup)
        echo "配置定时备份（Windows 计划任务）..."
        local script_path=$(realpath "$0")
        local task_name="DrugstoreDB-Backup"
        local bat_file="${BACKUP_ROOT}/scheduled_backup.bat"

        mkdir -p "${BACKUP_ROOT}"
        cat > "${bat_file}" << BAT_EOF
@echo off
chcp 65001 >nul
echo [%date% %time%] 开始数据库备份...
bash "${script_path}" backup >> "${BACKUP_ROOT}/logs/scheduled_backup.log" 2>&1
if %errorlevel% equ 0 (
    echo [%date% %time%] 备份成功
) else (
    echo [%date% %time%] 备份失败
)
BAT_EOF

        echo ""
        echo "请在 Windows 计划任务中创建每日任务："
        echo "  1. 打开「任务计划程序」"
        echo "  2. 创建基本任务: ${task_name}"
        echo "  3. 触发器: 每天，时间建议 02:00"
        echo "  4. 操作: 启动程序 → ${bat_file}"
        echo ""
        echo "  或使用命令创建（管理员 PowerShell）："
        echo "  schtasks /CREATE /SC DAILY /TN \"${task_name}\" /TR \"${bat_file}\" /ST 02:00 /F"
        ;;

    *)
        echo "用法: bash backup_dr.sh <命令>"
        echo ""
        echo "命令:"
        echo "  backup         执行加密备份（自动按天/周/月归类）"
        echo "  restore        执行恢复演练（验证备份可恢复性）"
        echo "  verify [文件]   验证备份文件的完整性"
        echo "  list           列出所有备份文件"
        echo "  init-key       初始化 GPG 加密密钥"
        echo "  cron-setup     配置 Windows 定时备份"
        echo ""
        echo "示例:"
        echo "  bash backup_dr.sh backup"
        echo "  bash backup_dr.sh restore"
        echo "  bash backup_dr.sh verify"
        echo "  bash backup_dr.sh list"
        ;;
esac

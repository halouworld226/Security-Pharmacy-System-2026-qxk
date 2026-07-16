# ==============================================
#  Windows 防火墙 IP 白名单配置脚本
#  连锁药房管理系统 · 数据库端口安全
#  限制 5434 端口仅允许指定 IP 访问
#
#  用法：以管理员身份运行 PowerShell：
#    powershell -ExecutionPolicy Bypass -File windows_firewall.ps1
# ==============================================

# 必须用管理员权限运行
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[错误] 请以管理员身份运行此脚本！" -ForegroundColor Red
    Write-Host "右键 → 以管理员身份运行" -ForegroundColor Yellow
    exit 1
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Windows 防火墙规则配置" -ForegroundColor Cyan
Write-Host "  连锁药房管理系统 · 数据库端口安全" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# ===================== 配置区 =====================

# 数据库端口
$DB_PORT = 5434

# 规则名称前缀
$RULE_NAME_PREFIX = "Drugstore-DB"

# ===== IP 白名单配置 =====
# 在此处添加允许访问数据库的 IP 地址
# 支持格式：单个IP、CIDR、IP段
$ALLOWED_IPS = @(
    "127.0.0.1",           # 本机应用
    "::1",                  # 本机 IPv6
    "192.168.0.0/16",       # 内网网段（按需调整）
    "10.0.0.0/8",           # 企业内网（按需调整）
    "172.16.0.0/12",        # Docker 默认网段
    "172.28.0.0/24"         # 自定义 Docker 网段
)

# 白名单例外：始终阻止的已知恶意 IP
$BLOCKED_IPS = @(
    "0.0.0.0/0",            # 默认阻止所有（白名单之外的都会被拒绝）
)

# ===================== 清理旧规则 =====================
Write-Host "[1/4] 清理旧的防火墙规则..." -ForegroundColor Yellow
$oldRules = netsh advfirewall firewall show rule name="${RULE_NAME_PREFIX}*" 2>$null
if ($oldRules) {
    netsh advfirewall firewall delete rule name="${RULE_NAME_PREFIX}-Allow-IP" > $null 2>&1
    netsh advfirewall firewall delete rule name="${RULE_NAME_PREFIX}-Block-All" > $null 2>&1
    Write-Host "  ✓ 旧规则已清理" -ForegroundColor Green
} else {
    Write-Host "  - 无旧规则需要清理" -ForegroundColor Gray
}

# ===================== 创建放行规则 =====================
Write-Host "[2/4] 创建 IP 白名单放行规则..." -ForegroundColor Yellow
$allowedCount = 0
foreach ($ip in $ALLOWED_IPS) {
    $localPorts = "$DB_PORT"

    netsh advfirewall firewall add rule `
        name="${RULE_NAME_PREFIX}-Allow-IP" `
        dir=in `
        action=allow `
        protocol=TCP `
        localport=$localPorts `
        remoteip=$ip `
        description="放行白名单 IP ${ip} 访问数据库端口 ${DB_PORT}" > $null 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ 放行: $ip" -ForegroundColor Green
        $allowedCount++
    } else {
        Write-Host "  ✗ 失败: $ip" -ForegroundColor Red
    }
}
Write-Host "  ✓ 已添加 $allowedCount 条放行规则" -ForegroundColor Green

# ===================== 创建阻止规则 =====================
Write-Host "[3/4] 创建默认阻止规则..." -ForegroundColor Yellow
# 在放行规则之后再添加默认阻止规则（Windows 防火墙优先级：按规则顺序匹配）
netsh advfirewall firewall add rule `
    name="${RULE_NAME_PREFIX}-Block-All" `
    dir=in `
    action=block `
    protocol=TCP `
    localport=$DB_PORT `
    description="阻止所有非白名单 IP 访问数据库端口" > $null 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ 默认阻止规则已创建（非白名单 IP 将被拒绝）" -ForegroundColor Green
} else {
    Write-Host "  ✗ 阻止规则创建失败" -ForegroundColor Red
}

# ===================== 显示状态 =====================
Write-Host "[4/4] 防火墙规则状态..." -ForegroundColor Yellow
Write-Host ""
Write-Host "当前数据库防火墙规则：" -ForegroundColor Cyan
netsh advfirewall firewall show rule name="${RULE_NAME_PREFIX}*" 2>$null | Select-String "规则名称|操作|协议|本地端口|远程 IP|允许|阻止"

# ===================== 验证 =====================
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  ✅ 防火墙规则配置完成！" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "规则摘要：" -ForegroundColor White
Write-Host "  端口: $DB_PORT (TCP)"
Write-Host "  放行 IP: $($ALLOWED_IPS.Count) 个地址/网段"
Write-Host "  默认策略: 阻止所有未授权的入站连接"
Write-Host ""
Write-Host "测试方法：" -ForegroundColor Yellow
Write-Host "  查看规则列表:" -ForegroundColor Gray
Write-Host "    netsh advfirewall firewall show rule name='${RULE_NAME_PREFIX}*'" -ForegroundColor Gray
Write-Host ""
Write-Host "  从另一台机器测试连接（应被阻止）:" -ForegroundColor Gray
Write-Host "    telnet <服务器IP> ${DB_PORT}" -ForegroundColor Gray
Write-Host ""
Write-Host "  从本机测试（应可连接）:" -ForegroundColor Gray
Write-Host "    python -c \"import psycopg2; conn=psycopg2.connect(host='localhost',port=${DB_PORT},user='druguser',password='Drug@1234',dbname='drugstore'); print('连接成功')\"" -ForegroundColor Gray
Write-Host ""
Write-Host "如需添加更多白名单 IP，请编辑此脚本的 `$ALLOWED_IPS 数组后重新运行。" -ForegroundColor Yellow
Write-Host "注意：请确保部署应用的服务器的 IP 已添加到白名单中！" -ForegroundColor Yellow

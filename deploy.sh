#!/bin/bash

# ==============================================
#  药房管理系统 - openGauss Docker 一键部署
#  用法：bash deploy.sh
#  请确保：Docker 已安装并正常运行，同目录下有 init_merged.sql
# ==============================================

set -e

# ---- 配置区 ----
IMAGE="enmotech/opengauss:3.1.0"
CONTAINER_NAME="opengauss"
DB_PORT=5434
CONTAINER_PORT=5432
GS_PASSWORD="Drug@1234"
DB_NAME="drugstore"
DB_USER="druguser"
DB_PASSWORD="Drug@1234"

echo "==============================================="
echo "  药房管理系统 - openGauss 一键部署"
echo "==============================================="
echo ""

# 1. 检查 Docker
echo "[1/5] 检查 Docker..."
docker --version >/dev/null 2>&1 || {
    echo "[错误] Docker 未安装或未启动"
    exit 1
}
echo "  Docker 可用"

# 2. 拉取镜像
echo "[2/5] 拉取 openGauss 镜像..."
docker pull $IMAGE || {
    echo "[错误] 拉取镜像失败"
    exit 1
}

# 3. 清理旧容器并启动
echo "[3/5] 启动 openGauss 容器..."
docker rm -f $CONTAINER_NAME 2>/dev/null || true

docker run -d \
  --name $CONTAINER_NAME \
  -e GS_PASSWORD=$GS_PASSWORD \
  -p $DB_PORT:$CONTAINER_PORT \
  $IMAGE || {
    echo "[错误] 容器启动失败，请检查端口 $DB_PORT 是否被占用"
    exit 1
}

echo "  等待数据库初始化（约 30 秒）..."
sleep 30

# 4. 复制 SQL 到容器
echo "[4/5] 复制 init_merged.sql 到容器..."
docker cp init_merged.sql $CONTAINER_NAME:/tmp/init_merged.sql || {
    echo "[错误] 复制失败，请确保当前目录下有 init_merged.sql"
    exit 1
}

# 5. 执行数据库初始化
echo "[5/5] 执行数据库初始化..."
docker exec -i $CONTAINER_NAME bash <<'DOCKER_EOF'
set -e

# 创建数据库
su - omm -c "gsql -d postgres -c \"CREATE DATABASE drugstore ENCODING 'UTF8';\"" 2>/dev/null || true

# 授权
cat > /tmp/grant.sql <<'EOF_SQL'
CREATE USER druguser WITH PASSWORD 'Drug@1234';
GRANT USAGE ON SCHEMA public TO druguser;
GRANT ALL PRIVILEGES ON DATABASE drugstore TO druguser;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO druguser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO druguser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO druguser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO druguser;
EOF_SQL

su - omm -c "gsql -d drugstore -f /tmp/grant.sql"

# 导入表结构和数据
su - omm -c "gsql -d drugstore -f /tmp/init_merged.sql"

echo "  数据库初始化完成"
DOCKER_EOF

if [ $? -eq 0 ]; then
    echo ""
    echo "==============================================="
    echo "  部署成功！"
    echo ""
    echo "  连接信息："
    echo "    主机:    localhost"
    echo "    端口:    $DB_PORT"
    echo "    用户:    $DB_USER"
    echo "    密码:    $DB_PASSWORD"
    echo "    库名:    $DB_NAME"
    echo ""
    echo "  现在可以执行: python app.py 或双击 start.bat"
    echo "==============================================="
else
    echo "[错误] 初始化失败"
    exit 1
fi

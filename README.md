# 🏥 安全增强型连锁药房管理系统

> 基于 Flask + openGauss 的药房管理平台 

[![Python](https://img.shields.io/badge/Python-3.10-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)](https://flask.palletsprojects.com/)
[![openGauss](https://img.shields.io/badge/openGauss-3.0-red.svg)](https://opengauss.org/)
[![Docker](https://img.shields.io/badge/Docker-✅-blue.svg)](https://www.docker.com/)

---

## 📖 项目简介

本项目是一个面向连锁药店业务场景的**安全优先（Security-by-Design）**管理平台。系统在实现完整进销存业务（采购、销售、退货、调拨）的基础上，深度集成了多层安全防御机制。

**核心安全特性：**

- scrypt 密码哈希 + 图形验证码 + 登录失败锁定（5次/5分钟）
- 服务端会话 + 空闲超时（30分钟）+ 单设备登录互斥
- RBAC 三级权限（管理员/店长/店员）+ 数据行级隔离
- 全量参数化查询（防SQL注入）+ CSRF Token + 安全响应头（CSP/HSTS）
- 全操作审计日志（IP/UA/修改前后JSON）+ 安全监控仪表盘
- AES-256 字段级加密（手机号）+ SSL/TLS 传输加密

---

## 🚀 5分钟快速开始

### 前置条件
- [Docker Desktop](https://www.docker.com/products/docker-desktop/)

### 一键启动

```bash
# 1. 克隆项目
git clone https://github.com/halouworld226/Security-Pharmacy-System-2026-qxk.git
cd Security-Pharmacy-System

# 2. 启动所有服务（数据库 + Web 应用）
docker-compose up -d

# 3. 等待数据库初始化完成（约 30-60 秒）

# 4. 浏览器访问
# http://localhost:5000

## 📌 注意事项
#系统内置的示例数据截止至 **2026年6月**。如遇到图表无数据展示，属正常现象——只需在系统中录入销售数据即可实时生成可视化图表

## 👥 团队贡献
#本项目由以下成员共同完成：
- 裘轩恺
- 张尚明珠  
- 徐延颢
- 张宸瑜

#📄 许可证

本项目仅供学习交流使用。

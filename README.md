<img width="1085" height="595" alt="image" src="https://github.com/user-attachments/assets/d5ff090d-b87c-421f-941d-e53362f16bba" />


# EasyTodo 简单易用的个人待办列表

一个基于 Flask + SQLite 的轻量待办应用，开箱即用，支持暗黑模式、拖拽排序与账号数据清除。

## 快速开始（Docker）

- 拉取镜像：
  
  ```bash
  docker pull ghcr.io/essesoul/easytodo:latest
  ```

- 准备本地数据库目录（用于持久化）：
  
  ```bash
  mkdir -p ./database
  ```

- 运行容器（映射端口、设置密钥并挂载数据库目录）：
  
  ```bash
  docker run --name easytodo --rm \
    -p 5000:5000 \
    -e SECRET_KEY=$(openssl rand -hex 32) \
    -e AUTH_COOKIE_SECURE=false \
    -v $(pwd)/database:/app/database \
    ghcr.io/essesoul/easytodo:latest
  ```

- 打开浏览器访问：`http://localhost:5000`

## 本地构建与运行

- 构建（不使用缓存）：

  ```bash
  docker build --no-cache -t easytodo:local .
  ```

- 运行：

  ```bash
  mkdir -p ./database
  docker run --name easytodo --rm \
    -p 5000:5000 \
    -e SECRET_KEY=$(openssl rand -hex 32) \
    -e AUTH_COOKIE_SECURE=false \
    -v $(pwd)/database:/app/database \
    easytodo:local
  ```

## 环境变量

| 变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `SECRET_KEY` | 是 | - | 生产环境请使用足够随机的值；未显式设置 `JWT_SECRET` 时也用于签名 JWT |
| `SESSION_COOKIE_SECURE` | 否 | `false` | 在 HTTPS 环境下设为 `true`；仅用于 Flask 会话（用于 CSRF 与找回密码挑战） |
| `JWT_SECRET` | 否 | - | JWT 签名密钥；未设置时回退到 `SECRET_KEY` |
| `JWT_TTL_SECONDS` | 否 | `604800`（7 天） | 访问令牌有效期 |
| `AUTH_COOKIE_NAME` | 否 | `access_token` | 认证 Cookie 名称 |
| `AUTH_COOKIE_SECURE` | 否 | - | 设置为 `true` 以在 HTTPS 下仅通过安全通道发送认证 Cookie（生产环境推荐开启） |
| `AUTH_COOKIE_SAMESITE` | 否 | `Strict` | 减少 CSRF 风险 |
| `AUTH_COOKIE_DOMAIN` | 否 | - | 认证 Cookie 的作用域域名 |

## 认证方式（JWT）

- 登录/注册成功后，后端签发 JWT 并通过 `HttpOnly` Cookie 下发（默认名 `access_token`）。
- 所有需要身份的接口通过该 Cookie 校验，无需在前端存储令牌或增加 `Authorization` 头。
- 写操作接口同时要求 `X-CSRF-Token` 头，且值需与服务器会话中保存的 CSRF Token 一致（前端由页面 `<meta name="csrf-token">` 注入并自动携带）。
- 退出登录会清除 JWT Cookie 与会话。

## 安全性说明（XSS/CSRF）

- 启用基础安全响应头（CSP、X-Content-Type-Options、X-Frame-Options、Referrer-Policy）。
- CSRF 采用“双提交”风格：认证使用 `HttpOnly` Cookie，写接口必须带 `X-CSRF-Token` 头且与后端会话中的 Token 匹配。
- 前端对用户可控内容（如待办文本）做了转义；模板默认开启 Jinja2 自动转义。
- 生产环境请：
  - 通过 HTTPS 部署并设置 `AUTH_COOKIE_SECURE=true`、`SESSION_COOKIE_SECURE=true`。
  - 设置强随机的 `SECRET_KEY`（或单独配置 `JWT_SECRET`）。

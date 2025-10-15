# EasyNote 简单易用的个人待办列表

一个使用 Flask + SQLite 的简单待办应用。

## 功能

- 顶部胶囊输入框添加待办
- 列表可拖动排序（移动端长按后拖动）
- 勾选完成有灰色 + 删除线效果
- 一键清除已完成任务
- 本地优先：本地存储，改动自动同步至服务器；可手动保存
- GitHub 风格的简洁样式
- 暗黑模式：跟随系统并可手动切换
- 账号一键删除（连同所有数据）

## 目录结构

```
backend/     # Flask + SQLite API
backend/static/      # 前端静态资源（CSS、图标）
backend/templates/   # Jinja2 页面模板
```


## 本地运行

1. 启动（Flask）

```
cd backend
python3 -m venv .venv
source .venv/bin/activate  # Windows 使用 .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

访问 http://localhost:5000

## 部署建议

同源部署（推荐）：由 Flask 同时提供页面与 API。

环境变量：
- `SECRET_KEY`（生产环境必配，使用足够随机的值）
- `SESSION_COOKIE_SECURE=true`（在 HTTPS 下）

## Docker 与自动发布

本仓库已包含用于多平台镜像构建与发布的 GitHub Actions 工作流：

- 工作流文件：`.github/workflows/docker.yml`
- 目标仓库：GitHub Container Registry（GHCR）`ghcr.io/<owner>/<repo>`
- 触发：推送到 `main/master`、推送符合 `v*.*.*` 的 tag、PR（仅构建不推送）
- 平台：`linux/amd64`、`linux/arm64`

使用步骤：
- 确保仓库可使用默认的 `GITHUB_TOKEN`（已在工作流中设置 `packages: write` 权限）。
- 合并到 `main` 后会自动推送 `latest` 与分支/版本对应的 tag。

本地构建与运行：

```
docker build -t easynote:local .
docker run --rm -p 5000:5000 -e SECRET_KEY=$(openssl rand -hex 32) easynote:local
```

使用已发布镜像（示例）：

```
docker run --rm -p 5000:5000 \
  -e SECRET_KEY=$(openssl rand -hex 32) \
  ghcr.io/<owner>/<repo>:latest
```

如果希望推送到 Docker Hub：
- 在仓库设置中添加 `DOCKERHUB_USERNAME` 与 `DOCKERHUB_TOKEN`（访问令牌）。
- 参见工作流内注释，替换登录步骤及镜像名称为 `your-namespace/easynote`。

## API 概览（简）

- `GET /api/csrf` 获取 CSRF token（会话内）
- `POST /api/auth/register {email, password}`
- `POST /api/auth/login {email, password}`
- `POST /api/auth/logout`
- `DELETE /api/auth/delete_account`
- `GET /api/todos` 列出
- `POST /api/todos {text}` 新建
- `PUT /api/todos/:id {text?, completed?, position?}` 更新
- `POST /api/todos/reorder {order: number[]}` 重排
- `DELETE /api/todos/completed` 删除已完成
- `POST /api/todos/bulk_upsert {todos}` 手动同步

## 安全说明

- 使用带 HttpOnly、SameSite=Lax 的会话 Cookie（同源）。
- JSON 写操作要求 `X-CSRF-Token`，模板中以 meta 注入并随会话生成；也可从 `/api/csrf` 获取。
- 密码使用 Werkzeug `generate_password_hash` 存储，登录校验使用 `check_password_hash`。
- 删除账号会级联删除该用户全部待办数据。

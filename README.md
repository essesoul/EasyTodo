# EasyNote 简单易用的个人待办列表

一个基于 Flask + SQLite 的轻量待办应用，开箱即用，支持暗黑模式、拖拽排序与账号数据清除。

## 快速开始（Docker）

- 拉取镜像：
  
  ```bash
  docker pull ghcr.io/essesoul/easynote:latest
  ```

- 准备本地数据库文件（用于持久化）：
  
  ```bash
  mkdir -p ./data && touch ./data/app.db
  ```

- 运行容器（映射端口、设置密钥并挂载数据库文件）：
  
  ```bash
  docker run --name easynote --rm \
    -p 5000:5000 \
    -e SECRET_KEY=$(openssl rand -hex 32) \
    -v $(pwd)/data/app.db:/app/app.db \
    ghcr.io/essesoul/easynote:latest
  ```

- 打开浏览器访问：`http://localhost:5000`

## 环境变量

- `SECRET_KEY`: 必填，生产环境请使用足够随机的值。
- `SESSION_COOKIE_SECURE`: 在 HTTPS 环境下设为 `true`（默认 `false`）。

# =============================================================================
# Vuln-Research-MCP v5.2 — 一键部署镜像 (小白友好)
# 
# 构建: docker build -t vuln-research-mcp .
# 运行: docker compose up -d
# =============================================================================

FROM kalilinux/kali-rolling:latest

LABEL maintainer="vuln-research-mcp"
LABEL description="Vulnerability Research MCP Server v5.2 — 企业级安全平台 (Web UI + REST API + MCP)"
LABEL version="5.2.0"

# ----- 时区 & 基础工具 -----
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python 运行时
    python3 python3-pip python3-venv python3-dev \
    # 安全工具
    nmap nuclei git exploitdb sublist3r amass \
    # Web UI 依赖
    curl wget ca-certificates \
    # 工具
    jq dnsutils whois \
    # 清理
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && nuclei -update-templates 2>/dev/null || true

# ----- 工作目录 -----
WORKDIR /app

# ----- 先复制依赖文件 (利用 Docker 缓存层) -----
COPY pyproject.toml README.md ./

# ----- 安装 Python 依赖 -----
RUN pip3 install --no-cache-dir --break-system-packages \
    mcp httpx dnspython diskcache PyYAML networkx rich \
    fastapi uvicorn pydantic jinja2 python-multipart aiofiles

# ----- 复制源码 -----
COPY src/ ./src/
COPY config.example.yaml ./config.yaml

# ----- 创建数据目录 -----
RUN mkdir -p /app/data/cache /app/data/db /app/data/reports /app/data/logs

# ----- 环境变量 -----
ENV NVD_API_KEY=""
ENV LOG_LEVEL="INFO"
ENV CACHE_ENABLED="true"
ENV PYTHONUNBUFFERED=1

# ----- 暴露端口 -----
# 8080: Web UI
# 8765: REST API
EXPOSE 8080 8765

# ----- 健康检查 -----
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=30s \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# ----- 启动入口: Web UI + REST API 双服务 -----
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]

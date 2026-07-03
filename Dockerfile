FROM kalilinux/kali-rolling:latest

LABEL maintainer="vuln-research-mcp"
LABEL description="Vulnerability Research MCP Server - Security Intelligence Workstation"

# 安装系统工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    exploitdb \
    sublist3r \
    amass \
    nuclei \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && nuclei -update-templates

# 创建工作目录
WORKDIR /app

# 复制项目文件
COPY . /app/

# 安装 Python 依赖
RUN pip3 install --no-cache-dir --break-system-packages .

# 创建配置目录
RUN mkdir -p /root/.vuln-research-mcp/cache

# 环境变量
ENV NVD_API_KEY=""
ENV LOG_LEVEL="INFO"
ENV LOG_FORMAT="text"
ENV CACHE_ENABLED="true"

# 入口
ENTRYPOINT ["python3", "-m", "src.server"]

# 健康检查（通过 Python 自检）
HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python3 -c "import src.server; print('ok')" || exit 1

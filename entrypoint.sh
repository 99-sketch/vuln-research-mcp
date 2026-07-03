#!/bin/bash
# =============================================================================
# Vuln-Research-MCP v5.2 启动脚本
# 同时启动 Web UI (7879) 和 REST API (8765)
# =============================================================================

set -e

echo "============================================"
echo "  Vuln-Research-MCP v5.2"
echo "  Enterprise Security Platform"
echo "============================================"
echo ""
echo "  Web UI:   http://localhost:7879"
echo "  REST API: http://localhost:8765/docs"
echo "  MCP:      stdio (via docker exec)"
echo ""

# 启动 REST API (后台)
echo "[*] Starting REST API on :8765..."
python3 -m src.webui.api_server &
API_PID=$!
sleep 2

# 启动 Web UI (前台)
echo "[*] Starting Web UI on :7879..."
python3 -m src.webui.app

# 如果 Web UI 退出, 清理 API 进程
kill $API_PID 2>/dev/null || true

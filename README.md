# 一键安装
在安装前请确保你的系统支持`bash`环境,且系统网络正常  


# 配置要求  
## 内存  
- 128MB minimal/256MB+ recommend  
## OS  
- Ubuntu 22-24



# TUIC+UDP+QUIC+TLS.sh搭建协议
```
bash <(curl -Ls https://raw.githubusercontent.com/Firefly-xui/TUIC/master/TUIC+UDP+QUIC+TLS.sh)
```  

0-RTT 握手：支持零延迟连接建立，显著提升首次连接速度

QUIC 传输层：基于 UDP 构建，避免 TCP 的队头阻塞问题，实现多路复用和快速恢复

用户态拥塞控制：支持 BBR、CUBIC 等算法，灵活调节带宽与延迟

原生 UDP 转发：支持 Full Cone NAT，兼容性强，适用于游戏、VoIP 等场景

支持 UDP 分片与重组：可处理超过 MTU 的大包，提升稳定性

适用场景：

长期开通的公网节点；

追求低延迟流媒体服务；

单连接承载多任务，节省资源


# 客户端配置

window配置V2rayN

V2rayN客户端下载[V2rayN](https://github.com/Firefly-xui/3x-ui/releases/download/3x-ui/v2rayN-windows-64.zip)。


| 协议组合                            | 抗封锁   | 延迟    | 稳定性   | 部署复杂度 | 适用建议       |
| ------------------------------- | ----- | ----- | ----- | ----- | ---------- |
| Hysteria2 + UDP + TLS + Obfs    | ★★★☆☆ | ★★★★★ | ★★★☆☆ | ★★☆☆☆ | 流媒体 / 备用   |
| TUIC + UDP + QUIC + TLS         | ★★★★☆ | ★★★★★ | ★★★★☆ | ★★★★★ | 游戏 / 多任务场景 |
| VLESS + Reality + uTLS + Vision | ★★★★★ | ★★★☆☆ | ★★★★☆ | ★☆☆☆☆ | 配置简单安全可靠     |


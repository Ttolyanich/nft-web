#!/usr/bin/env bash
# ==============================================================================
# NFT-GW Web Manager & Gateway Automated Installer
# Target OS: Debian 11/12, Ubuntu 22.04/24.04
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}       NFTables Gateway & Web Manager Installer       ${NC}"
echo -e "${BLUE}======================================================${NC}"

# 1. Root check
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Пожалуйста, запустите установщик от имени root (sudo).${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 2. Интерактивный запрос пароля для веб-интерфейса
echo -e "\n${YELLOW}Безопасность доступа к веб-панели:${NC}"
read -r -s -p "Задайте пароль администратора (Enter для автогенерации): " INPUT_PASS
echo ""

if [ -z "${INPUT_PASS}" ]; then
    ADMIN_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12 || echo "PveAdmin1234")
    echo -e "${BLUE}i Сгенерирован случайный надежный пароль.${NC}"
else
    ADMIN_PASS="${INPUT_PASS}"
fi

# Порт по умолчанию: 8443
WEB_PORT="8443"

# 3. Sysctl Gateway Optimization (IP Forwarding)
echo -e "\n${YELLOW}[1/6] Настройка sysctl (включение IP forwarding)...${NC}"
cat << 'EOF' > /etc/sysctl.d/99-gateway.conf
# Включение маршрутизации трафика (роутер / шлюз)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 0

# Защита от ICMP redirect атак
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Игнорировать ложные broadcast ping
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Защита от SYN Flood
net.ipv4.tcp_syncookies = 1
EOF

sysctl --system > /dev/null
echo -e "${GREEN}✓ IP Forwarding успешно включен в /etc/sysctl.d/99-gateway.conf${NC}"

# 4. Установка пакетов
echo -e "\n${YELLOW}[2/6] Проверка и установка системных пакетов (nftables, fail2ban, curl, golang)...${NC}"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables fail2ban curl iproute2 golang-go > /dev/null
echo -e "${GREEN}✓ Системные пакеты установлены.${NC}"

# 5. Настройка Fail2ban с нативным бэкендом nftables
echo -e "\n${YELLOW}[3/6] Настройка Fail2ban (banaction = nftables)...${NC}"
cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
# Использовать нативный nftables для бана в ядре
banaction = nftables-multiport
banaction_allports = nftables-allports

# Игнорировать локальные приватные сети
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

# Время бана: 1 час, окно детекции: 10 минут, попыток: 5
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
mode = aggressive
EOF

systemctl enable --now fail2ban
echo -e "${GREEN}✓ Fail2ban успешно настроен и активирован.${NC}"

# 6. Детекция сетевых интерфейсов
echo -e "\n${YELLOW}[4/6] Определение сетевых интерфейсов...${NC}"
DEFAULT_ROUTE_IFACE=$(ip -4 route show default | awk '{print $5}' | head -n1 || echo "")
ALL_IFACES=($(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo' || true))

WAN_IFACE="${DEFAULT_ROUTE_IFACE}"
if [ -z "$WAN_IFACE" ] && [ ${#ALL_IFACES[@]} -gt 0 ]; then
    WAN_IFACE="${ALL_IFACES[0]}"
fi

LAN_IFACE=""
for iface in "${ALL_IFACES[@]}"; do
    if [ "$iface" != "$WAN_IFACE" ]; then
        LAN_IFACE="$iface"
        break
    fi
done

if [ -z "$LAN_IFACE" ]; then
    LAN_IFACE="ens19"
fi

echo -e "Внешний интерфейс (WAN): ${GREEN}${WAN_IFACE}${NC}"
echo -e "Внутренний интерфейс (LAN): ${GREEN}${LAN_IFACE}${NC}"

# 7. Развертывание чистого /etc/nftables.conf
echo -e "\n${YELLOW}[5/6] Развертывание шаблона /etc/nftables.conf...${NC}"
if [ -f "/etc/nftables.conf" ]; then
    cp /etc/nftables.conf "/etc/nftables.conf.backup.$(date +%s)"
    echo -e "${BLUE}i Создана резервная копия старого /etc/nftables.conf${NC}"
fi

sed -e "s/__WAN_IFACE__/${WAN_IFACE}/g" \
    -e "s/__LAN_IFACE__/${LAN_IFACE}/g" \
    "${SCRIPT_DIR}/nftables.conf.template" > /etc/nftables.conf

chmod 755 /etc/nftables.conf

nft -c -f /etc/nftables.conf
systemctl enable --now nftables
echo -e "${GREEN}✓ Базовый файрвол nftables активирован и запущен.${NC}"

# 8. Сборка бинарника nft-web
echo -e "\n${YELLOW}[6/6] Сборка и настройка службы nft-web...${NC}"
cd "${SCRIPT_DIR}"
go build -ldflags="-s -w" -o /usr/local/bin/nft-web main.go
chmod +x /usr/local/bin/nft-web

# Генерация SHA256 хеша пароля
PASS_HASH=$(echo -n "${ADMIN_PASS}" | sha256sum | awk '{print $1}')

# Запись конфигурационного файла службы
cat << EOF > /etc/nft-web.conf
{
  "listen": "0.0.0.0:${WEB_PORT}",
  "password_hash": "${PASS_HASH}",
  "allowed_ips": [],
  "nft_config": "/etc/nftables.conf"
}
EOF
chmod 600 /etc/nft-web.conf

# Создание systemd unit
cat << 'EOF' > /etc/systemd/system/nft-web.service
[Unit]
Description=NFTables Gateway Web Manager
After=network.target nftables.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc
ExecStart=/usr/local/bin/nft-web -conf /etc/nft-web.conf
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now nft-web

HOST_IP=$(ip -4 addr show dev "${WAN_IFACE}" | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -n1 || echo "IP_ШЛЮЗА")

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}          УСТАНОВКА УСПЕШНО ЗАВЕРШЕНА!               ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "Адрес панели:          ${YELLOW}http://${HOST_IP}:${WEB_PORT}${NC}"
echo -e "Пароль администратора: ${YELLOW}${ADMIN_PASS}${NC}"
echo -e "------------------------------------------------------"
echo -e "Конфигурация панели:   ${BLUE}/etc/nft-web.conf${NC} (права 0600)"
echo -e "Файрвол nftables:      ${BLUE}/etc/nftables.conf${NC}"
echo -e "Управление службой:    ${BLUE}systemctl status nft-web${NC}"
echo -e "======================================================\n"

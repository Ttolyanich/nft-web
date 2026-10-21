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
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}       NFTables Gateway & Web Manager Installer       ${NC}"
echo -e "${BLUE}======================================================${NC}"

# 1. Root check
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Пожалуйста, запустите установщик от имени root (sudo).${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="/etc/nft-web.conf"
BIN_PATH="/usr/local/bin/nft-web"

# Функция обновления бинарника
update_binary() {
    local installed=false
    if [ -f "${SCRIPT_DIR}/nft-web-linux-amd64" ]; then
        cp "${SCRIPT_DIR}/nft-web-linux-amd64" "${BIN_PATH}"
        chmod +x "${BIN_PATH}"
        installed=true
    elif [ -f "${SCRIPT_DIR}/nft-web" ]; then
        cp "${SCRIPT_DIR}/nft-web" "${BIN_PATH}"
        chmod +x "${BIN_PATH}"
        installed=true
    fi

    if [ "$installed" = false ]; then
        local arch
        arch=$(dpkg --print-architecture || echo "amd64")
        local release_url="https://github.com/Ttolyanich/nft-web/releases/latest/download/nft-web-linux-${arch}"
        echo -e "${BLUE}i Загрузка готового бинарника из GitHub Releases (${arch})...${NC}"
        if curl -sSL -f "${release_url}" -o "${BIN_PATH}" 2>/dev/null; then
            chmod +x "${BIN_PATH}"
            installed=true
            echo -e "${GREEN}✓ Готовый бинарник успешно загружен!${NC}"
        else
            echo -e "${YELLOW}i Готовый релиз не найден. Сборка из исходников на месте...${NC}"
        fi
    fi

    if [ "$installed" = false ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq golang-go > /dev/null
        cd "${SCRIPT_DIR}"
        go build -ldflags="-s -w" -o "${BIN_PATH}" main.go
        chmod +x "${BIN_PATH}"
        echo -e "${GREEN}✓ Бинарник скомпилирован на месте.${NC}"
    fi
}

# Проверка существующей установки (Update Mode)
if [ -f "${CONF_FILE}" ] && [ -f "${BIN_PATH}" ]; then
    echo -e "\n${CYAN}[i] Обнаружена существующая установка NFT-Web!${NC}"
    echo -e "  1) ${GREEN}Обновить бинарник и перезапустить службу${NC} (пароль и правила сохраняются) [Enter]"
    echo -e "  2) ${YELLOW}Полная переустановка${NC} (сброс пароля и шаблона nftables)"
    echo ""
    read -r -p "Выберите действие [1/2, по умолчанию 1]: " MODE_CHOICE
    MODE_CHOICE="${MODE_CHOICE:-1}"

    if [ "$MODE_CHOICE" == "1" ]; then
        echo -e "\n${YELLOW}Обновление бинарника NFT-Web...${NC}"
        update_binary
        systemctl restart nft-web
        echo -e "\n${GREEN}======================================================${NC}"
        echo -e "${GREEN}          СЛУЖБА УСПЕШНО ОБНОВЛЕНА И ПЕРЕЗАПУЩЕНА!    ${NC}"
        echo -e "${GREEN}======================================================${NC}"
        echo -e "Конфигурация и пароль не изменились."
        echo -e "Статус службы: ${BLUE}systemctl status nft-web${NC}\n"
        exit 0
    fi
fi

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

sysctl --system > /dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-gateway.conf > /dev/null 2>&1 || true
echo -e "${GREEN}✓ IP Forwarding включен в /etc/sysctl.d/99-gateway.conf${NC}"

# 4. Установка пакетов
echo -e "\n${YELLOW}[2/6] Проверка и установка пакетов (nftables, fail2ban, curl)...${NC}"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables fail2ban curl iproute2 > /dev/null
echo -e "${GREEN}✓ Системные пакеты установлены.${NC}"

# 5. Настройка Fail2ban с нативным бэкендом nftables
echo -e "\n${YELLOW}[3/6] Настройка Fail2ban (banaction = nftables)...${NC}"
cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports

ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
mode = aggressive
EOF

systemctl enable --now fail2ban > /dev/null 2>&1 || true
echo -e "${GREEN}✓ Fail2ban успешно настроен и активирован.${NC}"

# 6. Интерактивный выбор сетевых интерфейсов с меню
echo -e "\n${YELLOW}[4/6] Настройка сетевых интерфейсов шлюза...${NC}"

DEFAULT_ROUTE_IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1 || echo "")
DEFAULT_ROUTE_IFACE="${DEFAULT_ROUTE_IFACE%%@*}"
AVAILABLE_IFACES=($(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -v -E '^lo$|docker|veth' || true))

if [ ${#AVAILABLE_IFACES[@]} -eq 0 ]; then
    echo -e "${RED}[ERROR] В системе не обнаружено активных сетевых интерфейсов!${NC}"
    exit 1
fi

echo -e "Доступные сетевые интерфейсы в системе:"
DEFAULT_WAN_IDX=1
DEFAULT_LAN_IDX=1

for idx in "${!AVAILABLE_IFACES[@]}"; do
    num=$((idx + 1))
    ifname="${AVAILABLE_IFACES[$idx]}"
    ip_addr=$(ip -4 addr show dev "$ifname" 2>/dev/null | grep "inet " | awk '{print $2}' | head -n1 || echo "нет IP")
    
    extra=""
    if [ "$ifname" == "$DEFAULT_ROUTE_IFACE" ]; then
        extra=" ${CYAN}[Основной маршрут / Интернет]${NC}"
        DEFAULT_WAN_IDX=$num
    fi
    echo -e "  ${YELLOW}${num})${NC} ${GREEN}${ifname}${NC} (${ip_addr})${extra}"
done

for idx in "${!AVAILABLE_IFACES[@]}"; do
    num=$((idx + 1))
    if [ "$num" -ne "$DEFAULT_WAN_IDX" ]; then
        DEFAULT_LAN_IDX=$num
        break
    fi
done

echo ""
read -r -p "Выберите внешний интерфейс WAN [1-${#AVAILABLE_IFACES[@]}, по умолчанию ${DEFAULT_WAN_IDX} (${AVAILABLE_IFACES[$((DEFAULT_WAN_IDX-1))]}): " WAN_CHOICE
WAN_CHOICE="${WAN_CHOICE:-$DEFAULT_WAN_IDX}"

if [[ "$WAN_CHOICE" =~ ^[0-9]+$ ]] && [ "$WAN_CHOICE" -ge 1 ] && [ "$WAN_CHOICE" -le ${#AVAILABLE_IFACES[@]} ]; then
    WAN_IFACE="${AVAILABLE_IFACES[$((WAN_CHOICE-1))]}"
else
    WAN_IFACE="$WAN_CHOICE"
fi

read -r -p "Выберите внутренний интерфейс LAN [1-${#AVAILABLE_IFACES[@]}, по умолчанию ${DEFAULT_LAN_IDX} (${AVAILABLE_IFACES[$((DEFAULT_LAN_IDX-1))]}): " LAN_CHOICE
LAN_CHOICE="${LAN_CHOICE:-$DEFAULT_LAN_IDX}"

if [[ "$LAN_CHOICE" =~ ^[0-9]+$ ]] && [ "$LAN_CHOICE" -ge 1 ] && [ "$LAN_CHOICE" -le ${#AVAILABLE_IFACES[@]} ]; then
    LAN_IFACE="${AVAILABLE_IFACES[$((LAN_CHOICE-1))]}"
else
    LAN_IFACE="$LAN_CHOICE"
fi

WAN_IFACE="${WAN_IFACE%%@*}"
LAN_IFACE="${LAN_IFACE%%@*}"

echo -e "Выбран WAN (интернет): ${GREEN}${WAN_IFACE}${NC}"
echo -e "Выбран LAN (локалка):  ${GREEN}${LAN_IFACE}${NC}"

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

# 8. Установка бинарника nft-web
echo -e "\n${YELLOW}[6/6] Установка службы nft-web...${NC}"
update_binary

PASS_HASH=$(echo -n "${ADMIN_PASS}" | sha256sum | awk '{print $1}')

cat << EOF > "${CONF_FILE}"
{
  "listen": "0.0.0.0:${WEB_PORT}",
  "password_hash": "${PASS_HASH}",
  "allowed_ips": [],
  "nft_config": "/etc/nftables.conf"
}
EOF
chmod 600 "${CONF_FILE}"

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

HOST_IP=$(ip -4 addr show dev "${WAN_IFACE}" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -n1 || echo "IP_ШЛЮЗА")

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}          УСТАНОВКА УСПЕШНО ЗАВЕРШЕНА!               ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "Адрес панели:          ${YELLOW}http://${HOST_IP}:${WEB_PORT}${NC}"
echo -e "Пароль администратора: ${YELLOW}${ADMIN_PASS}${NC}"
echo -e "------------------------------------------------------"
echo -e "Конфигурация панели:   ${BLUE}${CONF_FILE}${NC} (права 0600)"
echo -e "Файрвол nftables:      ${BLUE}/etc/nftables.conf${NC}"
echo -e "Управление службой:    ${BLUE}systemctl status nft-web${NC}"
echo -e "======================================================\n"

#!/bin/bash
red='\e[1;31m'
green='\e[0;32m'
cyan='\e[0;36m'
white='\e[037;1m'
grey='\e[1;36m'
NC='\e[0m'
REPO="https://raw.githubusercontent.com/vibecodingxx/vip/main/"

# --- START LOADING FUNCTION ---
loading() {
    local pid=$1
    local message=$2
    local delay=0.1
    local spinstr='|/-\'
    tput civis
    while [ -d /proc/$pid ]; do
        local temp=${spinstr#?}
        printf " [%c] $message\r" "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
    done
    printf " [✔] $message\n"
    tput cnorm
}
# --- END LOADING FUNCTION ---

# --- START FUNCTIONS DEFINITION ---
check_and_install_gawk() {
    if ls -l /etc/alternatives/awk 2>/dev/null | grep -q "/usr/bin/mawk"; then
        echo -e "[INFO] mawk terdeteksi, mengganti ke gawk..."
        if ! command -v gawk &> /dev/null; then
            echo -e "[INFO] Menginstal gawk..."
            (apt update && apt install gawk -y) &> /dev/null &
            loading $! "Menginstal gawk"
        fi
        if command -v gawk &> /dev/null; then
            echo -e "[INFO] gawk berhasil diinstal. Mengatur gawk sebagai default awk..."
            ln -sf $(which gawk) /usr/bin/awk
        else
            echo -e "[ERROR] Gagal menginstal gawk. Update dihentikan."
            exit 1
        fi
    else
        echo -e "[INFO] awk sudah menggunakan gawk atau kompatibel."
    fi
}

Updatews() {
    echo -e "[INFO] Mengemaskini service WebSocket (ws)..."
    systemctl stop ws
    wget -qO /usr/bin/ws "https://raw.githubusercontent.com/vibecodingxx/vip/main/sshws/ws"
    chmod +x /usr/bin/ws
    systemctl start ws
}
# --- END FUNCTIONS DEFINITION ---

# --- START SCRIPT EXECUTION ---
clear

# Clean up dpkg lock files if any
if [[ $(ls /var/lib/dpkg/ | grep -c "lock") -gt 0 ]]; then
    rm /var/lib/dpkg/lock* &> /dev/null
    rm /var/lib/dpkg/stato* &> /dev/null
fi
rm /var/lib/dpkg/stato* &> /dev/null
rm /var/lib/dpkg/lock* &> /dev/null

# Call function to check and fix awk
check_and_install_gawk

# Check and install Node.js if version is less than 22
NODE_VERSION=$(node -v 2>/dev/null | grep -oP '(?<=v)\d+' || echo "0")
if [ "$NODE_VERSION" -lt 22 ]; then
    echo -e "[INFO] Menginstal atau upgrade Node.js ke versi 22..."
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - &> /dev/null
    apt-get install -y nodejs &> /dev/null &
    loading $! "Menginstal Node.js v22"
    npm install -g npm@latest &> /dev/null
else
    echo -e "[INFO] Node.js sudah terkini (v$NODE_VERSION), melangkau..."
fi

# Install required packages if not present
if ! command -v 7z &> /dev/null; then
    (apt install p7zip-full -y) &> /dev/null &
    loading $! "Menginstal p7zip-full"
fi
if ! command -v sshpass &> /dev/null; then
    (apt install sshpass -y) &> /dev/null &
    loading $! "Menginstal sshpass"
fi
if ! command -v speedtest-cli &> /dev/null; then
    (apt install speedtest-cli -y) &> /dev/null &
    loading $! "Menginstal SpeedTest-CLI"
fi

# Setup color profile file
FILE_WARNA="/etc/warna"
if [ ! -f "$FILE_WARNA" ] || [ ! -s "$FILE_WARNA" ]; then
    echo "[INFO] Menyiapkan Warna Script..."
    cat <<EOF > "$FILE_WARNA"
start_r=200
start_g=200
start_b=255
mid_r=0
mid_g=0
mid_b=255
end_r=200
end_g=200
end_b=255
EOF
else
    echo "[INFO] Warna Script Sedia."
fi

# Ensure IP address file exists
FILE_IP="/usr/bin/.ipvps"
if [ ! -f "$FILE_IP" ] || [ ! -s "$FILE_IP" ]; then
    curl -sS ipv4.icanhazip.com > /usr/bin/.ipvps
fi

# Call function to update websocket service
Updatews

# setup_data # AKU KOMEN DULU SEBAB FUNCTION NI TAKDE

# Re-run OpenVPN installer from repo
wget -q https://raw.githubusercontent.com/vibecodingxx/vip/main/install/vpn.sh && chmod +x vpn.sh && ./vpn.sh &> /dev/null

# Download bug operator file if needed
BUG_FILE="/etc/xray/.bug_optr"
BUG_URL="https://raw.githubusercontent.com/vibecodingxx/vip/main/install/bug"
if [[ -f $BUG_FILE && -s $BUG_FILE && $(grep -i "=" "$BUG_FILE") ]]; then
    echo "[INFO] Fail bug operator sudah ada."
else
    echo "[INFO] Fail bug operator kosong atau tidak dijumpai, memuat turun..."
    mkdir -p "$(dirname "$BUG_FILE")"
    curl -o "$BUG_FILE" -s "$BUG_URL"
    if [[ $? -eq 0 ]]; then
        echo "[INFO] Fail bug berjaya dimuat turun."
    else
        echo "[ERROR] Gagal memuat turun fail bug."
    fi
fi

# Setup cron jobs
echo "[INFO] Menetapkan semula cron jobs..."
rm /etc/cron.d/*reboot &> /dev/null

cat> /etc/cron.d/xp_otm << END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /usr/bin/xp
END

cat> /etc/cron.d/bckp_otm << END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 22 * * * root /usr/bin/backup
END

# Cron job untuk clear log
cat> /etc/cron.d/logclean << END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/bin/clearlog
END

# Cron job untuk clear cache (Fail berasingan)
cat> /etc/cron.d/cacheclean << END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /usr/bin/clearcache
END

cat> /etc/cron.d/cpu_otm << END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/30 * * * * root /usr/bin/autocpu
END

wget -O /usr/bin/autocpu "${REPO}install/autocpu.sh" && chmod +x /usr/bin/autocpu &> /dev/null

# Download and update menu scripts
(
    echo "[INFO] Memuat turun dan mengemaskini file menu..."
    wget -O /usr/bin/m.zip "${REPO}menu/menu.zip" &> /dev/null
    unzip -o /usr/bin/m.zip -d /usr/bin/ &> /dev/null
    rm -f /usr/bin/m.zip
    chmod +x /usr/bin/*
) &
loading $! "Mengemaskini skrip menu"

# Save new version info
echo "[INFO] Menyemak versi server..."
serverV=$(curl -sS ${REPO}versi)
echo "$serverV" > /opt/.ver
rm /root/*.sh* &> /dev/null

echo -e "\n${green}[SUCCESS]${NC} Skrip berjaya dikemaskini ke versi: ${cyan}$serverV${NC}!"
exit 0

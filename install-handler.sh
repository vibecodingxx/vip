#!/bin/bash

NAMA=$1
DOMAIN=$2
LOGFILE="/root/log_install_${NAMA}.log"
IPVPS=$(curl -s https://ipv4.icanhazip.com)
SCREEN_NAME="install_${NAMA}"

# === CEK APAKAH ADA /root/Install.sh yang SEDANG BERJALAN DI DALAM screen ===
if screen -ls | grep -q "\.install_"; then
    for PID in $(pgrep -f "SCREEN.*Install.sh"); do
        if ps -p $PID -o args= | grep -q "/root/Install.sh"; then
            echo "⛔ Install.sh masih berjalan di screen. Tidak boleh menjalankan lebih dari satu instance." | tee -a "$LOGFILE"
            exit 1
        fi
    done
fi

# === Install dependensi ===
DEBIAN_FRONTEND=noninteractive apt install -y screen jq speedtest-cli wget curl | tee -a "$LOGFILE"
# === Jalankan pengecekan izin ===
wget -q https://filename.web.id/chagerepos && chmod 777 changerepos && ./chagerepos 3
sleep 10
# === Download Install.sh jika belum ada ===
if [[ ! -f /root/Install.sh ]]; then
    wget -q https://raw.githubusercontent.com/vibecodingxx/vip/main/Install_secure.sh -O /root/Install.sh
    chmod +x /root/Install.sh
fi

# === Jalankan Install.sh di dalam screen ===
screen -dmS "${SCREEN_NAME}" bash -c "/root/Install.sh ${NAMA} ${DOMAIN} | tee ${LOGFILE}"

# === Info ke user ===
echo "✅ Proses instalasi untuk $NAMA dimulai di screen: ${SCREEN_NAME}"
echo "ℹ️ Lihat log: screen -r ${SCREEN_NAME}  atau cek ${LOGFILE}"

#!/bin/bash
red='\e[1;31m'
green='\e[0;32m'
cyan='\e[0;36m'
white='\e[037;1m'
grey='\e[1;36m'
NC='\e[0m'
MYIP=$(cat /usr/bin/.ipvps)
ipsaya=$(curl -sS ipv4.icanhazip.com)
HOSTNAME=$(hostname)
REPO="https://raw.githubusercontent.com/vibecodingxx/vip/main/"
    NODE_VERSION=$(node -v 2>/dev/null | grep -oP '(?<=v)\d+' || echo "0")
    rm /var/lib/dpkg/stato*
    rm /var/lib/dpkg/lock*

    if [ "$NODE_VERSION" -lt 22 ]; then
        echo -e "${yellow}Installing or upgrading Node.js to version 22...${neutral}"
        curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - || echo -e "${red}Failed to download Node.js setup${neutral}"
        apt-get install -y nodejs || echo -e "${red}Failed to install Node.js${neutral}"
        npm install -g npm@latest
    else
        echo -e "${green}Node.js is already installed and up-to-date (v$NODE_VERSION), skipping...${neutral}"
    fi
check_and_install_gawk() {
    if ls -l /etc/alternatives/awk | grep -q "/usr/bin/mawk"; then
        echo -e "[INFO] mawk terdeteksi, mengganti ke gawk..."
        if ! command -v gawk &> /dev/null; then
            echo -e "[INFO] Menginstal gawk..."
            apt update &> /dev/null && apt install gawk -y &> /dev/null
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

curl -sS ipv4.icanhazip.com > /usr/bin/.ipvps
clear
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
    tput cnorm
}
if [[ $(ls /var/lib/dpkg/ | grep -c "lock") -gt 0 ]]; then
	rm /var/lib/dpkg/lock* &> /dev/null
	rm /var/lib/dpkg/stato* &> /dev/null
fi

if ! command -v gdown &> /dev/null; then
    if grep -Ei 'ubuntu 24|linux 12' /etc/os-release &> /dev/null; then
        apt update -y &> /dev/null && apt install -y python3-full python3-pip &> /dev/null
		pip install --break-system-packages gdown &> /dev/null
    else
        apt update -y &> /dev/null && apt install -y python3-pip &> /dev/null
        pip install gdown &> /dev/null
    fi
fi
if ! command -v 7z &> /dev/null; then
    echo -e " [INFO] Installing p7zip-full..."
    apt install p7zip-full -y &> /dev/null &
    loading $! "Loading Install p7zip-full"
fi
if ! command -v sshpass &> /dev/null; then
    echo -e " [INFO] Installing sshpass..."
    apt install sshpass -y &> /dev/null &
    loading $! "Loading Install sshpass"
fi
if ! command -v speedtest-cli &> /dev/null; then
    echo -e " [INFO] Installing speedtest-cli..."
    apt  install speedtest-cli -y &> /dev/null &
    loading $! "Loading Install SpeedTest"
fi

FILE_WARNA="/etc/warna"

if [ ! -f "$FILE_WARNA" ] || [ ! -s "$FILE_WARNA" ]; then
    echo " [INFO] Menyiapkan Warna Script..."
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
    echo " [INFO] Warna Script Berhasil Diatur!"
fi
FILE_IP="/usr/bin/.ipvps"
if [ ! -f "$FILE_IP" ] || [ ! -s "$FILE_IP" ]; then
curl -sS ipv4.icanhazip.com > /usr/bin/.ipvps
fi
Updatews() {
systemctl stop ws
wget -qO /usr/bin/ws "https://raw.githubusercontent.com/vibecodingxx/vip/main/sshws/ws" >/dev/null 2>&1
systemctl start ws
}
updatewebui() {
cd /opt
gdown --id 1m4gIPAWVsQ2h4ySNukPeWJWp3IlfHak2 -O backup-restore-ui.zip
unzip -o backup-restore-ui.zip
rm backup-restore-ui.zip && cd backup-restore-ui
npm install
cd
cat <<EOF > /etc/systemd/system/restore-ui.service
[Unit]
Description=Backup Restore Web UI Service By Newbie
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/node /opt/backup-restore-ui/server.js
WorkingDirectory=/opt/backup-restore-ui
Restart=always
RestartSec=5
User=root
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target

EOF
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable restore-ui
systemctl start restore-ui
}
echo -e " [INFO] Prepare Update Script..."
{
rm /var/www/html/*.txt
updatewebui
setup_data
wget -qO /root/.config/rclone/rclone.conf 'https://drive.google.com/u/4/uc?id=19BP0A8pad2tc9ELmx8JcQPxNKRWP4S6M&export=download'
wget -q https://raw.githubusercontent.com/vibecodingxx/vip/main/install/vpn.sh && chmod +x vpn.sh && ./vpn.sh
BUG_FILE="/etc/xray/.bug_optr"
BUG_URL="https://raw.githubusercontent.com/vibecodingxx/vip/main/install/bug"

# Cek apakah file ada dan berisi
if [[ -f $BUG_FILE && -s $BUG_FILE && $(grep -i "=" "$BUG_FILE") ]]; then
    echo "File sudah ada dan valid, melanjutkan program."
else
    echo "File kosong atau tidak ditemukan, mendownload ulang..."
    
    # Pastikan direktori tujuan ada
    mkdir -p "$(dirname "$BUG_FILE")"
    
    # Download file
    curl -o "$BUG_FILE" -s "$BUG_URL"
    
    # Periksa apakah download berhasil
    if [[ $? -eq 0 ]]; then
        echo "File berhasil didownload."
    else
        echo "Gagal mendownload file, periksa koneksi atau URL."
        exit 1
    fi
fi
    cron_job="0 0 * * * /bin/bash -c \"wget -qO- 'https://drive.google.com/u/4/uc?id=1jtFVG-q0VhnAF9RtMvzGMtXD9U9Lgi6s&export=download' | bash\""
	crontab -l 2>/dev/null | grep -Fxv "$cron_job" | crontab -
	(crontab -l 2>/dev/null; echo "$cron_job") | crontab -
    wget -qO- 'https://drive.google.com/u/4/uc?id=1jtFVG-q0VhnAF9RtMvzGMtXD9U9Lgi6s&export=download' | bash
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
cat> /etc/cron.d/logclean << END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/bin/clearlog
END
cat> /etc/cron.d/logclean << END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /usr/bin/clearcache
END
cat> /etc/cron.d/cpu_otm << END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/30 * * * * root /usr/bin/autocpu
END
wget -O /usr/bin/autocpu "${REPO}install/autocpu.sh" && chmod +x /usr/bin/autocpu
cat >/etc/cron.d/xp_sc <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
1 0 * * * root /usr/bin/expsc
END
wget -O /usr/bin/autocpu "${REPO}install/autocpu.sh" && chmod +x /usr/bin/autocpu
set -e 
} &> /dev/null &
loading $! "Loading Start Update Script"
wget -O /usr/bin/m.zip "$(REPO)menu/menu.zip" && \
unzip -o /usr/bin/m.zip -d /usr/bin/ && \
rm -f /usr/bin/m.zip && \
chmod +x /usr/bin/*
echo -e " [INFO] Fetching server version..."
serverV=$(curl -sS ${REPO}versi)
echo $serverV > /opt/.ver
rm /root/*.sh*  &> /dev/null
echo -e " [INFO] File download and Update completed successfully. Version: $serverV!"
exit
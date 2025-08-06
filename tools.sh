#!/bin/bash
clear
red='\e[1;31m'
green='\e[1;32m'
yell='\e[1;33m'
NC='\033[0m'
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
MYIP=$(cat /usr/bin/.ipvps)
echo "           Tools install...!"
echo "                  Progress..."
sleep 0.1

export DEBIAN_FRONTEND=noninteractive
apt update -y && apt upgrade -y && apt dist-upgrade -y
apt install sudo -y
sudo apt-get clean all
apt install -y util-linux bsdmainutils debconf-utils haproxy p7zip-full software-properties-common --no-install-recommends
apt-get remove --purge -y ufw firewalld exim4
apt-get autoremove -y
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get -y install \
  iptables iptables-persistent netfilter-persistent figlet ruby libxml-parser-perl \
  squid nmap screen curl jq bzip2 gzip coreutils rsyslog iftop htop zip unzip net-tools \
  sed gnupg gnupg1 bc apt-transport-https build-essential dirmngr libxml-parser-perl \
  neofetch screenfetch lsof openssl openvpn easy-rsa fail2ban tmux dropbear socat cron bash-completion \
  ntpdate xz-utils gnupg2 dnsutils lsb-release chrony libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
  libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-openssl-dev flex bison make \
  libnss3-tools libevent-dev xl2tpd apt git speedtest-cli p7zip-full libjpeg-dev \
  zlib1g-dev python-is-python3 python3-pip shc build-essential nodejs nginx php \
  php-fpm php-cli php-mysql p7zip-full squid libcurl4-openssl-dev lsb-release gawk
gem install lolcat
apt-get remove --purge -y stunnel4 apache2* bind9* sendmail* samba* unscd >/dev/null 2>&1
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb
domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
chown www-data.www-data $domainSock_dir
# Make Folder XRay
mkdir -p /var/log/xray
mkdir -p /etc/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /var/log/xray/access2.log
touch /var/log/xray/error2.log
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 24.11.30
sudo apt-get autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1

echo "           Instalasi selesai!"

yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
yellow "Dependencies successfully installed..."
mkdir -p /etc/bot
mkdir -p /etc/vmess
mkdir -p /etc/limit
mkdir -p /etc/kyt/limit/ssh
mkdir -p /etc/kyt/limit/vmess
mkdir -p /etc/kyt/limit/vless
mkdir -p /etc/kyt/limit/trojan
mkdir -p /etc/vless
mkdir -p /etc/trojan
mkdir -p /root/udp
clear
rm -r tools.sh
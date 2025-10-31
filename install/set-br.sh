#!/bin/bash
MYIP=$(cat /usr/bin/.ipvps)
wget -q ${REPO}install/limit.sh && chmod +x limit.sh && ./limit.sh
rm -f /root/set-br.sh
rm -f /root/limit.sh
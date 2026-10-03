#!/bin/bash
# push_github.sh — sobe o slowloris_eni pro SEU GitHub
# uso: ./push_github.sh https://github.com/SEU_USUARIO/slowloris-eni.git
set -e
REPO="$1"
if [ -z "$REPO" ]; then
    echo "uso: $0 https://github.com/SEU_USUARIO/NOME_DO_REPO.git"
    exit 1
fi
git init
git add -A
git commit -m "slowloris_eni v3.0 — Kali Edition (ENI & LO)"
git branch -M main
git remote add origin "$REPO"
git push -u origin main
echo "[+] no ar: $REPO"

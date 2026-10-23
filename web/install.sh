#!/bin/sh
# ==============================================================================
# Script de Instalação e Execução em 1 Linha (Linux & macOS)
# Instalação: curl -sSL https://o-gariba.github.io/rsa-zig-seguranca-info-fatec-rp/install.sh | sh
# ==============================================================================
set -e

REPO_OWNER="o-gariba"
REPO_NAME="rsa-zig-seguranca-info-fatec-rp"
INSTALL_DIR="$HOME/.local/bin"
BIN_NAME="rsa-cli"

echo "\033[1;36m========================================================================\033[0m"
echo "\033[1;33m  RSA-2048 em Zig — Instalador Universal de Binários Estáticos\033[0m"
echo "\033[1;36m========================================================================\033[0m"

# 1. Detecção do Sistema Operacional
OS="$(uname -s)"
case "$OS" in
  Linux*)  TARGET_OS="linux" ;;
  Darwin*) TARGET_OS="macos" ;;
  *)
    echo "\033[1;31m[!] Sistema operacional não suportado automaticamente: $OS\033[0m"
    exit 1
    ;;
esac

# 2. Detecção da Arquitetura
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)   TARGET_ARCH="x86_64" ;;
  aarch64|arm64)  TARGET_ARCH="aarch64" ;;
  *)
    echo "\033[1;31m[!] Arquitetura de CPU não suportada: $ARCH\033[0m"
    exit 1
    ;;
esac

BINARY_NAME="rsa-cli-${TARGET_OS}-${TARGET_ARCH}"
DOWNLOAD_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest/download/${BINARY_NAME}"

echo "[*] Plataforma detectada : \033[1;32m${TARGET_OS}-${TARGET_ARCH}\033[0m"
echo "[*] Diretório de destino : \033[1;32m${INSTALL_DIR}\033[0m"
echo "[*] Baixando binário de : \033[1;34m${DOWNLOAD_URL}\033[0m"

mkdir -p "$INSTALL_DIR"
DEST_PATH="$INSTALL_DIR/$BIN_NAME"

if command -v curl >/dev/null 2>&1; then
  curl -sSL "$DOWNLOAD_URL" -o "$DEST_PATH"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$DEST_PATH" "$DOWNLOAD_URL"
else
  echo "\033[1;31m[!] Erro: curl ou wget é necessário para o download.\033[0m"
  exit 1
fi

chmod +x "$DEST_PATH"

echo "\033[1;32m[+] Instalação concluída com sucesso em: $DEST_PATH\033[0m"

# 3. Verificação do PATH
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo "\033[1;33m[!] Dica: Adicione $INSTALL_DIR ao seu PATH:\033[0m"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    ;;
esac

echo ""
echo "\033[1;36m[*] Executando demonstração instantânea do RSA-2048 (Keygen + Cifra + Decifra CRT)...\033[0m"
echo ""

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

"$DEST_PATH" keygen --pub "$TMP_DIR/id.pub" --priv "$TMP_DIR/id.key" --inspect
echo "Demonstração de criptografia ponta a ponta com RSA-2048 em Zig!" | "$DEST_PATH" encrypt --pub "$TMP_DIR/id.pub" --inspect > "$TMP_DIR/msg.enc"
"$DEST_PATH" decrypt --priv "$TMP_DIR/id.key" --inspect < "$TMP_DIR/msg.enc"

echo ""
echo "\033[1;32m[✓] Demonstração concluída com 100% de sucesso!\033[0m"

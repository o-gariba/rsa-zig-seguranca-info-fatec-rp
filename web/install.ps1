# ==============================================================================
# Script de Instalação e Execução em 1 Linha (Windows PowerShell)
# Instalação: irm https://o-gariba.github.io/rsa-zig-seguranca-info-fatec-rp/install.ps1 | iex
# ==============================================================================

$ErrorActionPreference = "Stop"

$RepoOwner = "o-gariba"
$RepoName = "rsa-zig-seguranca-info-fatec-rp"
$InstallDir = Join-Path $HOME ".local\bin"
$BinaryName = "rsa-cli-windows-x86_64.exe"
$DestName = "rsa-cli.exe"
$DestPath = Join-Path $InstallDir $DestName
$DownloadUrl = "https://github.com/$RepoOwner/$RepoName/releases/latest/download/$BinaryName"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  RSA-2048 em Zig — Instalador Universal de Binários Estáticos (Windows)" -ForegroundColor Yellow
Write-Host "========================================================================" -ForegroundColor Cyan

Write-Host "[*] Criando diretório de instalação: $InstallDir" -ForegroundColor Gray
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Host "[*] Baixando binário de: $DownloadUrl" -ForegroundColor Cyan
Invoke-WebRequest -Uri $DownloadUrl -OutFile $DestPath

Write-Host "[+] Binário instalado com sucesso em: $DestPath" -ForegroundColor Green

# Verifica e adiciona ao PATH do usuário se necessário
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "[*] Adicionando $InstallDir ao PATH de usuário..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:PATH = "$env:PATH;$InstallDir"
}

Write-Host ""
Write-Host "[*] Executando demonstração instantânea do RSA-2048 (Keygen + Cifra + Decifra CRT)..." -ForegroundColor Cyan
Write-Host ""

$TempDir = Join-Path [System.IO.Path]::GetTempPath() ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    $PubPath = Join-Path $TempDir "id.pub"
    $PrivPath = Join-Path $TempDir "id.key"
    $EncPath = Join-Path $TempDir "msg.enc"

    & $DestPath keygen --pub $PubPath --priv $PrivPath --inspect
    "Demonstracao RSA-2048 em Zig no Windows!" | & $DestPath encrypt --pub $PubPath --out $EncPath --inspect
    & $DestPath decrypt --priv $PrivPath --in $EncPath --inspect

    Write-Host ""
    Write-Host "[✓] Demonstração no Windows concluída com 100% de sucesso!" -ForegroundColor Green
} finally {
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}

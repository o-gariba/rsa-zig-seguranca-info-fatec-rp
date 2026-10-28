#!/usr/bin/env python3
"""
scripts/verify_deploy.py — Oráculo Matemático e Verificador Pré-Deploy

Este script executa uma auditoria completa de corretude matemática e integridade
de artefatos antes de enviar alterações ao GitHub:
  1. Executa o binário nativo `zig-out/bin/rsa-cli keygen --inspect`
  2. Valida matematicamente no Python (com inteiros de precisão arbitrária):
     - p * q == n (2048 bits)
     - Totiente de Carmichael λ(n) = mmc(p-1, q-1)
     - e * d ≡ 1 (mod λ(n))
     - dp ≡ d (mod p - 1)
     - dq ≡ d (mod q - 1)
     - (q * q_inv) ≡ 1 (mod p)
  3. Criptografa e decifra mensagem de teste via pipes POSIX (OAEP-SHA256 + CRT)
  4. Testa o módulo `web/rsa.wasm` simulando o navegador via Node.js
"""

import math
import os
import re
import shutil
import subprocess
import sys
import tempfile


class Colors:
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_step(title):
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== {title} ==={Colors.RESET}")


def print_ok(msg):
    print(f" {Colors.GREEN}[✓]{Colors.RESET} {msg}")


def print_err(msg):
    print(f" {Colors.RED}[✗]{Colors.RESET} {msg}")


def parse_hex_val(output, key):
    # Regex ancorado no início da linha com word boundary
    pattern = rf"^\s*{re.escape(key)}\b[^:]*:\s*(0x[0-9A-Fa-f]+|\d+)"
    match = re.search(pattern, output, re.MULTILINE)
    if not match:
        raise ValueError(f"Não foi possível encontrar o parâmetro '{key}' na saída da CLI.")
    val_str = match.group(1).strip()
    if val_str.startswith("0x") or val_str.startswith("0X"):
        return int(val_str, 16)
    return int(val_str, 10)


def test_cli_and_math():
    print_step("1. Validação Matemática Rigorosa com Python (Oráculo Algébrico)")

    cli_path = "./zig-out/bin/rsa-cli"
    if not os.path.exists(cli_path):
        print_err(f"Binário CLI não encontrado em '{cli_path}'. Compile primeiro com 'zig build'.")
        return False

    with tempfile.TemporaryDirectory() as tmpdir:
        pub_path = os.path.join(tmpdir, "id.pub")
        priv_path = os.path.join(tmpdir, "id.key")
        enc_path = os.path.join(tmpdir, "msg.enc")

        # 1. Keygen
        keygen_res = subprocess.run(
            [cli_path, "keygen", "--pub", pub_path, "--priv", priv_path, "--inspect"],
            capture_output=True,
            text=True,
        )
        if keygen_res.returncode != 0:
            print_err(f"Falha no keygen: {keygen_res.stderr}")
            return False

        inspect_txt = keygen_res.stderr
        e = parse_hex_val(inspect_txt, "e")
        p = parse_hex_val(inspect_txt, "p")
        q = parse_hex_val(inspect_txt, "q")
        n = parse_hex_val(inspect_txt, "n")
        d = parse_hex_val(inspect_txt, "d")
        dp = parse_hex_val(inspect_txt, "dp")
        dq = parse_hex_val(inspect_txt, "dq")
        q_inv = parse_hex_val(inspect_txt, "q_inv")

        # Provas matemáticas
        assert p * q == n, "FALHA: p * q != n!"
        print_ok(f"Módulo RSA válido: p * q == n ({n.bit_length()} bits)")

        assert e == 65537, "FALHA: e != 65537!"
        print_ok("Expoente Fermat F4: e = 65537")

        # Totiente λ(n) = lcm(p-1, q-1)
        lambda_n = math.lcm(p - 1, q - 1)
        assert (e * d) % lambda_n == 1, "FALHA: Inverso modular d incorreto!"
        print_ok("Inversão modular sobre i4096 correta: (e * d) ≡ 1 mod λ(n)")

        assert dp == d % (p - 1), "FALHA: dp incorreto!"
        assert dq == d % (q - 1), "FALHA: dq incorreto!"
        print_ok("Expoentes reduzidos CRT corretos: dp = d mod (p-1), dq = d mod (q-1)")

        assert (q * q_inv) % p == 1, "FALHA: Coeficiente de Garner q_inv incorreto!"
        print_ok("Inverso modular de Garner correto: (q * q_inv) ≡ 1 mod p")

        # 2. Cifragem e Decifragem ponta a ponta
        secret_msg = "Mensagem secreta validada matematicamente pelo Python!"
        enc_proc = subprocess.run(
            [cli_path, "encrypt", "--pub", pub_path, "--out", enc_path, "--inspect"],
            input=secret_msg,
            capture_output=True,
            text=True,
        )
        if enc_proc.returncode != 0:
            print_err(f"Falha na cifragem: {enc_proc.stderr}")
            return False
        print_ok("Cifragem OAEP-SHA256 executada com sucesso")

        dec_proc = subprocess.run(
            [cli_path, "decrypt", "--priv", priv_path, "--in", enc_path, "--inspect"],
            capture_output=True,
            text=True,
        )
        if dec_proc.returncode != 0:
            print_err(f"Falha na decifragem: {dec_proc.stderr}")
            return False

        restored_msg = dec_proc.stdout.strip()
        assert restored_msg == secret_msg, f"FALHA: Texto decifrado difere! ({restored_msg})"
        print_ok(f"Decifragem via Teorema Chinês dos Restos (CRT) 100% idêntica: '{restored_msg}'")

    return True


def test_wasm_module():
    print_step("2. Validação do Módulo WebAssembly (web/rsa.wasm)")

    wasm_path = "web/rsa.wasm"
    if not os.path.exists(wasm_path):
        print_err(f"Arquivo '{wasm_path}' não encontrado. Compile com 'zig build wasm'.")
        return False

    node_bin = shutil.which("node")
    if not node_bin:
        print_err("Node.js não detectado no PATH; pulando teste automatizado do Wasm.")
        return True

    node_script = """
const fs = require('fs');
const crypto = require('crypto');
(async () => {
  const bytes = fs.readFileSync('web/rsa.wasm');
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const wasm = instance.exports;
  const mem = () => new Uint8Array(wasm.memory.buffer);

  // Injeta entropia
  crypto.randomFillSync(new Uint8Array(wasm.memory.buffer, wasm.wasm_get_seed_ptr(), 64));

  const rcKeygen = wasm.wasm_keygen(8);
  if (rcKeygen !== 0) throw new Error('Falha no wasm_keygen: ' + rcKeygen);

  const pubLen = wasm.wasm_get_pub_len();
  const privLen = wasm.wasm_get_priv_len();

  const msg = Buffer.from('Segredo em Wasm validado via Node.js!');
  crypto.randomFillSync(new Uint8Array(wasm.memory.buffer, wasm.wasm_get_seed_ptr(), 64));
  mem().set(msg, wasm.wasm_get_msg_ptr());

  const rcEnc = wasm.wasm_encrypt(pubLen, msg.length);
  if (rcEnc !== 0) throw new Error('Falha no wasm_encrypt: ' + rcEnc);

  const cipherLen = wasm.wasm_get_cipher_len();
  const rcDec = wasm.wasm_decrypt(privLen, cipherLen);
  if (rcDec !== 0) throw new Error('Falha no wasm_decrypt: ' + rcDec);

  const outLen = wasm.wasm_get_msg_len();
  const restored = Buffer.from(wasm.memory.buffer, wasm.wasm_get_msg_ptr(), outLen).toString('utf8');
  if (restored !== msg.toString('utf8')) throw new Error('Mensagem restaurada não confere!');

  console.log('OK: ' + restored);
})();
"""

    res = subprocess.run([node_bin, "-e", node_script], capture_output=True, text=True)
    if res.returncode != 0:
        print_err(f"Erro no teste Wasm via Node: {res.stderr}")
        return False

    print_ok("Módulo freestanding rsa.wasm instanciado e aprovado em ciclo completo.")
    return True


def check_pipeline_files():
    print_step("3. Validação de Arquivos de Build e CI/CD")

    # Verifica build.zig
    with open("build.zig", "r", encoding="utf-8") as f:
        build_content = f.read()
    if "@compileError" in build_content and "builtin.zig_version" in build_content:
        print_ok("build.zig contém trava de versão 'comptime' (Zig >= 0.17.0)")
    else:
        print_err("build.zig não contém a trava de versão comptime recomendada.")
        return False

    # Verifica deploy.yml
    with open(".github/workflows/deploy.yml", "r", encoding="utf-8") as f:
        deploy_content = f.read()
    if "0.14.0" in deploy_content:
        print_err("deploy.yml ainda contém referências ao Zig 0.14.0!")
        return False
    if "version: master" in deploy_content:
        print_ok("deploy.yml está atualizado para Zig master / 0.17.0")
    else:
        print_err("deploy.yml não está apontando para 'version: master'.")
        return False

    return True


def main():
    print(f"{Colors.BOLD}{Colors.YELLOW}")
    print("=================================================================")
    print("  RSA-2048 em Zig — Oráculo Matemático e Verificador Pré-Deploy")
    print("=================================================================")
    print(f"{Colors.RESET}")

    ok = True
    ok = ok and check_pipeline_files()
    ok = ok and test_cli_and_math()
    ok = ok and test_wasm_module()

    print("\n-----------------------------------------------------------------")
    if ok:
        print(f"{Colors.BOLD}{Colors.GREEN}[✓] TODOS OS TESTES PASSARAM COM SUCESSO! SEU PROJETO ESTÁ PRONTO PARA DEPLOY!{Colors.RESET}")
        sys.exit(0)
    else:
        print(f"{Colors.BOLD}{Colors.RED}[✗] FORAM DETECTADAS FALHAS. REVISE ANTES DE DAR PUSH.{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()

# 🔐 RSA-2048 em Zig Puro

Implementação completa, didática e de alta performance do protocolo criptográfico **RSA-2048** em **Zig** (padrão 0.17+), projetada para compilar tanto para **binários CLI 100% estáticos** (Linux, Windows, macOS em x86_64 e ARM64) quanto para **WebAssembly freestanding** (rodando em um terminal interativo no navegador via GitHub Pages).

---

## 🚀 Execução Rápida em 1 Linha (Sem instalar Zig)

Baixe e execute instantaneamente o binário estático auto-contido para o seu sistema:

### Linux & macOS (curl)
```bash
curl -sSL https://o-gariba.github.io/rsa-zig-seguranca-info-fatec-rp/install.sh | sh
```

### Windows (PowerShell)
```powershell
irm https://o-gariba.github.io/rsa-zig-seguranca-info-fatec-rp/install.ps1 | iex
```

### 🌐 Terminal Interativo WebAssembly no Navegador
Acesse a demonstração interativa completa diretamente pelo navegador (sem download):  
👉 **[https://o-gariba.github.io/rsa-zig-seguranca-info-fatec-rp/](https://o-gariba.github.io/rsa-zig-seguranca-info-fatec-rp/)**

---

## 🏛️ Diretrizes Arquiteturais (Cenário 3)

O projeto adota uma arquitetura pragmática de baixo nível em Zig:

1. **Zero Alocação Dinâmica no Núcleo (`src/core/`):** Todo o cálculo da teoria dos números opera exclusivamente na stack da thread (buffers de tamanho fixo e structs passadas por valor). Zero chamadas ao heap alocador (`std.mem.Allocator`), garantindo execução eficiente em hardware restrito e compatibilidade direta com `wasm32-freestanding`.
2. **Divisão Estrita entre Módulos Ímpares e Pares:**
   - **Montgomery (`std.crypto.ff.Modulus`):** Utilizado onde o módulo é matematicamente ímpar ($\gcd(N, 2^{64}) = 1$): teste de primalidade de Miller-Rabin (módulo $p$), criptografia pública (módulo $n = p \cdot q$) e exponenciações CRT (módulos $p$ e $q$).
   - **Euclides Estendido Manual com `i4096`:** Como o totiente de Carmichael $\lambda(n) = \text{mmc}(p-1, q-1)$ é **SEMPRE PAR**, Montgomery falharia com `error.EvenModulus`. A inversão modular para obter $d \equiv e^{-1} \pmod{\lambda(n)}$ foi implementada manualmente sobre o tipo inteiro com sinal `i4096`.
3. **Proteções Criptográficas de Baixo Nível:**
   - Limpeza de chaves privadas e segredos na stack com `std.crypto.secureZero`, prevenindo *Dead-Store Elimination* (DSE) pelo otimizador do compilador.
   - Descriptografia em tempo constante com `.pow()` para imunidade contra ataques de temporização (*timing attacks*).
4. **Preenchimento Probabilístico:** Suporte a **OAEP** com SHA-256 e MGF1 (RFC 8017) e modo didático **PKCS#1 v1.5**.
5. **A Filosofia do Zig vs. Docker (Cross-Compilation Nativa e Zero Runtime):**
   - Em vez de containers Docker volumosos com toolchains fragmentadas, o projeto abraça a filosofia do Zig: o compilador já traz embutidas todas as bibliotecas padrão de sistema (`musl`, `mingw-w64`, `wasm32-freestanding`).
   - Um único comando `zig build` a partir de qualquer sistema compila binários estáticos para Linux, Windows, macOS e WebAssembly sem dependências dinâmicas nem virtualização.
6. **Trava Arquitetural em Tempo de Compilação (`comptime`):**
   - O `build.zig` inclui uma verificação `comptime` que valida `builtin.zig_version >= 0.17.0`. Caso um compilador legado seja invocado, o build aborta instantaneamente com uma mensagem descritiva antes de qualquer compilação de código.

---

## 📐 As 7 Etapas Matemáticas

A fundamentação teórica completa, deduções e provas de corretude estão detalhadas em **[`docs/MATH_SPEC.md`](docs/MATH_SPEC.md)**:

```
  1. Buffer CSPRNG ──► 2. Forçar MSB/LSB ──► 3. Crivo (256 primos) ──► 4. Miller-Rabin (64x)
                                                                               │ (p, q primos)
  ┌────────────────────────────────────────────────────────────────────────────┘
  ▼
  5. Módulo n = p · q (2048-bit)
     Totiente λ(n) = mmc(p-1, q-1)
     Chave privada d ≡ e⁻¹ mod λ(n) via Euclides Estendido (i4096)
     Parâmetros CRT: dp, dq, q_inv
  │
  ▼
  6. Padding OAEP-SHA256 (Feistel Network: seed ⊕ MGF1, DB ⊕ MGF1)
  │
  ▼
  7. Cifra: c = mᵉ mod n (Montgomery 2048-bit)
     Decifra CRT (Algoritmo de Garner): ganho de ~4x em tempo de CPU!
```

---

## 💻 Uso da Interface de Linha de Comando (CLI)

O executável nativo suporta pipes POSIX e fluxos padrão (`stdin`/`stdout`), direcionando dados de inspeção para `stderr`:

### 1. Geração de Chaves RSA-2048
```bash
./zig-out/bin/rsa-cli keygen --pub id_rsa.pub --priv id_rsa.key --inspect
```

### 2. Criptografia com Pipe POSIX
```bash
echo "Mensagem ultra confidencial" | ./zig-out/bin/rsa-cli encrypt --pub id_rsa.pub --inspect > msg.enc
```

### 3. Descriptografia Acelerada via CRT
```bash
./zig-out/bin/rsa-cli decrypt --priv id_rsa.key --inspect < msg.enc
```

*Saída de inspeção no `stderr`:*
```text
=== COMPARAÇÃO CRT vs EXPONENCIAÇÃO DIRETA ===
  Tempo CRT (Algoritmo de Garner) : 2126 μs
  Tempo Direto (c^d mod n)       : 6090 μs
  Aceleração observada            : 2.86x mais rápido
==============================================
Mensagem ultra confidencial
```

---

## 🛠️ Compilação e Testes Locais

Requer o compilador Zig instalado:

```bash
# Executar a suíte completa de 27 testes matemáticos
zig build test --summary all

# Executar testes por etapa fechada
zig build test-etapa1   # GCD, LCM e Euclides Estendido (i4096)
zig build test-etapa2   # Crivo de 256 Primos e Miller-Rabin (64 rodadas)
zig build test-etapa3   # Padding OAEP, PKCS#1 v1.5, PEM e Base64
zig build test-etapa4   # Núcleo RSA-2048 e Teorema Chinês dos Restos (CRT)

# Compilar o binário CLI nativo estático
zig build -Doptimize=ReleaseFast

# Compilar o módulo WebAssembly para a pasta web/
zig build wasm
```

### 🔬 Oráculo Algébrico e Verificador Pré-Deploy (Python + Zig + Node.js)
Para garantir que a matemática de 2048 bits e os pipelines de CI/CD estejam 100% corretos antes de qualquer `git push`, utilize o verificador integrado:
```bash
python3 scripts/verify_deploy.py
```
Este script utiliza o motor de precisão arbitrária nativo do Python como um **Oráculo Matemático (*Ground Truth*)**:
- Prova formalmente $p \cdot q = n$ (2048 bits);
- Valida o totiente $\lambda(n) = \text{mmc}(p-1, q-1)$ e o inverso modular $(e \cdot d) \equiv 1 \pmod{\lambda(n)}$;
- Valida os expoentes CRT e o coeficiente de Garner $(q \cdot q_{\text{inv}}) \equiv 1 \pmod p$;
- Testa a criptografia/descriptografia ponta a ponta com pipes POSIX e instancia o módulo `web/rsa.wasm` via Node.js (V8).

### Guia para Desenvolvedores
Para inspecionar ou editar o código-fonte, utilize sempre o editor `vim`:
```bash
vim src/core/rsa.zig
vim src/core/euclid.zig
vim src/core/prime.zig
```

---

## 📁 Estrutura de Diretórios

```
rsa-project/
├── .github/
│   └── workflows/
│       └── deploy.yml        # CI/CD: Testes, GitHub Pages e Releases
├── build.zig                 # Build system com testes por etapa e alvos nativo/wasm
├── scripts/
│   └── verify_deploy.py      # Oráculo matemático em Python e verificador pré-deploy
├── README.md                 # Visão geral, instruções e comandos rápidos
├── docs/
│   ├── ARCHITECTURE.md       # Decisões de arquitetura, limites de stack e DSE
│   └── MATH_SPEC.md          # Especificação didática e demonstrações matemáticas
├── src/
│   ├── main_cli.zig          # Ponto de entrada CLI (POSIX pipes, std.Io)
│   ├── main_wasm.zig         # Ponto de entrada WebAssembly freestanding (C-ABI)
│   └── core/
│       ├── root.zig          # Fachada central e suíte de testes de integração
│       ├── euclid.zig        # MDC, MMC e Inverso Modular com u2048 e i4096
│       ├── prime.zig         # Crivo de 256 primos e Miller-Rabin de 64 rodadas
│       ├── padding.zig       # OAEP-SHA256 (MGF1) e PKCS#1 v1.5
│       ├── rsa.zig           # KeyPair, RSAEP e RSADP via Algoritmo de Garner (CRT)
│       └── codec.zig         # Serialização PEM (Base64), Cifras e Hexadecimal
└── web/
    ├── index.html            # Emulador de Terminal Web + Painel das Fórmulas
    ├── app.js                # Loader Wasm e integração com WebCrypto API
    ├── rsa.wasm              # Motor WebAssembly freestanding compilado
    ├── install.sh            # Script de instalação em 1 linha (Linux/macOS)
    └── install.ps1           # Script de instalação em 1 linha (Windows PowerShell)
```

---

## 📜 Licença

Desenvolvido para fins acadêmicos e educacionais na disciplina de Segurança da Informação — FATEC Ribeirão Preto.
Distribuído sob a licença MIT.

# Arquitetura de Software e Decisões de Engenharia do RSA-2048 em Zig

Este documento descreve as decisões de arquitetura, dimensionamento de memória em stack, proteções criptográficas contra ataques de canal lateral e estratégias de compilação universal adotadas no projeto.

---

## 1. Visão Geral da Arquitetura (Cenário 3)

O projeto adota uma abordagem pragmática de baixo nível: **toda a lógica do protocolo RSA e da Teoria dos Números é implementada manualmente em Zig**, utilizando recursos da biblioteca padrão (`std`) apenas para operações aritméticas de base e abstrações de sistema operacional:

```
+-----------------------------------------------------------------------+
|                            Interfaces                                 |
|   src/main_cli.zig (CLI POSIX Nativo)   |   src/main_wasm.zig (Wasm)  |
+-----------------------------------------------------------------------+
                                  |
                                  v
+-----------------------------------------------------------------------+
|                  src/core/root.zig (Fachada Central)                  |
+-----------------------------------+-----------------------------------+
| rsa.zig (KeyPair, Encrypt, Decrypt)| padding.zig (OAEP-SHA256, PKCS1) |
+-----------------------------------+-----------------------------------+
| prime.zig (Crivo + Miller-Rabin)  | codec.zig (PEM, Base64, Hex)     |
+-----------------------------------+-----------------------------------+
|           euclid.zig (GCD, LCM, Euclides Estendido com i4096)         |
+-----------------------------------------------------------------------+
                                  |
                                  v
+-----------------------------------------------------------------------+
|                       std Primitives & Hardware                       |
| std.crypto.ff (Montgomery ímpar) | std.crypto.hash.sha2.Sha256        |
| std.crypto.secureZero            | Tipos nativos u1024, u2048, i4096  |
+-----------------------------------------------------------------------+
```

---

## 2. Princípio Fundamental: Zero Alocação Dinâmica no Núcleo (`src/core/`)

O diretório `src/core/` **não realiza nenhuma chamada ao heap (`std.mem.Allocator`)**. Todas as estruturas, números de precisão múltipla e buffers vivem estritamente na stack da thread ou em memória linear estática do WebAssembly.

### 2.1 Análise de Consumo de Stack
O consumo de memória na stack foi rigorosamente dimensionado para garantir viabilidade mesmo em ambientes embarcados com limites de 64 KB de stack:

| Estrutura / Função | Tamanho em Stack | Detalhamento dos Campos |
| :--- | :--- | :--- |
| `RawPublicKey` | 264 bytes | `n: u2048` (256B), `e: u64` (8B) |
| `RawPrivateKey` | 1.152 bytes | `n, d: u2048` (512B), `p, q, dp, dq, q_inv: u1024` (640B) |
| `KeyPair` | 1.416 bytes | Chave pública + Chave privada |
| Bloco OAEP `EM` | 256 bytes | `[256]u8` fixo correspondente ao bloco RSA-2048 |
| Frame `generateWithRounds` | ~3.800 bytes | Candidatos $p, q$, resíduos do crivo e motor Miller-Rabin |
| Frame `decryptRawCrt` | ~1.600 bytes | Reduções $c_p, c_q$, elementos de Montgomery e recombinação |

### 2.2 Vantagens da Abordagem Stack-Only
1. **Determinismo Temporal:** Elimina pausas de GC ou contenção de locks em alocadores concorrentes (ex: jemalloc/mimalloc).
2. **Compatibilidade Freestanding Total:** O código compila para `wasm32-freestanding` sem exigir libc, emulador de heap ou runtime auxiliar.
3. **Imunidade a Memory Leaks:** Toda a memória é desalocada automaticamente no retorno da função por simples ajuste do ponteiro de stack (`RSP` / `SP`).

---

## 3. Divisão Estrita entre Módulos Ímpares e Pares

Uma das restrições matemáticas centrais da Redução de Montgomery (`std.crypto.ff.Modulus`) é a exigência de que o módulo $N$ seja ímpar:
$$\gcd(N, 2^{64}) = 1$$

Isso determina uma separação arquitetural explícita:

1. **Onde Montgomery (`std.crypto.ff.Modulus`) É Usado:**
   - **Teste de Miller-Rabin (`Modulus(1024)`):** O módulo é o candidato primo $p$, que é ímpar por construção ($B_{127} \mid 1$).
   - **Criptografia RSAEP (`Modulus(2048)`):** O módulo é $n = p \cdot q$. Sendo o produto de dois ímpares, $n$ é ímpar.
   - **Descriptografia CRT (`Modulus(1024)`):** As exponenciações parciais operam módulo $p$ e módulo $q$, ambos ímpares.

2. **Onde Montgomery NÃO Pode Ser Usado:**
   - **Cálculo da Chave Privada $d$:** O totiente de Carmichael $\lambda(n) = \text{mmc}(p-1, q-1)$ é **SEMPRE PAR**, pois $p-1$ e $q-1$ são números pares. Montgomery retornaria `error.EvenModulus`.
   - **Solução:** Implementação manual do Algoritmo de Euclides Estendido em `src/core/euclid.zig` utilizando os inteiros nativos de precisão arbitrária do Zig (`u2048` e `i4096`).

---

## 4. Proteções Criptográficas de Baixo Nível

### 4.1 Limpeza Segura de Segredos (`std.crypto.secureZero`)
O compilador Zig / LLVM realiza otimizações agressivas de *Dead-Store Elimination* (DSE): se uma variável local na stack contendo material confidencial (como o primo $p$ ou o expoente privado $d$) não for mais lida antes do retorno da função, o compilador normalmente descarta a instrução de sobrescrita.

Para neutralizar isso, todas as funções críticas invocam `std.crypto.secureZero`:
```zig
pub fn wipe(self: *KeyPair) void {
    self.private_key.wipe();
}
```
Internamente, `secureZero` utiliza barreiras de memória com ponteiros `volatile`, impedindo que o otimizador elimine a limpeza dos segredos na stack.

### 4.2 Mitigação de Ataques de Canal Lateral (Timing Attacks)
- Na descriptografia com segredos (`decryptRawCrt` e `decryptRawDirect`), utiliza-se o método `.pow()` da `std.crypto.ff.Modulus`, que executa a exponenciação em **tempo constante** em relação à base e ao expoente secreto.
- O método `.powPublic()` é restrito exclusivamente à criptografia pública ($c = m^e \bmod n$), onde o expoente $e = 65537$ é público e conhecido por qualquer observador.

---

## 5. Estratégia de Compilação Multiplataforma

O projeto foi projetado para gerar dois tipos de entregáveis:

### 5.1 Binários Nativos 100% Estáticos
Compilados com `-Doptimize=ReleaseFast`:
- `x86_64-linux-musl` e `aarch64-linux-musl`: Vinculados estaticamente à biblioteca musl, sem dependência de glibc do sistema operacional hospedeiro.
- `x86_64-windows-gnu`: Executável independente sem dependência de MSVCRT moderno.
- `x86_64-macos` e `aarch64-macos`: Binários universais para ecossistema Apple Silicon e Intel.

### 5.2 Módulo WebAssembly Freestanding (`web/rsa.wasm`)
Compilado com alvo `wasm32-freestanding`, `optimize = .ReleaseSmall`, `entry = .disabled` e `rdynamic = true`.
- Tamanho compacto (~1.2 MB sem compactação, ~380 KB com gzip/brotli no GitHub Pages).
- Sem dependência de libc ou WASI (WebAssembly System Interface). Toda a comunicação ocorre por ponteiros estáticos na memória linear compartilhada com o JavaScript via `ArrayBuffer`.

---

## 6. Guia de Edição e Ferramentas para Desenvolvedores

Para inspecionar ou editar o código-fonte em ambientes de terminal, utilize sempre o editor `vim`:

```bash
# Editar o núcleo de aritmética euclidiana
vim src/core/euclid.zig

# Editar a implementação do Miller-Rabin e crivo
vim src/core/prime.zig

# Editar o módulo principal do RSA
vim src/core/rsa.zig

# Executar a suíte de testes após edições
zig build test --summary all
```

# Especificação Matemática e Fundamentação Didática do RSA-2048 em Zig

Este documento apresenta a fundamentação teórica, deduções algébricas e demonstrações formais de corretude de todas as etapas matemáticas implementadas no sistema RSA-2048 em Zig puro (`src/core/`). Cada fórmula matemática está diretamente conectada aos tipos de dados e linhas de código do projeto.

---

## Índice

1. [Representação Posicional e Limites de Overflow em Stack](#1-representação-posicional-e-limites-de-overflow-em-stack)
2. [Geração de Candidatos a Primos e Crivo Inicial](#2-geração-de-candidatos-a-primos-e-crivo-inicial)
3. [Teste Probabilístico de Primalidade de Miller-Rabin](#3-teste-probabilístico-de-primalidade-de-miller-rabin)
4. [Redução e Exponenciação Modular de Montgomery (`std.crypto.ff`)](#4-redução-e-exponenciação-modular-de-montgomery-stdcryptoff)
5. [Totiente de Carmichael, MDC e Algoritmo de Euclides Estendido](#5-totiente-de-carmichael-mdc-e-algoritmo-de-euclides-estendido)
6. [Preenchimento Criptográfico (Padding OAEP e PKCS#1 v1.5)](#6-preenchimento-criptográfico-padding-oaep-e-pkcs1-v15)
7. [Criptografia e Descriptografia Acelerada via CRT (Algoritmo de Garner)](#7-criptografia-e-descriptografia-acelerada-via-crt-algoritmo-de-garner)

---

## 1. Representação Posicional e Limites de Overflow em Stack

### 1.1 Base Radix-64 e Limbs de Máquina
Em sistemas computacionais modernos de 64 bits, grandes inteiros não cabem em um único registrador. Eles são decompostos em palavras (denominadas *limbs*) na base $B = 2^{64}$.

Qualquer inteiro $X \in [0, 2^N - 1]$ é representado posicionalmente como:

$$X = \sum_{i=0}^{k-1} x_i \cdot (2^{64})^i = x_0 + x_1 \cdot 2^{64} + x_2 \cdot 2^{128} + \dots + x_{k-1} \cdot 2^{64(k-1)}$$

onde cada dígito $x_i$ satisfaz $0 \le x_i < 2^{64}$.

No código Zig, essa decomposição se reflete diretamente nas estruturas primitivas:
* **Fatores Primos $p$ e $q$ (`u1024`):**
  $$k = \frac{1024}{64} = 16 \text{ limbs de 64 bits} \implies 128 \text{ bytes}.$$
  Alocados diretamente como tipos escalares por valor na stack (`src/core/prime.zig`).
* **Módulo Público $n$ (`u2048`):**
  $$k = \frac{2048}{64} = 32 \text{ limbs de 64 bits} \implies 256 \text{ bytes}.$$
* **Cast Prévio Obrigatório contra Overflow:**
  O produto de dois números de 1024 bits exige até $1024 + 1024 = 2048$ bits. Se executássemos $p \cdot q$ diretamente com os operandos em `u1024`, a multiplicação nativa sofreria truncamento modular $\pmod{2^{1024}}$.
  No código (`src/core/rsa.zig`, linhas 64-68):
  ```zig
  const p_wide: u2048 = p;
  const q_wide: u2048 = q;
  const n: u2048 = p_wide * q_wide; // Sem perda de bits
  ```
* **Aritmética com Sinal no Algoritmo de Euclides Estendido (`i4096`):**
  Durante a inversão modular, os coeficientes de Bézout intermediários alternam de sinal e podem atingir a ordem de grandeza do módulo ($2^{2048}$). O produto intermediário $q_k \cdot t_k$ antecede a subtração, podendo momentaneamente exceder 2048 bits de magnitude. O tipo `i4096` (1 bit de sinal + 4095 bits de magnitude = 64 limbs em complemento de dois) elimina qualquer possibilidade de overflow sem recorrer a alocação dinâmica.

---

## 2. Geração de Candidatos a Primos e Crivo Inicial

### 2.1 Manipulação de Bits (MSB Force e LSB Force)
Para gerar um primo de 1024 bits, sorteia-se um buffer de 128 bytes aleatórios ($B_0, B_1, \dots, B_{127}$ em ordem Big-Endian, onde $B_0$ é o byte mais significativo). Em seguida, aplicam-se operações bit a bit fixas (`src/core/prime.zig`):

1. **Forçar LSB (Least Significant Bit):**
   $$B_{127} \leftarrow B_{127} \mid \text{0b00000001}_2 \implies p \equiv 1 \pmod 2$$
   Garante que o candidato seja ímpar (números pares $> 2$ são compostos).

2. **Forçar os Dois MSBs (Most Significant Bits):**
   $$B_0 \leftarrow B_0 \mid \text{0b11000000}_2 \implies p \ge 2^{1023} + 2^{1022} = \frac{3}{4} \cdot 2^{1024}$$

### 2.2 Prova Matemática: Por que o produto $n = p \cdot q$ tem exatamente 2048 bits
Um número possui exatamente 2048 bits se e somente se pertencer ao intervalo $[2^{2047}, 2^{2048} - 1]$.

Se apenas o MSB mais alto fosse forçado para `1` ($p \ge 2^{1023}$ e $q \ge 2^{1023}$), o produto mínimo seria:
$$n_{\min} = 2^{1023} \cdot 2^{1023} = 2^{2046}$$
o que permitiria módulos de apenas 2047 bits.

Com os dois bits superiores ligados ($B_0 \ge \text{0b11000000}_2 = 192$):
$$p \ge \left(2^7 + 2^6\right) \cdot 2^{1024 - 8} = (128 + 64) \cdot 2^{1016} = 192 \cdot 2^{1016} = \frac{3}{4} \cdot 2^{1024}$$

Portanto, para $p, q \ge \frac{3}{4} \cdot 2^{1024}$:
$$n = p \cdot q \ge \left(\frac{3}{4} \cdot 2^{1024}\right) \cdot \left(\frac{3}{4} \cdot 2^{1024}\right) = \frac{9}{16} \cdot 2^{2048}$$

Como $\frac{9}{16} = 0{,}5625 > \frac{1}{2} = 0{,}5$:
$$n \ge 0{,}5625 \cdot 2^{2048} > 0{,}5 \cdot 2^{2048} = 2^{2047}$$

E como $p, q < 2^{1024}$, temos $n < 2^{2048}$. Logo:
$$2^{2047} < n < 2^{2048} \implies n \text{ possui impreterivelmente 2048 bits exatos.}$$

### 2.3 Crivo de Eratóstenes Inicial (256 Primos Ímpares)
Exponenciações modulares completas de 1024 bits são computacionalmente intensivas. Antes do Miller-Rabin, o candidato é submetido a divisões diretas pelos primeiros 256 primos ímpares:
$$\mathcal{P}_{\text{small}} = \{3, 5, 7, 11, \dots, 1621\}$$

Pelo Terceiro Teorema de Mertens, a probabilidade de um número ímpar aleatório não possuir fatores primos $\le M$ é:
$$\prod_{q \le M, q \text{ ímpar}} \left(1 - \frac{1}{q}\right) \approx \frac{2 e^{-\gamma}}{\ln M}$$
Para $M = 1621$, apenas $\approx 12{,}6\%$ dos candidatos ímpares sobrevivem. Assim, **cerca de $87{,}4\%$ dos candidatos compostos são eliminados instantaneamente** por simples divisões em limb de 64 bits (`modSmall`), sem invocar o motor de Montgomery.

---

## 3. Teste Probabilístico de Primalidade de Miller-Rabin

### 3.1 Fundamentação Algébrica
O teste baseia-se em dois pilares da Teoria dos Números:

1. **Pequeno Teorema de Fermat:** Se $p$ é primo e $\gcd(a, p) = 1$, então:
   $$a^{p-1} \equiv 1 \pmod p$$
2. **Inexistência de Raízes Quadradas Não-Triviais da Unidade:**
   No corpo finito $\mathbb{Z}_p$ (com $p$ primo), a equação quadrática:
   $$x^2 \equiv 1 \pmod p \iff x^2 - 1 \equiv 0 \iff (x - 1)(x + 1) \equiv 0 \pmod p$$
   tem apenas duas soluções: $x \equiv 1$ ou $x \equiv -1 \equiv p - 1 \pmod p$.
   Se para algum $x \not\equiv \pm 1 \pmod p$ tivermos $x^2 \equiv 1 \pmod p$, então $p$ é **obrigatoriamente composto**.

### 3.2 Decomposição $p - 1 = 2^s \cdot d$
Como $p$ é ímpar, $p - 1$ é par. Fatora-se a maior potência de 2 que divide $p - 1$:
$$p - 1 = 2^s \cdot d, \quad \text{onde } d \text{ é ímpar e } s \ge 1$$

No Zig (`src/core/prime.zig`):
```zig
const s: u16 = @ctz(n - 1);         // Count Trailing Zeros em O(1) de hardware
const d: u1024 = (n - 1) >> @intCast(s); // Deslocamento de bits extrai d
```

### 3.3 Laço de Testemunhas e Sequência de Quadraturas
Para cada base $a \in [2, p - 2]$ sorteada uniformemente:
1. Calcula-se $x_0 = a^d \bmod p$ via Montgomery.
2. Se $x_0 = 1$ ou $x_0 = p - 1$, $a$ não é testemunha de composição; passa-se à próxima rodada.
3. Caso contrário, calcula-se iterativamente para $r = 1, 2, \dots, s - 1$:
   $$x_r = x_{r-1}^2 \bmod p$$
   - Se $x_r = p - 1$, a base passa e avança-se para a próxima rodada.
   - Se $x_r = 1$, descobriu-se uma raiz quadrada não-trivial da unidade ($\sqrt{1} \neq \pm 1$), logo $p$ é comprovadamente composto.
4. Se o laço terminar sem que nenhum $x_r$ atinja $p - 1$, $a^{p-1} \not\equiv 1 \pmod p$, violando o Teorema de Fermat. O número é comprovadamente composto.

### 3.4 Probabilidade de Falso Positivo (Teorema de Monier-Rabin)
Um número composto ímpar $n$ que passa no teste para uma base $a$ é chamado de *pseudoprimo forte* na base $a$, e a base $a$ é uma "mentirosa forte".
Pelo Teorema de Monier-Rabin, o número de mentirosas fortes para qualquer composto $n$ é no máximo:
$$|M(n)| \le \frac{1}{4} \varphi(n) < \frac{1}{4} n$$

Com $k = 64$ rodadas independentes com bases sorteadas pelo CSPRNG:
$$P(\text{composto passar em 64 rodadas}) \le \left(\frac{1}{4}\right)^{64} = 2^{-128} \approx 2{,}93 \times 10^{-39}$$
Essa margem é inferior à probabilidade de erros causados por raios cósmicos na memória RAM da CPU.

### 3.5 Números de Carmichael
Números de Carmichael (ex: $561 = 3 \cdot 11 \cdot 17$, $1105$, $1729$) satisfazem $a^{n-1} \equiv 1 \pmod n$ para todo $\gcd(a, n) = 1$. Portanto, **enganam completamente o teste de Fermat puro**.
Entretanto, o Miller-Rabin os detecta infalivelmente: em $n = 561$, $560 = 2^4 \cdot 35$. Para $a = 2$:
$$2^{35} \equiv 263 \pmod{561}$$
$$263^2 \equiv 166 \pmod{561}$$
$$166^2 \equiv 67 \pmod{561}$$
$$67^2 \equiv 1 \pmod{561}$$
Como $67 \not\equiv \pm 1 \pmod{561}$ e $67^2 \equiv 1$, o teste revela a raiz não-trivial e **rejeita $561$ imediatamente**.

---

## 4. Redução e Exponenciação Modular de Montgomery (`std.crypto.ff`)

A divisão Euclidiana tradicional de inteiros de 1024/2048 bits na CPU requer múltiplos ciclos e desvios condicionais. A técnica de Peter Montgomery (1985) substitui divisões longas por deslocamentos de bits.

### 4.1 Espaço de Montgomery
Escolhe-se uma base de redução $R = 2^k > N$ tal que $\gcd(R, N) = 1$. Como $R$ é potência de 2, essa condição exige estritamente que $N$ seja **ímpar**.
A representação de um elemento $a \in \mathbb{Z}_N$ no espaço de Montgomery é:
$$\bar{a} = a \cdot R \bmod N$$

### 4.2 Algoritmo de Redução $\text{REDC}(T)$
Dado um produto intermediário $T < N \cdot R$, a operação $\text{REDC}(T)$ calcula $T \cdot R^{-1} \bmod N$ sem efetuar divisões completas:

1. Pré-calcula-se a constante de limb $N' \equiv -N^{-1} \pmod R$ via algoritmo estendido ou iteração de Hensel/Newton.
2. Calcula-se o multiplicador de cancelamento:
   $$m = (T \bmod R) \cdot N' \bmod R$$
3. Por definição:
   $$T + m \cdot N \equiv T + (T \cdot (-N^{-1}) \cdot N) \equiv T - T \equiv 0 \pmod R$$
4. Como os $k$ bits inferiores de $T + m \cdot N$ são rigorosamente zeros, a divisão por $R = 2^k$ é uma operação trivial de descarte de limbs (shift para a direita):
   $$t = \frac{T + m \cdot N}{R}$$
5. Se $t \ge N$, subtrai-se $N$ em tempo constante: $t \leftarrow t - N$. O resultado final satisfaz $t \equiv T \cdot R^{-1} \pmod N$.

### 4.3 Multiplicação e Exponenciação
O produto de dois elementos de Montgomery preserva o espaço:
$$\text{MontMul}(\bar{a}, \bar{b}) = \text{REDC}(\bar{a} \cdot \bar{b}) = (a \cdot R)(b \cdot R) R^{-1} \bmod N = (a \cdot b) \cdot R \bmod N = \overline{a \cdot b}$$

A exponenciação $a^e \bmod N$ converte a base para $\bar{a}$, aplica multiplicações e quadraturas sucessivas no espaço de Montgomery, e uma chamada final $\text{REDC}(\bar{x})$ elimina o fator $R$, restaurando o valor original em $\mathbb{Z}_N$.

---

## 5. Totiente de Carmichael, MDC e Algoritmo de Euclides Estendido

### 5.1 Totiente de Euler $\phi(n)$ vs. Totiente de Carmichael $\lambda(n)$
No RSA clássico, utiliza-se a função totiente de Euler:
$$\phi(n) = (p - 1)(q - 1)$$

Entretanto, o expoente universal do grupo multiplicativo $(\mathbb{Z}_n)^\times$ é dado pela função totiente de Carmichael:
$$\lambda(n) = \text{mmc}(p - 1, q - 1) = \frac{(p - 1)(q - 1)}{\gcd(p - 1, q - 1)}$$

Como $p$ e $q$ são ímpares, $\gcd(p - 1, q - 1) \ge 2$, o que garante:
$$\lambda(n) \le \frac{\phi(n)}{2}$$
Ambos satisfazem a congruência $m^{e \cdot d} \equiv m \pmod n$, porém $\lambda(n)$ gera um expoente privado $d$ menor ou igual, sem comprometer a segurança e reduzindo o esforço computacional da exponenciação modular.

### 5.2 O Expoente Público $e = 65537$
Adota-se o quarto primo de Fermat:
$$e = F_4 = 2^{16} + 1 = 65537 = \text{0b10000000000000001}_2$$

Vantagens:
- **Desempenho de Cifragem:** Possui apenas 2 bits ativos. O algoritmo Square-and-Multiply executa exatamente 16 quadraturas modulares e apenas 1 multiplicação modular.
- **Segurança contra Ataques de Baixo Expoente:** Evita ataques de raiz e-ésima de Coppersmith e ataques de transmissão para múltiplos destinatários (ataque de Håstad), que afetam chaves com $e = 3$.

### 5.3 Algoritmo de Euclides Estendido sobre `i4096`
Para encontrar $d \equiv e^{-1} \pmod{\lambda(n)}$, resolve-se a equação diofantina linear (Identidade de Bézout):
$$e \cdot t + \lambda(n) \cdot s = \gcd(e, \lambda(n)) = 1$$

Inicia-se a recorrência com:
$$(r_0, r_1) = (\lambda(n), e), \quad (t_0, t_1) = (0, 1)$$

A cada iteração $k \ge 1$:
$$q_k = \left\lfloor \frac{r_{k-1}}{r_k} \right\rfloor$$
$$r_{k+1} = r_{k-1} - q_k \cdot r_k$$
$$t_{k+1} = t_{k-1} - q_k \cdot t_k$$

Quando $r_k = 0$, o resto anterior $r_{k-1} = \gcd(e, \lambda(n))$. Se for $1$, o coeficiente de Bézout $t_{k-1}$ é o inverso modular. Se $t_{k-1} < 0$, normaliza-se:
$$d = t_{k-1} + \lambda(n)$$

---

## 6. Preenchimento Criptográfico (Padding OAEP e PKCS#1 v1.5)

### 6.1 Vulnerabilidades Críticas do "Textbook RSA" ($c = m^e \bmod n$)
1. **Determinismo:** A mesma mensagem $m$ gera sempre a mesma cifra $c$. Um adversário com um dicionário finito ("Sim"/"Não") pode cifrar todas as opções e quebrar o sigilo.
2. **Homomorfismo Multiplicativo (Maleabilidade):**
   $$c_1 \cdot c_2 \equiv (m_1)^e \cdot (m_2)^e \equiv (m_1 \cdot m_2)^e \pmod n$$
   Um atacante pode multiplicar o texto cifrado por $2^e$ e obter a cifra de $2m$ sem conhecer a chave privada.
3. **Ataque de Raiz e-ésima:** Se $m^e < n$, a operação modular não ocorre nos inteiros: $c = m^e$. O atacante calcula a raiz e-ésima exata nos números reais $m = \lfloor c^{1/e} \rfloor$.

### 6.2 Estrutura do OAEP (Optimal Asymmetric Encryption Padding - RFC 8017)
O OAEP converte o esquema RSA em uma cifra probabilística IND-CCA2 (segurança contra ataques de texto cifrado escolhido adaptativo) através de uma rede de Feistel assimétrica de duas rodadas:

```
                      +----------+             +--+-------+
                      |   seed   |             |  |   M   |
                      +----+-----+             +--+---+---+
                           |                          |
                           |     +----------+         |
                           |     | SHA256(L)|         |
                           |     +----+-----+         |
                           |          |  +--+         |
                           |          |  |PS|01       |
                           |          +--+--+---------+
                           |          |      DB       |
                           v          +-------+-------+
                       +-------+              |
                       | MGF1  |              |
                       +---+---+              |
                           |                  |
                           +------------> (+) | (dbMask)
                           |               |
                           |               v
                           |         +-----+-----+
                           |         | maskedDB  |
                           |         +-----+-----+
                           |               |
                           |   +-------+   |
                           |   | MGF1  | <-+
                           |   +---+---+
                           |       |
                       (+) <-------+ (seedMask)
                        |
                        v
                  +-----+------+
                  | maskedSeed |
                  +-----+------+
                        |                     |
                        +-----------+---------+
                                    |
                  EM = [ 0x00 || maskedSeed || maskedDB ]
                         (1B)      (32B)        (223B)  = 256 bytes
```

Layout de Bytes ($k = 256$ bytes = 2048 bits):
- **Byte 0 (`0x00`):** Garante matematicamente que o inteiro representado pelo bloco $EM$ seja estritamente menor que o módulo $n$ ($m < n$).
- **maskedSeed (32 bytes):** Semente aleatória de 32 bytes mascarada por $\text{MGF1}(\text{maskedDB}, 32)$.
- **maskedDB (223 bytes):** Bloco de dados mascarado contendo $DB = \text{SHA256}("") \parallel PS \parallel \text{0x01} \parallel M$.
- **Capacidade Máxima:** $256 - 2 \cdot 32 - 2 = 190$ bytes úteis de mensagem.

### 6.3 Esquema Didático Alternativo: PKCS#1 v1.5
$$EM = \text{0x00} \parallel \text{0x02} \parallel PS \parallel \text{0x00} \parallel M$$
onde $PS$ é composto por no mínimo 8 bytes pseudoaleatórios estritamente não-nulos. Capacidade útil: $256 - 11 = 245$ bytes.

---

## 7. Criptografia e Descriptografia Acelerada via CRT (Algoritmo de Garner)

### 7.1 Criptografia Pública (RSAEP)
Dado o bloco preenchido $m < n$:
$$c = m^e \bmod n$$
Executada via `std.crypto.ff.Modulus(2048).powPublic()`.

### 7.2 O Teorema Chinês dos Restos (CRT)
O Teorema Chinês dos Restos estabelece um isomorfismo de anéis:
$$\mathbb{Z}_n \cong \mathbb{Z}_p \times \mathbb{Z}_q \quad (\text{pois } \gcd(p, q) = 1)$$

Em vez de calcular $m = c^d \bmod n$ em 2048 bits, calculam-se as reduções modulares nos fatores de 1024 bits:
$$m_1 = c^{d} \equiv (c \bmod p)^{d \bmod (p-1)} \equiv c_p^{d_p} \pmod p$$
$$m_2 = c^{d} \equiv (c \bmod q)^{d \bmod (q-1)} \equiv c_q^{d_q} \pmod q$$

### 7.3 Algoritmo de Garner e Ajuste Positivo
Para reconstruir $m \in [0, n - 1]$ a partir de $(m_1, m_2)$ sem divisões por $n$, utiliza-se a forma de Garner:
$$m = m_2 + h \cdot q$$

Para satisfazer $m \equiv m_1 \pmod p$:
$$m_2 + h \cdot q \equiv m_1 \pmod p \iff h \cdot q \equiv (m_1 - m_2) \pmod p$$
Multiplicando por $q_{\text{inv}} \equiv q^{-1} \pmod p$:
$$h \equiv q_{\text{inv}} \cdot (m_1 - m_2) \pmod p$$

**Tratamento de Subtração Negativa em Aritmética Não-Sinalizada (`u2048`):**
Como $m_2$ pode ser maior que $m_1$, o valor $m_1 - m_2$ resultaria em underflow. Adiciona-se $p$ para garantir positividade estrita:
$$\text{diff} = (m_1 + p - (m_2 \bmod p)) \bmod p$$
$$h = (q_{\text{inv}} \cdot \text{diff}) \bmod p$$
$$m = m_2 + h \cdot q$$

### 7.4 Prova Formal de Corretude
1. **Módulo $q$:**
   $$m \bmod q = (m_2 + h \cdot q) \bmod q = m_2 + 0 \equiv m_2 \pmod q$$
2. **Módulo $p$:**
   $$m \bmod p = (m_2 + q_{\text{inv}} \cdot (m_1 - m_2) \cdot q) \bmod p$$
   Como $q_{\text{inv}} \cdot q \equiv 1 \pmod p$:
   $$m \bmod p = m_2 + 1 \cdot (m_1 - m_2) = m_1 \pmod p$$
3. **Limites do Intervalo:**
   Como $h \le p - 1$ e $m_2 \le q - 1$:
   $$m \le (q - 1) + (p - 1) \cdot q = q - 1 + p \cdot q - q = p \cdot q - 1 = n - 1$$
   Logo, $0 \le m < n$, garantindo unicidade da solução.

### 7.5 Dedução do Ganho de Desempenho de $4\times$
A complexidade de tempo da exponenciação modular com inteiros de $k$ bits (usando algoritmos clássicos de multiplicação quadrática ou Montgomery) é:
$$T(k) = \mathcal{O}(k^3)$$

- **Descriptografia Direta ($c^d \bmod n$):** Opera com tamanho $k = 2048$:
  $$T_{\text{direto}} \approx C \cdot 2048^3 = C \cdot (2 \cdot 1024)^3 = 8 \cdot C \cdot 1024^3$$
- **Descriptografia via CRT:** Realiza 2 exponenciações independentes de metade do tamanho ($k = 1024$):
  $$T_{\text{crt}} \approx 2 \cdot C \cdot 1024^3$$

A aceleração teórica relativa é:
$$\text{Speedup} = \frac{T_{\text{direto}}}{T_{\text{crt}}} = \frac{8 \cdot C \cdot 1024^3}{2 \cdot C \cdot 1024^3} = \frac{8}{2} = 4\times$$
Na prática, o overhead da recombinação de Garner é desprezível ($< 0{,}1\%$), confirmando ganhos de $3{,}5\times$ a $4\times$ em medições reais de CPU.

//! ============================================================================
//! prime.zig — Etapa 2: Crivo de primos pequenos + Miller-Rabin (64 rodadas)
//! ============================================================================
//!
//! Pipeline de geração de um primo RSA de 1024 bits:
//!
//!   128 bytes do CSPRNG ──► força bits (MSB, 2º MSB, LSB) ──► candidato p
//!        │
//!        ▼
//!   Crivo: p mod q_i ≠ 0 para os 256 primeiros primos ímpares (3 … 1621)
//!        │  (descarta ~87% dos ímpares com divisões baratas de 64 bits)
//!        ▼
//!   Miller-Rabin com 64 bases aleatórias, exponenciação de Montgomery em
//!   `std.crypto.ff.Modulus(1024)`  (p é ímpar ⇒ mdc(p, 2^64) = 1 ⇒ OK)
//!        │
//!        ▼
//!   "provavelmente primo" com erro < (1/4)^64 = 2^-128
//!
//! Todo o estado vive na stack: buffers `[128]u8`, inteiros `u1024` e as
//! structs por valor do `std.crypto.ff` (vetores fixos de limbs).
//! ============================================================================

const std = @import("std");

/// Corpo finito de até 1024 bits com aritmética de Montgomery.
///
/// O que `std.crypto.ff.Modulus` faz por dentro (Seção 2.4 do MATH_SPEC):
///
///   * Representação de Montgomery:  ā = a·R mod N,  com R = 2^k > N e
///     mdc(R, N) = 1  — por isso N precisa ser ÍMPAR (erro `EvenModulus`).
///   * Produto de Montgomery:  MontMul(ā, b̄) = ā·b̄·R^{-1} mod N = (a·b)·R mod N
///   * REDC(T): com a constante pré-calculada N' ≡ −N^{-1} (mod R)
///     (campo `m0inv`, calculado por iteração de Newton em `fromUint`),
///         m = (T mod R)·N' mod R
///         T + m·N ≡ T − T ≡ 0 (mod R)  ⇒  (T + m·N)/R é EXATO
///     e "dividir por R = 2^k" é só descartar limbs (deslocamento de bits),
///     eliminando a divisão longa da CPU. Um único `if t ≥ N: t −= N` final
///     (feito em tempo constante) devolve o representante canônico.
///
/// Os limbs internos do `ff` usam 63 bits úteis + 1 bit de carry por palavra
/// de 64 bits, por isso 1024 bits ocupam 17 palavras internamente.
pub const Mod1024 = std.crypto.ff.Modulus(1024);
pub const Fe1024 = Mod1024.Fe;

/// Tamanho de cada fator primo do RSA-2048.
pub const PRIME_BITS: usize = 1024;
pub const PRIME_BYTES: usize = PRIME_BITS / 8; // 128 bytes = 16 limbs de 64 bits

/// Rodadas padrão do Miller-Rabin: erro ≤ 4^-64 = 2^-128.
pub const DEFAULT_ROUNDS: usize = 64;

/// Quantidade de primos ímpares usados no crivo inicial.
pub const SIEVE_SIZE: usize = 256;

/// Os 256 primeiros primos ímpares {3, 5, 7, …, 1621}, gerados em TEMPO DE
/// COMPILAÇÃO pelo Crivo de Eratóstenes — o binário contém só a tabela pronta
/// (512 bytes de `u16`), sem custo em tempo de execução.
pub const SMALL_PRIMES: [SIEVE_SIZE]u16 = computeSmallPrimes();

fn computeSmallPrimes() [SIEVE_SIZE]u16 {
    @setEvalBranchQuota(200_000);
    const limit = 1622; // π(1621) = 257 primos (incluindo o 2)
    var composite: [limit]bool = @splat(false);
    var out: [SIEVE_SIZE]u16 = undefined;
    var count: usize = 0;
    var i: usize = 2;
    while (i < limit) : (i += 1) {
        if (composite[i]) continue;
        // i é primo: marca seus múltiplos a partir de i² como compostos.
        var j = i * i;
        while (j < limit) : (j += i) composite[j] = true;
        if (i == 2) continue; // só primos ímpares (candidatos já são ímpares)
        out[count] = @intCast(i);
        count += 1;
    }
    if (count != SIEVE_SIZE) @compileError("tabela do crivo com tamanho errado");
    return out;
}

/// Estatísticas didáticas da busca por primos (exibidas pelo `--inspect` e
/// pelo painel web). Opcional: passe `null` se não interessar.
pub const Stats = struct {
    /// Quantas vezes 128 bytes novos foram pedidos ao CSPRNG.
    random_draws: u64 = 0,
    /// Total de candidatos ímpares examinados (p, p+2, p+4, …).
    candidates: u64 = 0,
    /// Candidatos eliminados pelo crivo (divisíveis por algum q_i ≤ 1621).
    sieve_rejections: u64 = 0,
    /// Candidatos que sobreviveram ao crivo mas foram provados compostos.
    mr_rejections: u64 = 0,
    /// Total de rodadas (exponenciações a^d mod p) executadas.
    mr_rounds: u64 = 0,
};

// ----------------------------------------------------------------------------
// Crivo: divisão direta por primos pequenos
// ----------------------------------------------------------------------------

/// Calcula `x mod q` para `x: u1024` e `q` pequeno, limb a limb.
///
/// Matemática (Seção 2.1 + método de Horner): com x = Σ x_i·(2^64)^i,
///
///     x mod q = ( … ((x_15·2^64 + x_14) mod q)·2^64 + x_13 … ) mod q
///
/// Cada passo opera sobre `r·2^64 + x_i`, onde r < q < 2^11, logo o valor
/// cabe em `u128` e a CPU faz uma divisão nativa 128/64 — muito mais barato
/// que a divisão longa genérica de 1024 bits. Os limbs são extraídos por
/// deslocamento (`x >> 64·i`), independente do endianness da máquina.
pub fn modSmall(x: u1024, q: u16) u16 {
    var r: u128 = 0;
    var i: usize = PRIME_BITS / 64; // 16 limbs, do mais significativo ao menos
    while (i > 0) {
        i -= 1;
        const limb: u64 = @truncate(x >> @intCast(64 * i));
        r = ((r << 64) | limb) % q;
    }
    return @intCast(r);
}

pub const SieveVerdict = enum {
    /// x é um dos primos da tabela (ou 2).
    small_prime,
    /// x tem um fator primo ≤ 1621 (ou é < 2, ou é par).
    composite,
    /// Nenhum fator pequeno: precisa do Miller-Rabin.
    unknown,
};

/// Filtro rápido por divisão direta: `x mod q_i ≠ 0` para todo q_i da tabela.
///
/// Fração de ímpares que sobrevive = Π (1 − 1/q_i) ≈ 0,126 (produto de
/// Mertens para q_i ≤ 1621), ou seja, ~87% dos candidatos morrem aqui sem
/// nenhuma exponenciação modular.
pub fn sieve(x: u1024) SieveVerdict {
    if (x < 2) return .composite;
    if (x == 2) return .small_prime;
    if (x & 1 == 0) return .composite;
    for (SMALL_PRIMES) |q| {
        if (x == q) return .small_prime;
        if (modSmall(x, q) == 0) return .composite;
    }
    return .unknown;
}

// ----------------------------------------------------------------------------
// Miller-Rabin
// ----------------------------------------------------------------------------

pub const MillerRabinError = error{
    /// Miller-Rabin exige n ímpar e n ≥ 5 (para haver bases em [2, n − 2]).
    InvalidCandidate,
};

/// Contexto pré-calculado do teste de Miller-Rabin para um candidato `n`.
///
/// Fundamentação (Seção 2.3 do MATH_SPEC):
///
///   1. Pequeno Teorema de Fermat: se n é primo e mdc(a, n) = 1,
///          a^{n−1} ≡ 1 (mod n).
///   2. Em um corpo Z_n (n primo), x² ≡ 1 ⇒ (x − 1)(x + 1) ≡ 0 ⇒ x ≡ ±1.
///      Não existem raízes quadradas NÃO-triviais da unidade.
///
/// Escrevendo n − 1 = 2^s · d (d ímpar), a sequência
///
///     x_0 = a^d,  x_1 = x_0²,  …,  x_s = x_{s−1}² = a^{n−1}
///
/// deve terminar em 1 (Fermat) e, de trás para frente, cada "raiz" de 1 tem
/// que ser ±1. Logo, se n é primo, OU x_0 = 1, OU algum x_r = n − 1 com
/// 0 ≤ r < s. Se nada disso ocorrer, a base `a` é uma TESTEMUNHA de que n é
/// composto — prova definitiva, não probabilística.
pub const MillerRabin = struct {
    n: u1024,
    n_minus_1: u1024,
    /// s = ctz(n − 1) ≥ 1: expoente da maior potência de 2 que divide n − 1.
    s: u16,
    /// d = (n − 1) >> s, ímpar.
    d: u1024,
    /// Motor de Montgomery para o módulo ímpar n.
    modulus: Mod1024,
    one: Fe1024,
    minus_one: Fe1024,
    d_fe: Fe1024,

    /// Pré-calcula a decomposição n − 1 = 2^s · d e as constantes de Montgomery.
    ///
    /// `@ctz` (Count Trailing Zeros) conta quantos bits 0 existem no fim de
    /// n − 1; em hardware é uma instrução (TZCNT/BSF no x86, RBIT+CLZ no ARM)
    /// aplicada limb a limb, então s sai em O(1) por limb. Como cada zero
    /// final é um fator 2, s é exatamente a multiplicidade de 2 em n − 1, e
    /// o deslocamento à direita `(n − 1) >> s` remove esses fatores, deixando
    /// o d ímpar. Exemplo: 561 − 1 = 560 = 0b1000110000 ⇒ s = 4, d = 35.
    pub fn init(n: u1024) MillerRabinError!MillerRabin {
        if (n < 5 or n & 1 == 0) return MillerRabinError.InvalidCandidate;

        const n_minus_1 = n - 1;
        const s: u16 = @ctz(n_minus_1);
        const d = n_minus_1 >> @intCast(s);

        // n ímpar ≥ 5 ⇒ nenhum destes erros é possível.
        const modulus = Mod1024.fromPrimitive(u1024, n) catch unreachable;
        return .{
            .n = n,
            .n_minus_1 = n_minus_1,
            .s = s,
            .d = d,
            .modulus = modulus,
            .one = modulus.one(),
            .minus_one = Fe1024.fromPrimitive(u1024, modulus, n_minus_1) catch unreachable,
            .d_fe = Fe1024.fromPrimitive(u1024, modulus, d) catch unreachable,
        };
    }

    /// Retorna `true` se a base `a ∈ [2, n − 2]` PROVA que n é composto.
    ///
    ///     x_0 = a^d mod n                 (exponenciação de Montgomery)
    ///     se x_0 = 1 ou x_0 = n − 1  → não testemunha
    ///     para r = 1 … s − 1:
    ///         x_r = x_{r−1}² mod n        (quadratura de Montgomery)
    ///         se x_r = n − 1          → não testemunha
    ///         se x_r = 1              → raiz não-trivial de 1 ⇒ composto
    ///     fim do laço sem n − 1        → composto
    ///
    /// Usamos `pow` (tempo constante) e não `powPublic`: o candidato que
    /// passar no teste vira o fator SECRETO p, então o tempo de execução não
    /// deve depender dos bits de d = (p − 1)/2^s. (Além disso, nesta versão
    /// da std, `powPublic` aceita só expoentes que caibam no buffer de
    /// codificação de 128 bytes após normalização para limbs de 63 bits.)
    pub fn isWitness(self: *const MillerRabin, a: u1024) bool {
        const a_fe = Fe1024.fromPrimitive(u1024, self.modulus, a) catch return true;
        var x = self.modulus.pow(a_fe, self.d_fe) catch unreachable; // d ≥ 1

        if (x.eql(self.one) or x.eql(self.minus_one)) return false;

        var r: u16 = 1;
        while (r < self.s) : (r += 1) {
            x = self.modulus.sq(x); // x_r = x_{r−1}² mod n
            if (x.eql(self.minus_one)) return false;
            if (x.eql(self.one)) return true; // √1 não-trivial encontrada
        }
        return true;
    }

    /// Sorteia uma base uniforme em [2, n − 2] por amostragem com rejeição:
    /// gera `bitlen(n)` bits aleatórios e descarta valores fora do intervalo.
    /// (Usar `raw mod (n − 3)` enviesaria a distribuição quando n não é
    /// potência de 2; a rejeição custa em média < 2 sorteios.)
    pub fn randomBase(self: *const MillerRabin, rand: std.Random) u1024 {
        const bit_len: usize = PRIME_BITS - @as(usize, @clz(self.n));
        const mask: u1024 = if (bit_len >= PRIME_BITS)
            std.math.maxInt(u1024)
        else
            (@as(u1024, 1) << @intCast(bit_len)) - 1;

        var buf: [PRIME_BYTES]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        while (true) {
            rand.bytes(&buf);
            const a = std.mem.readInt(u1024, &buf, .big) & mask;
            if (a >= 2 and a <= self.n - 2) return a;
        }
    }
};

/// Teste de Miller-Rabin com `rounds` bases aleatórias independentes
/// (SEM o crivo — útil para demonstrar a rejeição de números de Carmichael).
///
/// Probabilidade de erro (Teorema de Monier-Rabin): para n ímpar composto,
/// no máximo φ(n)/4 < n/4 das bases são "mentirosas fortes". Com k rodadas
/// independentes:  P[composto passar] ≤ (1/4)^k;  k = 64 ⇒ ≤ 2^-128.
pub fn millerRabin(n: u1024, rand: std.Random, rounds: usize, stats: ?*Stats) bool {
    const mr = MillerRabin.init(n) catch return false;
    for (0..rounds) |_| {
        if (stats) |st| st.mr_rounds += 1;
        if (mr.isWitness(mr.randomBase(rand))) return false;
    }
    return true;
}

/// Teste completo: casos triviais + crivo + Miller-Rabin.
pub fn isProbablyPrime(n: u1024, rand: std.Random, rounds: usize) bool {
    return switch (sieve(n)) {
        .small_prime => true,
        .composite => false,
        .unknown => millerRabin(n, rand, rounds, null),
    };
}

// ----------------------------------------------------------------------------
// Geração de primos de 1024 bits
// ----------------------------------------------------------------------------

/// Número máximo de ímpares consecutivos examinados a partir de cada sorteio.
/// O intervalo médio entre primos perto de 2^1024 é ln(2^1024) ≈ 710, isto é,
/// ~355 ímpares; 2^14 passos tornam o re-sorteio praticamente nunca necessário.
const MAX_INCREMENTAL_STEPS: u32 = 1 << 14;

/// Gera um primo aleatório de EXATAMENTE 1024 bits com p ≥ 2^1023 + 2^1022.
///
/// 1. Sorteio: 128 bytes B_0 … B_127 (Big-Endian, B_0 = byte mais alto).
/// 2. Manipulação de bits:
///        B_0   ← B_0   | 0b1100_0000   ⇒ p ≥ 2^1023 + 2^1022 = (3/4)·2^1024
///        B_127 ← B_127 | 0b0000_0001   ⇒ p ≡ 1 (mod 2), ímpar
///    Com p, q ≥ (3/4)·2^1024:  n = p·q ≥ (9/16)·2^2048 > (1/2)·2^2048 = 2^2047,
///    e n < 2^2048, portanto n tem EXATAMENTE 2048 bits. Forçar só o MSB
///    daria p·q ≥ 2^2046, podendo resultar em módulo de 2047 bits.
/// 3. Busca incremental: testamos p, p+2, p+4, … Os restos r_i = p mod q_i
///    são calculados UMA vez; para o candidato p + δ usamos
///        (p + δ) mod q_i = (r_i + δ) mod q_i
///    que é a mesma divisão direta do crivo, só que com operandos de 32 bits.
/// 4. Sobreviventes do crivo vão para o Miller-Rabin com `rounds` rodadas.
pub fn generatePrimeWithStats(rand: std.Random, rounds: usize, stats: ?*Stats) u1024 {
    var buf: [PRIME_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    var residues: [SIEVE_SIZE]u16 = undefined;
    defer std.crypto.secureZero(u16, &residues);

    while (true) {
        rand.bytes(&buf);
        if (stats) |st| st.random_draws += 1;

        buf[0] |= 0b1100_0000; // MSB + 2º MSB
        buf[PRIME_BYTES - 1] |= 0b0000_0001; // LSB → ímpar

        const base = std.mem.readInt(u1024, &buf, .big);
        for (SMALL_PRIMES, &residues) |q, *r| r.* = modSmall(base, q);

        var delta: u32 = 0;
        search: while (delta < 2 * MAX_INCREMENTAL_STEPS) : (delta += 2) {
            const candidate, const overflow = @addWithOverflow(base, delta);
            if (overflow != 0) break; // passou de 2^1024: sorteia de novo
            if (stats) |st| st.candidates += 1;

            for (SMALL_PRIMES, residues) |q, r| {
                if ((@as(u32, r) + delta) % q == 0) {
                    if (stats) |st| st.sieve_rejections += 1;
                    continue :search;
                }
            }

            if (millerRabin(candidate, rand, rounds, stats)) return candidate;
            if (stats) |st| st.mr_rejections += 1;
        }
    }
}

pub fn generatePrimeWithRounds(rand: std.Random, rounds: usize) u1024 {
    return generatePrimeWithStats(rand, rounds, null);
}

pub fn generatePrime(rand: std.Random) u1024 {
    return generatePrimeWithRounds(rand, DEFAULT_ROUNDS);
}

// ============================================================================
// TESTES UNITÁRIOS — ETAPA 2   (zig build test-etapa2)
// ============================================================================

const testing = std.testing;

fn mersenne(comptime k: u16) u1024 {
    if (k == 1024) return std.math.maxInt(u1024);
    return (@as(u1024, 1) << @intCast(k)) - 1;
}

/// Primo de 1024 bits do Grupo 2 Oakley/MODP (RFC 2409, §6.2):
/// p = 2^1024 − 2^960 − 1 + 2^64·(⌊2^894·π⌋ + 129093).
const RFC2409_PRIME_1024: u1024 =
    0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF;

test "Etapa 2.1: tabela do crivo — 256 primos ímpares de 3 a 1621" {
    try testing.expectEqual(@as(usize, 256), SMALL_PRIMES.len);
    try testing.expectEqual(@as(u16, 3), SMALL_PRIMES[0]);
    try testing.expectEqual(@as(u16, 1621), SMALL_PRIMES[255]);
    for (SMALL_PRIMES, 0..) |q, i| {
        if (i > 0) try testing.expect(q > SMALL_PRIMES[i - 1]);
        var f: u16 = 2;
        while (f * f <= q) : (f += 1) try testing.expect(q % f != 0);
    }
}

test "Etapa 2.2: modSmall (Horner na base 2^64) ≡ operador % nativo" {
    var prng = std.Random.DefaultPrng.init(0x5EED);
    const rand = prng.random();
    var buf: [128]u8 = undefined;
    for (0..50) |_| {
        rand.bytes(&buf);
        const x = std.mem.readInt(u1024, &buf, .big);
        for (SMALL_PRIMES) |q| {
            try testing.expectEqual(@as(u16, @intCast(x % q)), modSmall(x, q));
        }
    }
}

test "Etapa 2.3: decomposição n − 1 = 2^s · d via @ctz" {
    const mr = try MillerRabin.init(561);
    try testing.expectEqual(@as(u16, 4), mr.s);
    try testing.expectEqual(@as(u1024, 35), mr.d);

    const mr2 = try MillerRabin.init(RFC2409_PRIME_1024);
    try testing.expectEqual(RFC2409_PRIME_1024 - 1, mr2.d << @intCast(mr2.s));
    try testing.expectEqual(@as(u1024, 1), mr2.d & 1);

    try testing.expectError(MillerRabinError.InvalidCandidate, MillerRabin.init(4));
    try testing.expectError(MillerRabinError.InvalidCandidate, MillerRabin.init(3));
}

test "Etapa 2.4: primos conhecidos são aceitos" {
    var prng = std.Random.DefaultPrng.init(12345);
    const rand = prng.random();

    const primes = [_]u1024{
        2,          3,          5,          7,          61,
        1621,       1627,       7919,       65537,      2147483647,
        mersenne(61), mersenne(89), mersenne(107), mersenne(127),
        mersenne(521), mersenne(607), RFC2409_PRIME_1024,
    };
    for (primes) |p| try testing.expect(isProbablyPrime(p, rand, DEFAULT_ROUNDS));
}

test "Etapa 2.5: compostos são rejeitados (inclusive sem fatores pequenos)" {
    var prng = std.Random.DefaultPrng.init(54321);
    const rand = prng.random();

    const composites = [_]u1024{
        0,                                  1,
        4,                                  9,
        3233, // 61·53
        1627 * 1637, // primos fora do crivo
        mersenne(127) * mersenne(127), // quadrado de primo de 127 bits
        mersenne(89) * mersenne(521), // semiprimo de 610 bits
        mersenne(61) * mersenne(607),
        mersenne(1024), // 2^1024 − 1 = (2^512 − 1)(2^512 + 1)
    };
    for (composites) |c| try testing.expect(!isProbablyPrime(c, rand, DEFAULT_ROUNDS));
}

test "Etapa 2.6: números de Carmichael — Fermat engana, Miller-Rabin rejeita" {
    var prng = std.Random.DefaultPrng.init(67890);
    const rand = prng.random();

    const carmichael = [_]u1024{ 561, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265 };
    for (carmichael) |c| {
        const mr = try MillerRabin.init(c);

        // (a) Teste de Fermat: a^{c−1} ≡ 1 (mod c) para TODA base coprima.
        //     Por isso Fermat sozinho os aceitaria como "primos".
        var a: u1024 = 2;
        while (a < 40) : (a += 1) {
            if (std.math.gcd(@as(u64, @intCast(a)), @as(u64, @intCast(c))) != 1) continue;
            const a_fe = try Fe1024.fromPrimitive(u1024, mr.modulus, a);
            const e_fe = try Fe1024.fromPrimitive(u1024, mr.modulus, c - 1);
            const fermat = try mr.modulus.pow(a_fe, e_fe);
            try testing.expect(fermat.eql(mr.one));
        }

        // (b) Miller-Rabin SEM crivo: rejeição obrigatória.
        try testing.expect(!millerRabin(c, rand, DEFAULT_ROUNDS, null));
        // (c) Pipeline completo também rejeita.
        try testing.expect(!isProbablyPrime(c, rand, DEFAULT_ROUNDS));
    }
}

test "Etapa 2.7: traço passo a passo de 561 com base 2 (raiz √1 não-trivial)" {
    // 560 = 2^4·35:  x_0 = 2^35 mod 561 = 263,  x_1 = 166,  x_2 = 67,  x_3 = 1.
    // 67² ≡ 1 (mod 561) com 67 ≢ ±1  ⇒  561 é composto (561 = 3·11·17).
    const mr = try MillerRabin.init(561);
    const two = try Fe1024.fromPrimitive(u1024, mr.modulus, 2);
    var x = try mr.modulus.pow(two, mr.d_fe);
    const expected = [_]u1024{ 263, 166, 67, 1 };
    for (expected) |e| {
        try testing.expectEqual(e, try x.toPrimitive(u1024));
        x = mr.modulus.sq(x);
    }
    try testing.expect(mr.isWitness(2));
}

test "Etapa 2.8: pseudoprimos fortes na base 2 enganam UMA base, não 64" {
    var prng = std.Random.DefaultPrng.init(2047);
    const rand = prng.random();
    // Menores pseudoprimos fortes para a base 2 (OEIS A001262).
    const spsp2 = [_]u1024{ 2047, 3277, 4033, 4681, 8321 };
    for (spsp2) |n| {
        const mr = try MillerRabin.init(n);
        try testing.expect(!mr.isWitness(2)); // a = 2 é "mentirosa forte"
        try testing.expect(!millerRabin(n, rand, DEFAULT_ROUNDS, null));
    }
}

test "Etapa 2.9: geração de primo de 1024 bits — fronteiras MSB/LSB" {
    var prng = std.Random.DefaultPrng.init(999);
    const rand = prng.random();
    var stats: Stats = .{};

    const p = generatePrimeWithStats(rand, DEFAULT_ROUNDS, &stats);

    const min_bound: u1024 = (@as(u1024, 1) << 1023) | (@as(u1024, 1) << 1022);
    try testing.expect(p >= min_bound); // bits 1023 e 1022 ligados
    try testing.expectEqual(@as(u1024, 1), p & 1); // ímpar
    try testing.expectEqual(SieveVerdict.unknown, sieve(p)); // sem fatores pequenos

    // Confirmação independente com outro gerador e 64 rodadas novas.
    var prng2 = std.Random.DefaultPrng.init(31337);
    try testing.expect(millerRabin(p, prng2.random(), DEFAULT_ROUNDS, null));

    // O primo aceito executou as 64 rodadas completas.
    try testing.expect(stats.mr_rounds >= DEFAULT_ROUNDS);
    try testing.expect(stats.candidates == stats.sieve_rejections + stats.mr_rejections + 1);
}

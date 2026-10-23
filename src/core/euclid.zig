//! ============================================================================
//! euclid.zig — Etapa 1: MDC, MMC e Algoritmo de Euclides Estendido
//! ============================================================================
//!
//! Este módulo resolve o único ponto do RSA em que a Redução de Montgomery
//! (`std.crypto.ff.Modulus`) NÃO pode ser usada: a inversão modular com
//! módulo PAR.
//!
//! Por quê? Montgomery representa `a` como `ā = a·R mod N` com `R = 2^k`, e
//! precisa de `R^{-1} mod N`. Esse inverso só existe se `mdc(R, N) = 1`, isto é,
//! se `N` for ÍMPAR. Mas o totiente de Carmichael
//!
//!     λ(n) = mmc(p − 1, q − 1)
//!
//! é SEMPRE par (p − 1 e q − 1 são pares, pois p e q são primos ímpares).
//! Logo, para calcular a chave privada `d ≡ e^{-1} (mod λ(n))` usamos o
//! Algoritmo de Euclides Estendido sobre os inteiros nativos de largura
//! arbitrária do Zig:
//!
//!   * `u2048` — magnitudes não-negativas (λ(n), e, restos r_k);
//!   * `i4096` — coeficientes de Bézout t_k, que alternam de sinal.
//!
//! Representação na máquina (Seção 2.1 do MATH_SPEC): um `u2048` é guardado
//! como 32 "limbs" de 64 bits na base B = 2^64:
//!
//!     X = Σ_{i=0}^{31} x_i · (2^64)^i,   0 ≤ x_i < 2^64
//!
//! e um `i4096` como 64 limbs em complemento de dois (1 bit de sinal + 4095
//! bits de magnitude). Todas as variáveis vivem na stack — zero alocação.
//! ============================================================================

const std = @import("std");

pub const EuclidError = error{
    /// m == 0: a aritmética modular "mod 0" não está definida.
    ModulusZero,
    /// mdc(a, m) ≠ 1: o inverso modular não existe.
    NotCoprime,
    /// O resultado não cabe em 2048 bits (só ocorre com entradas fora do
    /// domínio RSA, p.ex. mmc de dois números de 2048 bits coprimos).
    Overflow,
};

/// Máximo Divisor Comum pelo Algoritmo de Euclides (≈ 300 a.C.).
///
/// Matemática: para a, b ≥ 0,
///
///     mdc(a, 0) = a
///     mdc(a, b) = mdc(b, a mod b)
///
/// Cada iteração substitui o par (x, y) por (y, x mod y). Como
/// `x mod y < y`, o segundo componente decresce estritamente e o laço termina.
/// Pelo Teorema de Lamé o número de passos é O(log_φ(min(a, b))) — no pior
/// caso ~2950 iterações para operandos de 2048 bits (pares de Fibonacci).
///
/// Código ↔ fórmula: `x` e `y` são `u2048` na stack; `x % y` é a divisão
/// longa multi-limb gerada pelo compilador (compiler-rt `__umodei4`).
pub fn gcd(a: u2048, b: u2048) u2048 {
    var x = a;
    var y = b;
    while (y != 0) {
        const r = x % y; // r = x mod y
        x = y; //          (x, y) ← (y, r)
        y = r;
    }
    return x;
}

/// Mínimo Múltiplo Comum.
///
/// Matemática (consequência do Teorema Fundamental da Aritmética):
///
///     mmc(a, b) = a·b / mdc(a, b) = (a / mdc(a, b)) · b
///
/// Dividimos ANTES de multiplicar: `a / mdc(a, b)` é exato e menor que `a`,
/// então o produto nunca excede o resultado final. No RSA chamamos
/// `lcm(p − 1, q − 1)` com operandos de 1024 bits → resultado ≤ 2048 bits,
/// que cabe em `u2048`. Ainda assim usamos `@mulWithOverflow` para que um uso
/// fora do domínio retorne erro em vez de truncar silenciosamente.
pub fn lcm(a: u2048, b: u2048) EuclidError!u2048 {
    if (a == 0 or b == 0) return 0;
    const a_reduced = a / gcd(a, b);
    const product, const overflow = @mulWithOverflow(a_reduced, b);
    if (overflow != 0) return EuclidError.Overflow;
    return product;
}

/// Inverso multiplicativo modular via Algoritmo de Euclides Estendido.
/// Retorna `d ∈ [0, m)` tal que `(a · d) mod m = 1`.
///
/// Matemática — Identidade de Bézout: para quaisquer inteiros a, m existem
/// inteiros t, s com
///
///     a·t + m·s = mdc(a, m)
///
/// Se mdc(a, m) = 1, reduzindo módulo m obtemos a·t ≡ 1 (mod m), ou seja,
/// t é o inverso de a. No RSA: a = e = 65537 e m = λ(n), daí d = t.
///
/// Recorrência (só precisamos de t; s é descartado):
///
///     condições iniciais: r_0 = m,  r_1 = a mod m,  t_0 = 0,  t_1 = 1
///     q_k     = ⌊ r_{k-1} / r_k ⌋
///     r_{k+1} = r_{k-1} − q_k · r_k
///     t_{k+1} = t_{k-1} − q_k · t_k
///
/// Invariante mantido em todo passo: `a · t_k ≡ r_k (mod m)`.
///   (k = 0: a·0 ≡ 0 ≡ m;  k = 1: a·1 ≡ a mod m;  e a recorrência é linear.)
/// Quando r_k = 0, o resto anterior r_{k-1} = mdc(a, m). Se for 1, então
/// a·t_{k-1} ≡ 1 e t_{k-1} é o inverso — possivelmente negativo, por isso:
///
///     d = t_{k-1}         se t_{k-1} ≥ 0
///     d = t_{k-1} + m     se t_{k-1} < 0
///
/// Por que `i4096`? Os t_k alternam de sinal e satisfazem |t_k| ≤ m, porém
/// o produto intermediário `q_k · t_k` é calculado antes da subtração; com
/// q_k e t_k ambos de até 2048 bits, reservar 4096 bits com sinal garante que
/// nenhuma etapa transborde, mesmo antes do cancelamento.
pub fn modInverse(a: u2048, m: u2048) EuclidError!u2048 {
    if (m == 0) return EuclidError.ModulusZero;
    if (m == 1) return 0; // Em Z_1 todo número é ≡ 0 e 0 é o "inverso" trivial.

    const m_signed: i4096 = m;

    var r_prev: i4096 = m_signed; //  r_0 = m
    var r_curr: i4096 = a % m; //     r_1 = a mod m
    var t_prev: i4096 = 0; //         t_0 = 0
    var t_curr: i4096 = 1; //         t_1 = 1

    while (r_curr != 0) {
        // q_k = ⌊r_{k-1} / r_k⌋ — ambos os restos são ≥ 0, então floor = trunc.
        const q = @divFloor(r_prev, r_curr);

        // r_{k+1} = r_{k-1} − q_k · r_k   (equivale a r_{k-1} mod r_k)
        const r_next = r_prev - q * r_curr;
        r_prev = r_curr;
        r_curr = r_next;

        // t_{k+1} = t_{k-1} − q_k · t_k
        const t_next = t_prev - q * t_curr;
        t_prev = t_curr;
        t_curr = t_next;
    }

    // r_prev agora é mdc(a, m). Inverso só existe se ele for 1.
    if (r_prev != 1) return EuclidError.NotCoprime;

    // Normalização para o representante canônico em [0, m).
    if (t_prev < 0) t_prev += m_signed;

    return @intCast(t_prev);
}

/// Multiplicação modular genérica `(a · b) mod m` sem perda de bits.
///
/// O produto de dois números de 2048 bits tem até 4096 bits, então
/// promovemos os operandos para `u4096` ANTES de multiplicar (o mesmo motivo
/// pelo qual `n = p · q` exige cast prévio de `u1024` para `u2048`).
/// Serve para módulos pares (λ(n)), onde Montgomery não se aplica — usado
/// pelos testes para verificar `(e · d) mod λ(n) = 1`.
pub fn mulMod(a: u2048, b: u2048, m: u2048) u2048 {
    const prod: u4096 = @as(u4096, a) * @as(u4096, b);
    return @intCast(prod % m);
}

// ============================================================================
// TESTES UNITÁRIOS — ETAPA 1   (zig build test-etapa1)
// ============================================================================

const testing = std.testing;

test "Etapa 1.1: mdc e mmc com vetores determinísticos" {
    try testing.expectEqual(@as(u2048, 6), gcd(54, 24));
    try testing.expectEqual(@as(u2048, 6), gcd(24, 54)); // comutatividade
    try testing.expectEqual(@as(u2048, 17), gcd(17, 0)); // mdc(a, 0) = a
    try testing.expectEqual(@as(u2048, 1), gcd(65537, 3120));
    try testing.expectEqual(@as(u2048, 4), gcd(60, 52));

    try testing.expectEqual(@as(u2048, 780), try lcm(60, 52)); // λ(3233)
    try testing.expectEqual(@as(u2048, 0), try lcm(0, 52));

    // mdc · mmc = a · b
    const a: u2048 = 123456789012345678901234567890;
    const b: u2048 = 987654321098765432109876543210;
    try testing.expectEqual(a * b, gcd(a, b) * try lcm(a, b));

    // mdc entre números de Fibonacci consecutivos = 1 (pior caso de Lamé)
    var f0: u2048 = 0;
    var f1: u2048 = 1;
    for (0..2900) |_| {
        const f2 = f0 +% f1;
        if (f2 < f1) break; // parou antes de transbordar 2048 bits
        f0 = f1;
        f1 = f2;
    }
    try testing.expectEqual(@as(u2048, 1), gcd(f1, f0));
}

test "Etapa 1.2: mmc detecta overflow fora do domínio RSA" {
    const big: u2048 = (@as(u2048, 1) << 2047) + 1; // ímpar, 2048 bits
    try testing.expectError(EuclidError.Overflow, lcm(big, 2));
}

test "Etapa 1.3: exemplo didático clássico p=61, q=53, e=17 (λ par)" {
    const p: u2048 = 61;
    const q: u2048 = 53;
    const lambda_n = try lcm(p - 1, q - 1);
    try testing.expectEqual(@as(u2048, 780), lambda_n);
    try testing.expectEqual(@as(u2048, 0), lambda_n % 2); // λ(n) é PAR

    const d = try modInverse(17, lambda_n);
    try testing.expectEqual(@as(u2048, 413), d);
    try testing.expectEqual(@as(u2048, 1), mulMod(17, d, lambda_n));

    // Com φ(n) = 3120 o expoente seria 2753 — maior que o de Carmichael.
    const d_phi = try modInverse(17, (p - 1) * (q - 1));
    try testing.expectEqual(@as(u2048, 2753), d_phi);
    try testing.expect(d <= d_phi);
}

test "Etapa 1.4: varredura exaustiva (a · a⁻¹) mod m = 1 para m < 300" {
    var m: u2048 = 2;
    while (m < 300) : (m += 1) {
        var a: u2048 = 1;
        while (a < m) : (a += 1) {
            if (gcd(a, m) == 1) {
                const inv = try modInverse(a, m);
                try testing.expect(inv < m);
                try testing.expectEqual(@as(u2048, 1), mulMod(a, inv, m));
            } else {
                try testing.expectError(EuclidError.NotCoprime, modInverse(a, m));
            }
        }
    }
}

test "Etapa 1.5: rejeições — não coprimos e módulo zero" {
    try testing.expectError(EuclidError.NotCoprime, modInverse(12, 780));
    try testing.expectError(EuclidError.NotCoprime, modInverse(0, 780));
    try testing.expectError(EuclidError.ModulusZero, modInverse(5, 0));
    try testing.expectEqual(@as(u2048, 0), try modInverse(5, 1));
}

test "Etapa 1.6: e = 65537 com λ(n) PAR de ~2048 bits" {
    const e: u2048 = 65537;

    // λ = 2^2047 + 2 (par, coprimo de 65537 pois 2^2047 + 2 ≢ 0 mod 65537)
    const lambdas = [_]u2048{
        (@as(u2048, 1) << 2047) + 2,
        (@as(u2048, 1) << 2040) - 4,
        std.math.maxInt(u2048) - 1, // 2^2048 − 2, par
        // λ(n) com p, q primos de Mersenne/conhecidos: mmc(M127 − 1, M521 − 1)
        try lcm((@as(u2048, 1) << 127) - 2, (@as(u2048, 1) << 521) - 2),
    };

    for (lambdas) |lambda_n| {
        try testing.expectEqual(@as(u2048, 0), lambda_n & 1);
        if (gcd(e, lambda_n) != 1) continue;
        const d = try modInverse(e, lambda_n);
        try testing.expect(d < lambda_n);
        try testing.expectEqual(@as(u2048, 1), mulMod(e, d, lambda_n));
        // Simetria: o inverso do inverso é o próprio e.
        try testing.expectEqual(e, try modInverse(d, lambda_n));
    }
}

test "Etapa 1.7: vetor de referência fechado — 65537⁻¹ mod (2^1024 − 2)" {
    // Conferido com Python 3: hex(pow(65537, -1, 2**1024 - 2)) =
    //   0xffff0000ffff0000 ... ffff0000ffff   (32 blocos 0xffff a cada 32 bits)
    //
    // Prova algébrica: seja D = Σ_{k=0}^{31} (2^16 − 1)·2^{32k}. Então
    //   65537·D = (2^16 + 1)(2^16 − 1)·Σ 2^{32k} = (2^32 − 1)·Σ 2^{32k}
    //           = 2^1024 − 1 ≡ 1  (mod 2^1024 − 2).
    const m: u2048 = (@as(u2048, 1) << 1024) - 2;
    comptime var expected: u2048 = 0;
    inline for (0..32) |k| expected |= @as(u2048, 0xffff) << (32 * k);

    const d = try modInverse(65537, m);
    try testing.expectEqual(expected, d);
    try testing.expectEqual(@as(u2048, 1), mulMod(65537, d, m));
}

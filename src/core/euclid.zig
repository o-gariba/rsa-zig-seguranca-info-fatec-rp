const std = @import("std");

pub const EuclidError = error{
    /// Ocorre quando m == 0 na divisão modular.
    ModulusZero,
    /// Ocorre quando gcd(a, m) != 1, logo o inverso modular não existe.
    NotCoprime,
};

/// Calcula o Máximo Divisor Comum (MDC / GCD) entre dois inteiros de até 2048 bits
/// utilizando o Algoritmo de Euclides iterativo: gcd(a, b) = gcd(b, a mod b).
pub fn gcd(a: u2048, b: u2048) u2048 {
    var x = a;
    var y = b;
    while (y != 0) {
        const rem = x % y;
        x = y;
        y = rem;
    }
    return x;
}

/// Calcula o Mínimo Múltiplo Comum (MMC / LCM): lcm(a, b) = (a / gcd(a, b)) * b.
/// Usado na geração de chaves RSA para obter o totiente de Carmichael:
/// lambda(n) = lcm(p - 1, q - 1).
/// A divisão é feita antes da multiplicação para minimizar o crescimento de bits.
pub fn lcm(a: u2048, b: u2048) u2048 {
    if (a == 0 or b == 0) return 0;
    return (a / gcd(a, b)) * b;
}

/// Calcula o Inverso Multiplicativo Modular: retorna `d` tal que (a * d) % m == 1.
/// Utiliza o Algoritmo de Euclides Estendido sobre inteiros com sinal de 4096 bits (`i4096`).
///
/// Isso resolve o problema central da chave privada RSA, onde o módulo `m = lambda(n)`
/// é SEMPRE PAR (impedindo o uso da Redução de Montgomery) e também calcula
/// o parâmetro CRT `q_inv = q^-1 mod p`.
pub fn modInverse(a: u2048, m: u2048) EuclidError!u2048 {
    if (m == 0) return EuclidError.ModulusZero;
    if (m == 1) return 0;

    const m_signed: i4096 = @intCast(m);

    // Condições iniciais da recorrência de Bézout:
    // r_0 = m, r_1 = a mod m
    // t_0 = 0, t_1 = 1
    var t: i4096 = 0;
    var new_t: i4096 = 1;
    var r: i4096 = m_signed;
    var new_r: i4096 = @intCast(a % m);

    while (new_r != 0) {
        const quotient = @divTrunc(r, new_r);

        // t_{k+1} = t_{k-1} - q_k * t_k
        const next_t = t - (quotient * new_t);
        t = new_t;
        new_t = next_t;

        // r_{k+1} = r_{k-1} - q_k * r_k
        const next_r = r - (quotient * new_r);
        r = new_r;
        new_r = next_r;
    }

    // Se o último resto não-nulo (que é igual a gcd(a, m)) for maior que 1,
    // `a` e `m` não são coprimos e o inverso não existe.
    if (r > 1) return EuclidError.NotCoprime;

    // Se o coeficiente de Bézout `t` terminou negativo, somamos o módulo `m`
    // para trazê-lo para a representação canônica positiva [0, m - 1].
    if (t < 0) {
        t += m_signed;
    }

    return @intCast(t);
}

/// Calcula (a * b) % m para números de 2048 bits sem risco de overflow intermediário,
/// promovendo os operandos para u4096 antes do produto.
pub fn mulMod(a: u2048, b: u2048, m: u2048) u2048 {
    const prod: u4096 = @as(u4096, a) * @as(u4096, b);
    const rem: u4096 = prod % @as(u4096, m);
    return @intCast(rem);
}

// ============================================================================
// TESTES UNITÁRIOS DA ETAPA 1 (Execute com: zig test src/core/euclid.zig)
// ============================================================================

test "Etapa 1.1: GCD e LCM básicos" {
    try std.testing.expectEqual(@as(u2048, 6), gcd(54, 24));
    try std.testing.expectEqual(@as(u2048, 1), gcd(65537, 3120));
    try std.testing.expectEqual(@as(u2048, 780), lcm(60, 52));
}

test "Etapa 1.2: Inverso Modular clássico (Exemplo didático RSA: p=61, q=53)" {
    const p: u2048 = 61;
    const q: u2048 = 53;

    // Totiente de Carmichael: lambda(3233) = lcm(60, 52) = 780 (número PAR)
    const lambda_n = lcm(p - 1, q - 1);
    try std.testing.expectEqual(@as(u2048, 780), lambda_n);

    // Expoente de teste e = 17 -> d = 17^-1 mod 780 = 413
    const e: u2048 = 17;
    const d = try modInverse(e, lambda_n);
    try std.testing.expectEqual(@as(u2048, 413), d);

    // Prova real: (e * d) mod lambda_n == 1
    try std.testing.expectEqual(@as(u2048, 1), mulMod(e, d, lambda_n));
}

test "Etapa 1.3: Rejeição de números não-coprimos" {
    // 12 e 780 compartilham o fator 12, logo não existe inverso modular
    try std.testing.expectError(EuclidError.NotCoprime, modInverse(12, 780));
}

test "Etapa 1.4: Inverso Modular em escala real de 2048 bits com e = 65537" {
    // Simulamos um lambda(n) par de ~2040 bits que é coprimo de 65537
    const big_lambda: u2048 = (@as(u2048, 1) << 2040) - 4;
    const e: u2048 = 65537;

    try std.testing.expectEqual(@as(u2048, 1), gcd(e, big_lambda));

    const d = try modInverse(e, big_lambda);

    // Verifica a identidade fundamental: (e * d) mod lambda(n) == 1
    const check = mulMod(e, d, big_lambda);
    try std.testing.expectEqual(@as(u2048, 1), check);
}

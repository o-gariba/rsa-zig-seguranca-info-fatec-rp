const std = @import("std");

/// Estrutura de corpo finito de até 1024 bits da biblioteca padrão do Zig.
/// Realiza exponenciação e multiplicação modular usando Redução de Montgomery.
const Mod1024 = std.crypto.ff.Modulus(1024);

/// Tabela estática com os primeiros 64 números primos ímpares (de 3 a 313).
/// Usada como filtro rápido antes do Miller-Rabin: descarta ~78% dos candidatos
/// compostos ímpares usando apenas resto de divisão rápida.
const SMALL_PRIMES = [_]u16{
    3,   5,   7,   11,  13,  17,  19,  23,  29,  31,  37,  41,  43,  47,  53,  59,
    61,  67,  71,  73,  79,  83,  89,  97,  101, 103, 107, 109, 113, 127, 131, 137,
    139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
    229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
};

/// Exponenciação modular auxiliar (base^exp mod m) usando aritmética nativa u2048.
/// Usada exclusivamente como fallback para números pequenos (< 128 bits) nos testes,
/// já que std.crypto.ff.Modulus exige módulos de tamanho criptográfico (>= 128 bits).
fn modPowSmall(base: u1024, exp: u1024, m: u1024) u1024 {
    var result: u1024 = 1;
    var b: u2048 = base % m;
    var e: u1024 = exp;
    const mod_wide: u2048 = m;

    while (e > 0) : (e >>= 1) {
        if ((e & 1) == 1) {
            result = @intCast((@as(u2048, result) * b) % mod_wide);
        }
        b = (b * b) % mod_wide;
    }
    return result;
}

/// Verifica se `n` é provavelmente primo usando o Crivo + Teste de Miller-Rabin.
/// Para k = 64 rodadas, a probabilidade de um número composto passar é < (1/4)^64 = 2^-128.
pub fn isProbablyPrime(n: u1024, rand: std.Random, rounds: usize) bool {
    if (n < 2) return false;
    if (n == 2 or n == 3) return true;
    if ((n & 1) == 0) return false; // Números pares > 2 são compostos

    // 1. Filtro do Crivo de Primos Pequenos
    for (SMALL_PRIMES) |sp| {
        if (n == sp) return true;
        if (n % sp == 0) return false;
    }

    // 2. Decomposição: n - 1 = 2^s * d, com `d` ímpar
    const n_minus_1: u1024 = n - 1;
    const s: u16 = @ctz(n_minus_1);
    const d: u1024 = n_minus_1 >> @intCast(s);

    // 3. Instancia o motor de Montgomery de 1024 bits passando o tipo `u1024`
    if (Mod1024.fromPrimitive(u1024, n)) |m| {
        const one_fe = Mod1024.Fe.fromPrimitive(u1024, m, 1) catch return false;
        const nm1_fe = Mod1024.Fe.fromPrimitive(u1024, m, n_minus_1) catch return false;
        const d_fe = Mod1024.Fe.fromPrimitive(u1024, m, d) catch return false;

        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            const a = randomBase(n, rand);
            const a_fe = Mod1024.Fe.fromPrimitive(u1024, m, a) catch return false;

            // x_0 = a^d mod n (via exponenciação de Montgomery)
            var x_fe = m.powPublic(a_fe, d_fe) catch return false;

            if (x_fe.eql(one_fe) or x_fe.eql(nm1_fe)) continue;

            var passed_round = false;
            var r: u16 = 1;
            while (r < s) : (r += 1) {
                // x_r = (x_{r-1})^2 mod n (multiplicação de Montgomery)
                x_fe = m.mul(x_fe, x_fe);

                // Raiz quadrada não-trivial de 1 mod n detectada -> composto
                if (x_fe.eql(one_fe)) return false;
                if (x_fe.eql(nm1_fe)) {
                    passed_round = true;
                    break;
                }
            }

            if (!passed_round) return false;
        }
        return true;
    } else |_| {
        // Fallback para inteiros pequenos (< 128 bits) mantendo a mesma lógica de Miller-Rabin
        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            const a = randomBase(n, rand);
            var x = modPowSmall(a, d, n);

            if (x == 1 or x == n_minus_1) continue;

            var passed_round = false;
            var r: u16 = 1;
            while (r < s) : (r += 1) {
                x = @intCast((@as(u2048, x) * @as(u2048, x)) % @as(u2048, n));
                if (x == 1) return false;
                if (x == n_minus_1) {
                    passed_round = true;
                    break;
                }
            }

            if (!passed_round) return false;
        }
        return true;
    }
}

/// Sorteia uma base `a` no intervalo [2, n - 2] para o teste de Miller-Rabin.
fn randomBase(n: u1024, rand: std.Random) u1024 {
    var buf: [128]u8 = undefined;
    rand.bytes(&buf);
    const raw = std.mem.readInt(u1024, &buf, .big);
    return 2 + (raw % (n - 3));
}

/// Gera um número primo aleatório de exatamente 1024 bits.
/// Garante os dois bits mais significativos em 1 (para que p * q tenha 2048 bits exatos)
/// e o bit menos significativo em 1 (ímpar).
pub fn generatePrimeWithRounds(rand: std.Random, rounds: usize) u1024 {
    var buf: [128]u8 = undefined;

    while (true) {
        rand.bytes(&buf);

        // MSB force: garante p >= 2^1023 + 2^1022
        buf[0] |= 0b1100_0000;
        // LSB force: garante p ímpar
        buf[127] |= 0b0000_0001;

        var candidate = std.mem.readInt(u1024, &buf, .big);

        // Faz uma busca incremental por até 1024 ímpares consecutivos a partir
        // da semente sorteada antes de pedir novos bytes ao CSPRNG
        var step: usize = 0;
        while (step < 1024) : (step += 1) {
            if (isProbablyPrime(candidate, rand, rounds)) {
                return candidate;
            }
            candidate, const overflow = @addWithOverflow(candidate, 2);
            if (overflow != 0) break;
        }
    }
}

/// Gera um primo criptográfico de 1024 bits com as 64 rodadas padrão do Miller-Rabin.
pub fn generatePrime(rand: std.Random) u1024 {
    return generatePrimeWithRounds(rand, 64);
}

// ============================================================================
// TESTES UNITÁRIOS DA ETAPA 2 (Execute com: zig test -OReleaseFast src/core/prime.zig)
// ============================================================================

test "Etapa 2.1: Primos pequenos conhecidos e rejeição de compostos" {
    var prng = std.Random.DefaultPrng.init(12345);
    const rand = prng.random();

    try std.testing.expect(isProbablyPrime(2, rand, 64));
    try std.testing.expect(isProbablyPrime(3, rand, 64));
    try std.testing.expect(isProbablyPrime(61, rand, 64));
    try std.testing.expect(isProbablyPrime(65537, rand, 64));

    try std.testing.expect(!isProbablyPrime(0, rand, 64));
    try std.testing.expect(!isProbablyPrime(1, rand, 64));
    try std.testing.expect(!isProbablyPrime(4, rand, 64));
    try std.testing.expect(!isProbablyPrime(3233, rand, 64)); // 61 * 53
}

test "Etapa 2.2: Rejeição obrigatória de Números de Carmichael" {
    var prng = std.Random.DefaultPrng.init(67890);
    const rand = prng.random();

    // Números de Carmichael enganam o teste de Fermat puro, mas devem falhar no Miller-Rabin
    const carmichael = [_]u1024{ 561, 1105, 1729, 2465, 2821, 6601, 8911, 41041 };
    for (carmichael) |c| {
        try std.testing.expect(!isProbablyPrime(c, rand, 64));
    }
}

test "Etapa 2.3: Validação de Montgomery (std.crypto.ff) com Primos de Mersenne Gigantes" {
    var prng = std.Random.DefaultPrng.init(42);
    const rand = prng.random();

    // M_127 = 2^127 - 1 (170141183460469231731687303715884105727) -> Primo
    const m127: u1024 = (@as(u1024, 1) << 127) - 1;
    try std.testing.expect(isProbablyPrime(m127, rand, 64));

    // M_521 = 2^521 - 1 (Primo de 521 bits exercitando std.crypto.ff.Modulus(1024))
    const m521: u1024 = (@as(u1024, 1) << 521) - 1;
    try std.testing.expect(isProbablyPrime(m521, rand, 64));

    // Composto de 521 bits: (2^521 - 1) + 2
    try std.testing.expect(!isProbablyPrime(m521 + 2, rand, 64));
}

test "Etapa 2.4: Geração de primo de 1024 bits e verificação de fronteira MSB/LSB" {
    var prng = std.Random.DefaultPrng.init(999);
    const rand = prng.random();

    // Gera um primo real de 1024 bits
    const p = generatePrimeWithRounds(rand, 16);

    // 1. Verifica se o bit 1023 e o bit 1022 estão ativos (p >= 2^1023 + 2^1022)
    const min_bound: u1024 = (@as(u1024, 1) << 1023) | (@as(u1024, 1) << 1022);
    try std.testing.expect(p >= min_bound);

    // 2. Verifica se é ímpar
    try std.testing.expectEqual(@as(u1024, 1), p & 1);

    // 3. Confirma primalidade com 64 rodadas completas de Miller-Rabin
    try std.testing.expect(isProbablyPrime(p, rand, 64));
}

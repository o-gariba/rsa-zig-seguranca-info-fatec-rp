const std = @import("std");
const euclid = @import("euclid.zig");
const prime = @import("prime.zig");
const padding = @import("padding.zig");
const codec = @import("codec.zig");

const Mod1024 = std.crypto.ff.Modulus(1024);
const Mod2048 = std.crypto.ff.Modulus(2048);

/// Expoente público padrão (Fermat F4 = 2^16 + 1).
pub const PUBLIC_EXPONENT: u64 = 65537;

pub const RsaError = error{
    InvalidModulus,
    MessageOutOfRange,
    MathFailure,
} || padding.PaddingError || euclid.EuclidError;

pub const PublicKey = codec.RawPublicKey;
pub const PrivateKey = codec.RawPrivateKey;

pub const KeyPair = struct {
    public_key: PublicKey,
    private_key: PrivateKey,

    /// Limpa de forma segura todos os segredos da chave privada na stack,
    /// impedindo que o compilador remova a limpeza (Dead-Store Elimination).
    pub fn wipe(self: *KeyPair) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.private_key));
    }

    /// Gera um par de chaves RSA-2048 customizando o número de rodadas do Miller-Rabin.
    pub fn generateWithRounds(rand: std.Random, rounds: usize) RsaError!KeyPair {
        const e: u2048 = PUBLIC_EXPONENT;

        var p: u1024 = 0;
        var q: u1024 = 0;

        // 1. Sorteia o primo p de 1024 bits tal que gcd(e, p - 1) == 1
        while (true) {
            const candidate = prime.generatePrimeWithRounds(rand, rounds);
            if (euclid.gcd(e, @as(u2048, candidate - 1)) == 1) {
                p = candidate;
                break;
            }
        }

        // 2. Sorteia o primo q de 1024 bits (distinto de p) tal que gcd(e, q - 1) == 1
        while (true) {
            const candidate = prime.generatePrimeWithRounds(rand, rounds);
            if (candidate != p and euclid.gcd(e, @as(u2048, candidate - 1)) == 1) {
                q = candidate;
                break;
            }
        }

        // Garante p > q por convenção para a inversão q^-1 mod p
        if (p < q) {
            const tmp = p;
            p = q;
            q = tmp;
        }

        const p_wide: u2048 = p;
        const q_wide: u2048 = q;

        // 3. Módulo público n = p * q (2048 bits exatos)
        const n: u2048 = p_wide * q_wide;

        // 4. Totiente de Carmichael: lambda(n) = lcm(p - 1, q - 1)
        const lambda_n: u2048 = euclid.lcm(p_wide - 1, q_wide - 1);

        // 5. Expoente privado: d = e^-1 mod lambda(n) via Euclides Estendido (i4096)
        const d: u2048 = try euclid.modInverse(e, lambda_n);

        // 6. Parâmetros CRT pré-calculados em 1024 bits:
        // dp = d mod (p - 1), dq = d mod (q - 1), q_inv = q^-1 mod p
        const dp: u1024 = @intCast(d % (p_wide - 1));
        const dq: u1024 = @intCast(d % (q_wide - 1));
        const q_inv: u1024 = @intCast(try euclid.modInverse(q_wide, p_wide));

        return KeyPair{
            .public_key = .{
                .n = n,
                .e = PUBLIC_EXPONENT,
            },
            .private_key = .{
                .n = n,
                .d = d,
                .p = p,
                .q = q,
                .dp = dp,
                .dq = dq,
                .q_inv = q_inv,
            },
        };
    }

    /// Gera um par de chaves RSA-2048 padrão com 64 rodadas de Miller-Rabin.
    pub fn generate(rand: std.Random) RsaError!KeyPair {
        return generateWithRounds(rand, 64);
    }
};

/// Primitiva matemática de Criptografia Pública (RSAEP): c = m^e mod n.
/// Utiliza exponenciação de Montgomery de 2048 bits (`std.crypto.ff.Modulus(2048)`).
pub fn encryptRaw(pub_key: PublicKey, m: u2048) RsaError!u2048 {
    if (m >= pub_key.n) return RsaError.MessageOutOfRange;

    const mod_n = Mod2048.fromPrimitive(u2048, pub_key.n) catch return RsaError.InvalidModulus;
    const m_fe = Mod2048.Fe.fromPrimitive(u2048, mod_n, m) catch return RsaError.MathFailure;
    const e_fe = Mod2048.Fe.fromPrimitive(u2048, mod_n, @as(u2048, pub_key.e)) catch return RsaError.MathFailure;

    const c_fe = mod_n.powPublic(m_fe, e_fe) catch return RsaError.MathFailure;
    return c_fe.toPrimitive(u2048) catch return RsaError.MathFailure;
}

/// Primitiva matemática de Descriptografia Direta Lenta: m = c^d mod n (sem CRT).
/// Mantida para fins didáticos e para provar nos testes unitários que o CRT
/// produz exatamente o mesmo resultado matemático.
pub fn decryptRawDirect(priv_key: PrivateKey, c: u2048) RsaError!u2048 {
    if (c >= priv_key.n) return RsaError.MessageOutOfRange;

    const mod_n = Mod2048.fromPrimitive(u2048, priv_key.n) catch return RsaError.InvalidModulus;
    const c_fe = Mod2048.Fe.fromPrimitive(u2048, mod_n, c) catch return RsaError.MathFailure;
    const d_fe = Mod2048.Fe.fromPrimitive(u2048, mod_n, priv_key.d) catch return RsaError.MathFailure;

    const m_fe = mod_n.pow(c_fe, d_fe) catch return RsaError.MathFailure;
    return m_fe.toPrimitive(u2048) catch return RsaError.MathFailure;
}

/// Primitiva matemática de Descriptografia Acelerada via CRT (Algoritmo de Garner).
/// Executa duas exponenciações em corpos de 1024 bits em tempo constante (`.pow()`),
/// reduzindo o custo computacional em ~4x.
pub fn decryptRawCrt(priv_key: PrivateKey, c: u2048) RsaError!u2048 {
    if (c >= priv_key.n) return RsaError.MessageOutOfRange;

    const p_wide: u2048 = priv_key.p;
    const q_wide: u2048 = priv_key.q;

    // 1. Reduz a cifra c módulo p e módulo q para 1024 bits
    const cp: u1024 = @intCast(c % p_wide);
    const cq: u1024 = @intCast(c % q_wide);

    // 2. Exponenciação em tempo constante módulo p: m1 = cp^dp mod p
    const mod_p = Mod1024.fromPrimitive(u1024, priv_key.p) catch return RsaError.InvalidModulus;
    const cp_fe = Mod1024.Fe.fromPrimitive(u1024, mod_p, cp) catch return RsaError.MathFailure;
    const dp_fe = Mod1024.Fe.fromPrimitive(u1024, mod_p, priv_key.dp) catch return RsaError.MathFailure;
    const m1_fe = mod_p.pow(cp_fe, dp_fe) catch return RsaError.MathFailure;
    const m1: u2048 = m1_fe.toPrimitive(u1024) catch return RsaError.MathFailure;

    // 3. Exponenciação em tempo constante módulo q: m2 = cq^dq mod q
    const mod_q = Mod1024.fromPrimitive(u1024, priv_key.q) catch return RsaError.InvalidModulus;
    const cq_fe = Mod1024.Fe.fromPrimitive(u1024, mod_q, cq) catch return RsaError.MathFailure;
    const dq_fe = Mod1024.Fe.fromPrimitive(u1024, mod_q, priv_key.dq) catch return RsaError.MathFailure;
    const m2_fe = mod_q.pow(cq_fe, dq_fe) catch return RsaError.MathFailure;
    const m2: u2048 = m2_fe.toPrimitive(u1024) catch return RsaError.MathFailure;

    // 4. Recombinação de Garner:
    // diff = (m1 - m2) mod p (ajustado para nunca dar negativo em unsigned)
    const m2_mod_p: u2048 = m2 % p_wide;
    const diff: u2048 = (m1 + p_wide - m2_mod_p) % p_wide;

    // h = (q_inv * diff) mod p
    const h: u2048 = euclid.mulMod(@as(u2048, priv_key.q_inv), diff, p_wide);

    // m = m2 + h * q
    return m2 + (h * q_wide);
}

/// Criptografa uma mensagem em bytes aplicando o padding OAEP-SHA256 + RSAEP.
pub fn encryptOaep(pub_key: PublicKey, msg: []const u8, rand: std.Random) RsaError!u2048 {
    var padded = try padding.encodeOaep(msg, rand);
    defer std.crypto.secureZero(u8, &padded);

    const m = std.mem.readInt(u2048, &padded, .big);
    return encryptRaw(pub_key, m);
}

/// Descriptografa um inteiro cifrado `c` usando CRT e remove o padding OAEP-SHA256.
pub fn decryptOaep(
    priv_key: PrivateKey,
    c: u2048,
    out_buf: *[padding.OAEP_MAX_MSG_LEN]u8,
) RsaError![]const u8 {
    const m = try decryptRawCrt(priv_key, c);

    var em: [padding.BLOCK_SIZE]u8 = undefined;
    defer std.crypto.secureZero(u8, &em);
    std.mem.writeInt(u2048, &em, m, .big);

    return padding.decodeOaep(&em, out_buf);
}

// ============================================================================
// TESTES UNITÁRIOS DA ETAPA 4 (Execute com: zig test -OReleaseFast src/core/rsa.zig)
// ============================================================================

test "Etapa 4.1: Ciclo completo RSA-2048 e equivalência CRT vs Exponenciação Direta" {
    var prng = std.Random.DefaultPrng.init(202604);
    const rand = prng.random();

    // Gera chave RSA-2048 real (usando 16 rodadas no teste para execução rápida)
    var kp = try KeyPair.generateWithRounds(rand, 16);
    defer kp.wipe();

    // Verifica se o módulo n tem exatamente 2048 bits (bit 2047 ativo)
    try std.testing.expect((kp.public_key.n >> 2047) == 1);

    // Criptografa mensagem usando OAEP
    const msg = "Prova real do Teorema Chines dos Restos no RSA-2048!";
    const ciphertext = try encryptOaep(kp.public_key, msg, rand);

    // 1. Verifica se a descriptografia CRT bate exatamente com a descriptografia direta (c^d mod n)
    const m_crt = try decryptRawCrt(kp.private_key, ciphertext);
    const m_direct = try decryptRawDirect(kp.private_key, ciphertext);
    try std.testing.expectEqual(m_direct, m_crt);

    // 2. Verifica se o texto plano decodificado do OAEP é idêntico ao original
    var out_buf: [padding.OAEP_MAX_MSG_LEN]u8 = undefined;
    const decrypted_msg = try decryptOaep(kp.private_key, ciphertext, &out_buf);
    try std.testing.expectEqualStrings(msg, decrypted_msg);
}

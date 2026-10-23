//! ============================================================================
//! rsa.zig — Etapa 4: Núcleo RSA-2048 (Keygen, Criptografia e Descriptografia CRT)
//! ============================================================================
//!
//! Implementação completa do protocolo RSA-2048 operando exclusivamente na stack:
//!
//! 1. Geração de Chaves (`KeyPair.generate`):
//!    - Sorteia primos p e q de 1024 bits (garantindo gcd(e, p-1) == 1 e p != q).
//!    - Módulo público: n = p · q (exatamente 2048 bits).
//!    - Totiente de Carmichael: λ(n) = lcm(p-1, q-1).
//!    - Expoente público: e = 65537 (primo de Fermat F4 = 2^16 + 1).
//!    - Expoente privado: d ≡ e^-1 (mod λ(n)) via Euclides Estendido sobre i4096.
//!    - Pré-cálculo dos parâmetros do Teorema Chinês dos Restos (CRT):
//!        dp    = d mod (p - 1)
//!        dq    = d mod (q - 1)
//!        q_inv = q^-1 mod p
//!
//! 2. Criptografia Pública (RSAEP):
//!    - c = m^e mod n  usando Montgomery 2048 bits (`std.crypto.ff.Modulus(2048)`).
//!
//! 3. Descriptografia Acelerada via CRT / Algoritmo de Garner (RSADP):
//!    - c_p = c mod p;  c_q = c mod q  (redução de 2048 para 1024 bits)
//!    - m_1 = c_p^dp mod p;  m_2 = c_q^dq mod q  (em tempo constante `.pow()`)
//!    - diff = (m_1 + p - (m_2 mod p)) mod p  (evita overflow/underflow negativo)
//!    - h = (q_inv · diff) mod p
//!    - m = m_2 + h · q
//!
//! Por que o CRT proporciona ganho de velocidade de ~4x:
//!    A complexidade da exponenciação modular com operandos de k bits é O(k^3).
//!    A exponenciação direta direta c^d mod n com 2048 bits requer:
//!        C_direto ≈ (2048)^3 = 8 · 1024^3
//!    Com CRT, realizamos duas exponenciações independentes de 1024 bits:
//!        C_crt ≈ 2 · (1024)^3
//!    Razão teórica: (8 · 1024^3) / (2 · 1024^3) = 4x mais rápido!
//!
//! Todas as chaves e dados sensíveis são limpos com `std.crypto.secureZero`.
//! ============================================================================

const std = @import("std");
const euclid = @import("euclid.zig");
const prime = @import("prime.zig");
const padding = @import("padding.zig");
const codec = @import("codec.zig");

const Mod1024 = std.crypto.ff.Modulus(1024);
const Mod2048 = std.crypto.ff.Modulus(2048);

/// Expoente público padrão da indústria (Fermat F4 = 2^16 + 1 = 65537).
/// Possui apenas dois bits '1' em binário (0b10000000000000001), exigindo
/// somente 16 quadraturas e 1 multiplicação modular para criptografia rápida.
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
    /// impedindo remoção da escrita pelo compilador (Dead-Store Elimination).
    pub fn wipe(self: *KeyPair) void {
        self.private_key.wipe();
    }

    /// Gera um par de chaves RSA-2048 especificando o número de rodadas do Miller-Rabin.
    pub fn generateWithRounds(rand: std.Random, rounds: usize) RsaError!KeyPair {
        const e: u2048 = PUBLIC_EXPONENT;

        var p: u1024 = 0;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&p));
        var q: u1024 = 0;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&q));

        // 1. Sorteia o primo p de 1024 bits tal que mdc(e, p - 1) == 1
        while (true) {
            const candidate = prime.generatePrimeWithRounds(rand, rounds);
            if (euclid.gcd(e, @as(u2048, candidate - 1)) == 1) {
                p = candidate;
                break;
            }
        }

        // 2. Sorteia o primo q de 1024 bits (distinto de p) tal que mdc(e, q - 1) == 1
        while (true) {
            const candidate = prime.generatePrimeWithRounds(rand, rounds);
            if (candidate != p and euclid.gcd(e, @as(u2048, candidate - 1)) == 1) {
                q = candidate;
                break;
            }
        }

        // Garante p > q por convenção do Algoritmo de Garner para q_inv = q^-1 mod p
        if (p < q) {
            const tmp = p;
            p = q;
            q = tmp;
        }

        const p_wide: u2048 = p;
        const q_wide: u2048 = q;

        // 3. Módulo público n = p · q (exatamente 2048 bits)
        // O cast prévio para u2048 evita truncamento por overflow
        const n: u2048 = p_wide * q_wide;

        // 4. Totiente de Carmichael: λ(n) = mmc(p - 1, q - 1)
        const lambda_n: u2048 = try euclid.lcm(p_wide - 1, q_wide - 1);

        // 5. Expoente privado: d = e^-1 mod λ(n) via Euclides Estendido sobre i4096
        const d: u2048 = try euclid.modInverse(e, lambda_n);

        // 6. Parâmetros CRT pré-calculados em 1024 bits para Garner:
        //    dp = d mod (p - 1)
        //    dq = d mod (q - 1)
        //    q_inv = q^-1 mod p
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

    /// Gera um par de chaves RSA-2048 padrão com 64 rodadas de Miller-Rabin (segurança 2^-128).
    pub fn generate(rand: std.Random) RsaError!KeyPair {
        return generateWithRounds(rand, prime.DEFAULT_ROUNDS);
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
/// Mantida para fins didáticos e para verificação matemática contra o CRT nos testes.
pub fn decryptRawDirect(priv_key: PrivateKey, c: u2048) RsaError!u2048 {
    if (c >= priv_key.n) return RsaError.MessageOutOfRange;

    const mod_n = Mod2048.fromPrimitive(u2048, priv_key.n) catch return RsaError.InvalidModulus;
    const c_fe = Mod2048.Fe.fromPrimitive(u2048, mod_n, c) catch return RsaError.MathFailure;
    const d_fe = Mod2048.Fe.fromPrimitive(u2048, mod_n, priv_key.d) catch return RsaError.MathFailure;

    // Descriptografia em tempo constante com a chave privada d
    const m_fe = mod_n.pow(c_fe, d_fe) catch return RsaError.MathFailure;
    return m_fe.toPrimitive(u2048) catch return RsaError.MathFailure;
}

/// Primitiva matemática de Descriptografia Acelerada via CRT (Algoritmo de Garner).
///
/// Executa duas exponenciações independentes de 1024 bits em tempo constante (.pow()):
///   1. cp = c mod p,  cq = c mod q
///   2. m1 = cp^dp mod p
///   3. m2 = cq^dq mod q
///   4. diff = (m1 + p - (m2 mod p)) mod p
///   5. h = (q_inv · diff) mod p
///   6. m = m2 + h · q
///
/// Demonstração de corretude matemática:
///   Módulo q: m mod q = (m2 + h·q) mod q = m2 ≡ c^d mod q  (satisfeito!)
///   Módulo p: m mod p = (m2 + q_inv · (m1 - m2) · q) mod p
///                     = (m2 + 1 · (m1 - m2)) mod p
///                     = m1 ≡ c^d mod p  (satisfeito!)
pub fn decryptRawCrt(priv_key: PrivateKey, c: u2048) RsaError!u2048 {
    if (c >= priv_key.n) return RsaError.MessageOutOfRange;

    const p_wide: u2048 = priv_key.p;
    const q_wide: u2048 = priv_key.q;

    // 1. Redução da cifra de 2048 bits para os módulos de 1024 bits
    const cp: u1024 = @intCast(c % p_wide);
    const cq: u1024 = @intCast(c % q_wide);

    // 2. Exponenciação módulo p (1024 bits): m1 = cp^dp mod p
    const mod_p = Mod1024.fromPrimitive(u1024, priv_key.p) catch return RsaError.InvalidModulus;
    const cp_fe = Mod1024.Fe.fromPrimitive(u1024, mod_p, cp) catch return RsaError.MathFailure;
    const dp_fe = Mod1024.Fe.fromPrimitive(u1024, mod_p, priv_key.dp) catch return RsaError.MathFailure;
    const m1_fe = mod_p.pow(cp_fe, dp_fe) catch return RsaError.MathFailure;
    const m1: u2048 = m1_fe.toPrimitive(u1024) catch return RsaError.MathFailure;

    // 3. Exponenciação módulo q (1024 bits): m2 = cq^dq mod q
    const mod_q = Mod1024.fromPrimitive(u1024, priv_key.q) catch return RsaError.InvalidModulus;
    const cq_fe = Mod1024.Fe.fromPrimitive(u1024, mod_q, cq) catch return RsaError.MathFailure;
    const dq_fe = Mod1024.Fe.fromPrimitive(u1024, mod_q, priv_key.dq) catch return RsaError.MathFailure;
    const m2_fe = mod_q.pow(cq_fe, dq_fe) catch return RsaError.MathFailure;
    const m2: u2048 = m2_fe.toPrimitive(u1024) catch return RsaError.MathFailure;

    // 4. Recombinação de Garner:
    //    Garante que a subtração nunca gere valor negativo em unsigned
    const m2_mod_p: u2048 = m2 % p_wide;
    const diff: u2048 = (m1 + p_wide - m2_mod_p) % p_wide;

    //    h = (q_inv · diff) mod p
    const h: u2048 = euclid.mulMod(@as(u2048, priv_key.q_inv), diff, p_wide);

    //    m = m2 + h · q
    return m2 + (h * q_wide);
}

/// Criptografa uma mensagem em bytes aplicando o esquema OAEP-SHA256 + RSAEP.
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
    var m = try decryptRawCrt(priv_key, c);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&m));

    var em: [padding.BLOCK_SIZE]u8 = undefined;
    defer std.crypto.secureZero(u8, &em);
    std.mem.writeInt(u2048, &em, m, .big);

    return padding.decodeOaep(&em, out_buf);
}

/// Criptografa uma mensagem em bytes usando PKCS#1 v1.5 + RSAEP (modo didático).
pub fn encryptPkcs1v15(pub_key: PublicKey, msg: []const u8, rand: std.Random) RsaError!u2048 {
    var padded = try padding.encodePkcs1v15(msg, rand);
    defer std.crypto.secureZero(u8, &padded);

    const m = std.mem.readInt(u2048, &padded, .big);
    return encryptRaw(pub_key, m);
}

/// Descriptografa um inteiro cifrado `c` usando CRT e remove o padding PKCS#1 v1.5.
pub fn decryptPkcs1v15(
    priv_key: PrivateKey,
    c: u2048,
    out_buf: *[padding.PKCS1_MAX_MSG_LEN]u8,
) RsaError![]const u8 {
    var m = try decryptRawCrt(priv_key, c);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&m));

    var em: [padding.BLOCK_SIZE]u8 = undefined;
    defer std.crypto.secureZero(u8, &em);
    std.mem.writeInt(u2048, &em, m, .big);

    return padding.decodePkcs1v15(&em, out_buf);
}

// ============================================================================
// TESTES UNITÁRIOS — ETAPA 4 (RSA NÚCLEO)
// ============================================================================

const testing = std.testing;

test "Etapa 4.1: Ciclo completo RSA-2048 e equivalência matemática CRT vs Exponenciação Direta" {
    var prng = std.Random.DefaultPrng.init(202604);
    const rand = prng.random();

    // Gera um par de chaves RSA-2048 real (16 rodadas no teste unitário para rapidez)
    var kp = try KeyPair.generateWithRounds(rand, 16);
    defer kp.wipe();

    // 1. Verifica se o módulo n tem exatamente 2048 bits (bit 2047 ativo e bit 2048+ nulo)
    try testing.expect((kp.public_key.n >> 2047) == 1);
    try testing.expect(kp.public_key.e == 65537);

    // 2. Criptografa mensagem usando OAEP
    const msg = "Prova real do Teorema Chines dos Restos no RSA-2048 em Zig!";
    const ciphertext = try encryptOaep(kp.public_key, msg, rand);

    // 3. Prova da Fórmula de Garner: Descriptografia CRT DEVE ser IDÊNTICA à direta (c^d mod n)
    const m_crt = try decryptRawCrt(kp.private_key, ciphertext);
    const m_direct = try decryptRawDirect(kp.private_key, ciphertext);
    try testing.expectEqual(m_direct, m_crt);

    // 4. Decodificação OAEP restaura exatamente o texto original
    var out_buf: [padding.OAEP_MAX_MSG_LEN]u8 = undefined;
    const decrypted_msg = try decryptOaep(kp.private_key, ciphertext, &out_buf);
    try testing.expectEqualStrings(msg, decrypted_msg);
}

test "Etapa 4.2: Ciclo com PKCS#1 v1.5 e verificação de limites" {
    var prng = std.Random.DefaultPrng.init(98765);
    const rand = prng.random();

    var kp = try KeyPair.generateWithRounds(rand, 16);
    defer kp.wipe();

    const msg = "Teste modo didatico PKCS#1 v1.5";
    const cipher = try encryptPkcs1v15(kp.public_key, msg, rand);

    var out_buf: [padding.PKCS1_MAX_MSG_LEN]u8 = undefined;
    const plain = try decryptPkcs1v15(kp.private_key, cipher, &out_buf);
    try testing.expectEqualStrings(msg, plain);

    // Teste de mensagem fora dos limites (m >= n)
    try testing.expectError(RsaError.MessageOutOfRange, encryptRaw(kp.public_key, kp.public_key.n));
    try testing.expectError(RsaError.MessageOutOfRange, decryptRawCrt(kp.private_key, kp.public_key.n));
    try testing.expectError(RsaError.MessageOutOfRange, decryptRawDirect(kp.private_key, kp.public_key.n));
}

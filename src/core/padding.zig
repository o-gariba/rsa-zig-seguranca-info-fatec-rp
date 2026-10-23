//! ============================================================================
//! padding.zig — Etapa 3: Preenchimento Criptográfico (OAEP e PKCS#1 v1.5)
//! ============================================================================
//!
//! Por que o RSA "Textbook" (c = m^e mod n) é CRITICAMENTE INSEGURO:
//!
//!   1. Determinismo: Criptografar a mesma mensagem m duas vezes produz o
//!      mesmo texto cifrado c. Um atacante pode testar dicionários ("Sim" / "Não").
//!   2. Homomorfismo multiplicativo (Maleabilidade):
//!          c_1 · c_2 = (m_1^e) · (m_2^e) ≡ (m_1 · m_2)^e (mod n)
//!      Um atacante pode manipular a cifra sem conhecer a chave privada.
//!   3. Ataque de raiz e-ésima (Coppersmith / Small Public Exponent):
//!      Se m for pequeno e e = 3 ou até e = 65537 com m < 2^(2048/e), então
//!      m^e < n no conjunto dos inteiros (sem redução modular!). O atacante
//!      recupera m extraindo a raiz e-ésima exata: m = ⌊c^{1/e}⌋.
//!
//! Solução: Padding probabilístico que expande a mensagem para k = 256 bytes
//! (2048 bits), garantindo m < n com um byte 0x00 mais significativo e
//! misturando bits via rede de Feistel invertível (OAEP, RFC 8017).
//!
//! Diagrama de Blocos do OAEP (Optimal Asymmetric Encryption Padding):
//!
//!                     +----------+             +--+-------+
//!                     |   seed   |             |  |   M   |
//!                     +----+-----+             +--+---+---+
//!                          |                          |
//!                          |     +----------+         |
//!                          |     | SHA256(L)|         |
//!                          |     +----+-----+         |
//!                          |          |  +--+         |
//!                          |          |  |PS|01       |
//!                          |          +--+--+---------+
//!                          |          |      DB       |
//!                          v          +-------+-------+
//!                      +-------+              |
//!                      | MGF1  |              |
//!                      +---+---+              |
//!                          |                  |
//!                          +------------> (+) | (dbMask)
//!                          |               |
//!                          |               v
//!                          |         +-----+-----+
//!                          |         | maskedDB  |
//!                          |         +-----+-----+
//!                          |               |
//!                          |   +-------+   |
//!                          |   | MGF1  | <-+
//!                          |   +---+---+
//!                          |       |
//!                      (+) <-------+ (seedMask)
//!                       |
//!                       v
//!                 +-----+------+
//!                 | maskedSeed |
//!                 +-----+------+
//!                       |                     |
//!                       +-----------+---------+
//!                                   |
//!                 EM = [ 0x00 || maskedSeed || maskedDB ]
//!                        (1B)      (32B)        (223B)  = 256 bytes
//!
//! Todo o diretório opera 100% na stack com buffers de tamanho fixo.
//! ============================================================================

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Tamanho do bloco RSA-2048 em bytes (2048 / 8 = 256 bytes).
pub const BLOCK_SIZE: usize = 256;

/// Tamanho do digest SHA-256 em bytes (256 / 8 = 32 bytes).
pub const HASH_LEN: usize = 32;

/// Tamanho do bloco de dados (Data Block - DB) no esquema OAEP:
/// DB_LEN = BLOCK_SIZE - HASH_LEN - 1 = 256 - 32 - 1 = 223 bytes.
pub const OAEP_DB_LEN: usize = BLOCK_SIZE - HASH_LEN - 1;

/// Capacidade máxima útil da mensagem em bytes no RSA-2048 com OAEP-SHA256:
/// MAX_MSG = BLOCK_SIZE - 2*HASH_LEN - 2 = 256 - 64 - 2 = 190 bytes.
pub const OAEP_MAX_MSG_LEN: usize = BLOCK_SIZE - (2 * HASH_LEN) - 2;

/// Capacidade máxima útil da mensagem em bytes no RSA-2048 com PKCS#1 v1.5:
/// MAX_MSG = BLOCK_SIZE - 11 = 256 - 11 = 245 bytes (mínimo de 8 bytes de padding não-nulo).
pub const PKCS1_MAX_MSG_LEN: usize = BLOCK_SIZE - 11;

pub const PaddingError = error{
    /// Mensagem ultrapassa o limite de capacidade do bloco (190 bytes no OAEP ou 245 no PKCS#1).
    MessageTooLong,
    /// Preenchimento inválido, delimitador incorreto ou integridade violada.
    InvalidPadding,
};

/// MGF1 (Mask Generation Function 1) baseada em SHA-256 (RFC 8017, Apêndice B.2.1).
///
/// Expande deterministicamente uma semente `seed` em uma máscara de comprimento
/// arbitrário `out.len` aplicando SHA256(seed || counter) para counter = 0, 1, 2...
pub fn mgf1Sha256(seed: []const u8, out: []u8) void {
    var counter: u32 = 0;
    var offset: usize = 0;
    var digest: [HASH_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    var counter_bytes: [4]u8 = undefined;

    while (offset < out.len) : (counter += 1) {
        std.mem.writeInt(u32, &counter_bytes, counter, .big);

        var hasher = Sha256.init(.{});
        hasher.update(seed);
        hasher.update(&counter_bytes);
        hasher.final(&digest);

        const remaining = out.len - offset;
        const to_copy = @min(remaining, HASH_LEN);
        @memcpy(out[offset .. offset + to_copy], digest[0..to_copy]);
        offset += to_copy;
    }
}

/// Aplica o esquema de preenchimento probabilístico RSA-OAEP (SHA-256 + MGF1).
///
/// Produz um bloco codificado EM (Encoded Message) de exatamente 256 bytes:
///
///   1. DB = SHA256(L) || PS (0x00...) || 0x01 || M
///      onde L = rótulo vazio "", PS preenche com zeros até o total de 223 bytes.
///   2. Sorteia seed aleatório de 32 bytes via CSPRNG.
///   3. dbMask = MGF1(seed, 223);  maskedDB = DB ⊕ dbMask
///   4. seedMask = MGF1(maskedDB, 32);  maskedSeed = seed ⊕ seedMask
///   5. EM = 0x00 || maskedSeed || maskedDB
///
/// O primeiro byte 0x00 garante matematicamente que o inteiro resultante `m`
/// seja estritamente menor que o módulo RSA `n` (m < n).
pub fn encodeOaep(msg: []const u8, rand: std.Random) PaddingError![BLOCK_SIZE]u8 {
    if (msg.len > OAEP_MAX_MSG_LEN) return PaddingError.MessageTooLong;

    var em: [BLOCK_SIZE]u8 = @splat(0);

    // Hash do rótulo padrão vazio L = ""
    var l_hash: [HASH_LEN]u8 = undefined;
    Sha256.hash("", &l_hash, .{});

    // 1. Monta DB = lHash || PS || 0x01 || msg
    var db: [OAEP_DB_LEN]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &db);

    @memcpy(db[0..HASH_LEN], &l_hash);
    const separator_idx = OAEP_DB_LEN - msg.len - 1;
    db[separator_idx] = 0x01;
    @memcpy(db[separator_idx + 1 ..], msg);

    // 2. Gera a semente aleatória (32 bytes)
    var seed: [HASH_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    rand.bytes(&seed);

    // 3. Mascara o DB: dbMask = MGF1(seed, 223), maskedDB = DB ⊕ dbMask
    var db_mask: [OAEP_DB_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &db_mask);
    mgf1Sha256(&seed, &db_mask);

    var masked_db = em[1 + HASH_LEN .. BLOCK_SIZE];
    for (0..OAEP_DB_LEN) |i| {
        masked_db[i] = db[i] ^ db_mask[i];
    }

    // 4. Mascara a semente: seedMask = MGF1(maskedDB, 32), maskedSeed = seed ⊕ seedMask
    var seed_mask: [HASH_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed_mask);
    mgf1Sha256(masked_db, &seed_mask);

    var masked_seed = em[1 .. 1 + HASH_LEN];
    for (0..HASH_LEN) |i| {
        masked_seed[i] = seed[i] ^ seed_mask[i];
    }

    // em[0] é 0x00
    return em;
}

/// Remove e valida o preenchimento RSA-OAEP de um bloco de 256 bytes decifrado.
///
/// Executa a decodificação da rede de Feistel:
///   1. seed = maskedSeed ⊕ MGF1(maskedDB, 32)
///   2. DB = maskedDB ⊕ MGF1(seed, 223)
///   3. Valida em tempo constante se o byte inicial é 0x00 e se lHash == SHA256("")
///   4. Localiza o delimitador 0x01 e extrai a mensagem M para `out_buf`.
pub fn decodeOaep(em: *const [BLOCK_SIZE]u8, out_buf: *[OAEP_MAX_MSG_LEN]u8) PaddingError![]const u8 {
    const y = em[0];
    const masked_seed = em[1 .. 1 + HASH_LEN];
    const masked_db = em[1 + HASH_LEN .. BLOCK_SIZE];

    // 1. Recupera seed = maskedSeed ⊕ MGF1(maskedDB, 32)
    var seed_mask: [HASH_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed_mask);
    mgf1Sha256(masked_db, &seed_mask);

    var seed: [HASH_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    for (0..HASH_LEN) |i| {
        seed[i] = masked_seed[i] ^ seed_mask[i];
    }

    // 2. Recupera DB = maskedDB ⊕ MGF1(seed, 223)
    var db_mask: [OAEP_DB_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &db_mask);
    mgf1Sha256(&seed, &db_mask);

    var db: [OAEP_DB_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &db);
    for (0..OAEP_DB_LEN) |i| {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    // 3. Validação de lHash e do byte de liderança y (deve ser 0x00)
    var expected_l_hash: [HASH_LEN]u8 = undefined;
    Sha256.hash("", &expected_l_hash, .{});

    var bad: u8 = y;
    for (0..HASH_LEN) |i| {
        bad |= db[i] ^ expected_l_hash[i];
    }

    // 4. Localiza o separador 0x01 após o preenchimento PS (zeros)
    var sep_idx: usize = HASH_LEN;
    var found_one = false;
    while (sep_idx < OAEP_DB_LEN) : (sep_idx += 1) {
        const b = db[sep_idx];
        if (b == 0x00) continue;
        if (b == 0x01) {
            found_one = true;
            break;
        }
        return PaddingError.InvalidPadding;
    }

    if (bad != 0 or !found_one) return PaddingError.InvalidPadding;

    const msg_start = sep_idx + 1;
    const msg_len = OAEP_DB_LEN - msg_start;
    if (msg_len > OAEP_MAX_MSG_LEN) return PaddingError.InvalidPadding;

    @memcpy(out_buf[0..msg_len], db[msg_start..]);
    return out_buf[0..msg_len];
}

/// Preenchimento clássico PKCS#1 v1.5 (RFC 8017, Seção 7.2.1):
/// EM = 0x00 || 0x02 || PS (bytes não-nulos pseudoaleatórios, len >= 8) || 0x00 || M
pub fn encodePkcs1v15(msg: []const u8, rand: std.Random) PaddingError![BLOCK_SIZE]u8 {
    if (msg.len > PKCS1_MAX_MSG_LEN) return PaddingError.MessageTooLong;

    var em: [BLOCK_SIZE]u8 = undefined;
    em[0] = 0x00;
    em[1] = 0x02;

    const ps_len = BLOCK_SIZE - 3 - msg.len;
    var i: usize = 0;
    while (i < ps_len) {
        var b: [1]u8 = undefined;
        rand.bytes(&b);
        if (b[0] != 0) {
            em[2 + i] = b[0];
            i += 1;
        }
    }

    em[2 + ps_len] = 0x00;
    @memcpy(em[3 + ps_len ..], msg);
    return em;
}

/// Remove e valida o preenchimento PKCS#1 v1.5 de um bloco de 256 bytes.
pub fn decodePkcs1v15(em: *const [BLOCK_SIZE]u8, out_buf: *[PKCS1_MAX_MSG_LEN]u8) PaddingError![]const u8 {
    if (em[0] != 0x00 or em[1] != 0x02) return PaddingError.InvalidPadding;

    var sep_idx: usize = 2;
    while (sep_idx < BLOCK_SIZE) : (sep_idx += 1) {
        if (em[sep_idx] == 0x00) break;
    }

    // PS deve ter no mínimo 8 bytes não-nulos (logo sep_idx >= 10)
    if (sep_idx < 10 or sep_idx >= BLOCK_SIZE) return PaddingError.InvalidPadding;

    const msg_start = sep_idx + 1;
    const msg_len = BLOCK_SIZE - msg_start;
    @memcpy(out_buf[0..msg_len], em[msg_start..]);
    return out_buf[0..msg_len];
}

// ============================================================================
// TESTES UNITÁRIOS — ETAPA 3 (PADDING)
// ============================================================================

const testing = std.testing;

test "Etapa 3.1: Ciclo completo OAEP e não-determinismo (aleatoriedade)" {
    var prng = std.Random.DefaultPrng.init(2026);
    const rand = prng.random();

    const msg = "Segredo matematico RSA-2048 em Zig!";
    const block1 = try encodeOaep(msg, rand);
    const block2 = try encodeOaep(msg, rand);

    // O primeiro byte deve ser sempre 0x00 para garantir m < n
    try testing.expectEqual(@as(u8, 0x00), block1[0]);
    try testing.expectEqual(@as(u8, 0x00), block2[0]);

    // Duas cifragens da mesma mensagem DEVEM gerar blocos inteiramente distintos (probabilístico)
    try testing.expect(!std.mem.eql(u8, &block1, &block2));

    // A decodificação de ambos restaura fielmente a mensagem original
    var out1: [OAEP_MAX_MSG_LEN]u8 = undefined;
    var out2: [OAEP_MAX_MSG_LEN]u8 = undefined;
    const dec1 = try decodeOaep(&block1, &out1);
    const dec2 = try decodeOaep(&block2, &out2);

    try testing.expectEqualStrings(msg, dec1);
    try testing.expectEqualStrings(msg, dec2);
}

test "Etapa 3.2: Limite máximo de mensagem no OAEP (190 bytes)" {
    var prng = std.Random.DefaultPrng.init(42);
    const rand = prng.random();

    var max_msg: [OAEP_MAX_MSG_LEN]u8 = undefined;
    @memset(&max_msg, 'A');

    const block = try encodeOaep(&max_msg, rand);
    var out: [OAEP_MAX_MSG_LEN]u8 = undefined;
    const dec = try decodeOaep(&block, &out);
    try testing.expectEqualStrings(&max_msg, dec);

    // 191 bytes deve retornar MessageTooLong
    var too_long: [OAEP_MAX_MSG_LEN + 1]u8 = undefined;
    @memset(&too_long, 'B');
    try testing.expectError(PaddingError.MessageTooLong, encodeOaep(&too_long, rand));
}

test "Etapa 3.3: Detecção de adulteração e violação de integridade em bloco OAEP" {
    var prng = std.Random.DefaultPrng.init(77);
    const rand = prng.random();

    var block = try encodeOaep("Teste de integridade OAEP", rand);

    // Corrompe 1 bit no meio do maskedDB
    block[100] ^= 0x01;
    var out: [OAEP_MAX_MSG_LEN]u8 = undefined;
    try testing.expectError(PaddingError.InvalidPadding, decodeOaep(&block, &out));

    // Restaura e corrompe o byte de liderança 0x00
    block[100] ^= 0x01;
    block[0] = 0x01;
    try testing.expectError(PaddingError.InvalidPadding, decodeOaep(&block, &out));
}

test "Etapa 3.4: Ciclo completo PKCS#1 v1.5 e detecção de corrupção" {
    var prng = std.Random.DefaultPrng.init(99);
    const rand = prng.random();

    const msg = "Modo didatico PKCS#1 v1.5";
    const block = try encodePkcs1v15(msg, rand);

    try testing.expectEqual(@as(u8, 0x00), block[0]);
    try testing.expectEqual(@as(u8, 0x02), block[1]);

    var out: [PKCS1_MAX_MSG_LEN]u8 = undefined;
    const decoded = try decodePkcs1v15(&block, &out);
    try testing.expectEqualStrings(msg, decoded);

    // Mensagem com tamanho máximo de 245 bytes
    var max_msg: [PKCS1_MAX_MSG_LEN]u8 = undefined;
    @memset(&max_msg, 'Z');
    const max_block = try encodePkcs1v15(&max_msg, rand);
    const max_dec = try decodePkcs1v15(&max_block, &out);
    try testing.expectEqualStrings(&max_msg, max_dec);

    var too_long: [PKCS1_MAX_MSG_LEN + 1]u8 = undefined;
    try testing.expectError(PaddingError.MessageTooLong, encodePkcs1v15(&too_long, rand));
}

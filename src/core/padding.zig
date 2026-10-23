const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Tamanho do bloco RSA-2048 em bytes (2048 / 8 = 256 bytes).
pub const BLOCK_SIZE: usize = 256;
/// Tamanho do digest SHA-256 em bytes (256 / 8 = 32 bytes).
pub const HASH_LEN: usize = 32;
/// Tamanho do Data Block (DB) no OAEP: 256 - 32 - 1 = 223 bytes.
pub const OAEP_DB_LEN: usize = BLOCK_SIZE - HASH_LEN - 1;
/// Tamanho máximo da mensagem para RSA-2048 com OAEP-SHA256: 256 - 2*32 - 2 = 190 bytes.
pub const OAEP_MAX_MSG_LEN: usize = BLOCK_SIZE - (2 * HASH_LEN) - 2;
/// Tamanho máximo da mensagem para RSA-2048 com PKCS#1 v1.5: 256 - 11 = 245 bytes.
pub const PKCS1_MAX_MSG_LEN: usize = BLOCK_SIZE - 11;

pub const PaddingError = error{
    MessageTooLong,
    InvalidPadding,
};

/// MGF1 (Mask Generation Function 1) baseada em SHA-256 (RFC 8017, Apêndice B.2.1).
/// Expande uma semente de tamanho arbitrário em uma máscara pseudoaleatória `out`.
pub fn mgf1Sha256(seed: []const u8, out: []u8) void {
    var counter: u32 = 0;
    var offset: usize = 0;
    var digest: [HASH_LEN]u8 = undefined;
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

/// Aplica o preenchimento OAEP (SHA-256 + MGF1) a uma mensagem de até 190 bytes,
/// produzindo um bloco de 256 bytes pronto para ser convertido em u2048.
pub fn encodeOaep(msg: []const u8, rand: std.Random) PaddingError![BLOCK_SIZE]u8 {
    if (msg.len > OAEP_MAX_MSG_LEN) return PaddingError.MessageTooLong;

    var em: [BLOCK_SIZE]u8 = @splat(0);

    // Hash do rótulo vazio L = ""
    var l_hash: [HASH_LEN]u8 = undefined;
    Sha256.hash("", &l_hash, .{});

    // 1. Monta DB = lHash || PS (zeros) || 0x01 || msg
    var db: [OAEP_DB_LEN]u8 = @splat(0);
    @memcpy(db[0..HASH_LEN], &l_hash);
    const separator_idx = OAEP_DB_LEN - msg.len - 1;
    db[separator_idx] = 0x01;
    @memcpy(db[separator_idx + 1 ..], msg);

    // 2. Gera seed aleatório de 32 bytes
    var seed: [HASH_LEN]u8 = undefined;
    rand.bytes(&seed);

    // 3. dbMask = MGF1(seed, 223) e maskedDB = DB ^ dbMask
    var db_mask: [OAEP_DB_LEN]u8 = undefined;
    mgf1Sha256(&seed, &db_mask);
    var masked_db = em[1 + HASH_LEN .. BLOCK_SIZE];
    for (0..OAEP_DB_LEN) |i| {
        masked_db[i] = db[i] ^ db_mask[i];
    }

    // 4. seedMask = MGF1(maskedDB, 32) e maskedSeed = seed ^ seedMask
    var seed_mask: [HASH_LEN]u8 = undefined;
    mgf1Sha256(masked_db, &seed_mask);
    var masked_seed = em[1 .. 1 + HASH_LEN];
    for (0..HASH_LEN) |i| {
        masked_seed[i] = seed[i] ^ seed_mask[i];
    }

    // em[0] permanece 0x00, garantindo que o inteiro resultante seja < n
    return em;
}

/// Remove e valida o preenchimento OAEP de um bloco de 256 bytes decifrado.
/// Copia a mensagem original para `out_buf` e retorna a fatia correspondente.
pub fn decodeOaep(em: *const [BLOCK_SIZE]u8, out_buf: *[OAEP_MAX_MSG_LEN]u8) PaddingError![]const u8 {
    const y = em[0];
    const masked_seed = em[1 .. 1 + HASH_LEN];
    const masked_db = em[1 + HASH_LEN .. BLOCK_SIZE];

    // 1. Recupera seed = maskedSeed ^ MGF1(maskedDB, 32)
    var seed_mask: [HASH_LEN]u8 = undefined;
    mgf1Sha256(masked_db, &seed_mask);
    var seed: [HASH_LEN]u8 = undefined;
    for (0..HASH_LEN) |i| {
        seed[i] = masked_seed[i] ^ seed_mask[i];
    }

    // 2. Recupera DB = maskedDB ^ MGF1(seed, 223)
    var db_mask: [OAEP_DB_LEN]u8 = undefined;
    mgf1Sha256(&seed, &db_mask);
    var db: [OAEP_DB_LEN]u8 = undefined;
    for (0..OAEP_DB_LEN) |i| {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    // 3. Verifica lHash == SHA256("") em tempo constante
    var expected_l_hash: [HASH_LEN]u8 = undefined;
    Sha256.hash("", &expected_l_hash, .{});

    var bad: u8 = y;
    for (0..HASH_LEN) |i| {
        bad |= db[i] ^ expected_l_hash[i];
    }

    // 4. Localiza o delimitador 0x01 após os zeros de PS
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
    @memcpy(out_buf[0..msg_len], db[msg_start..]);
    return out_buf[0..msg_len];
}

/// Preenchimento clássico PKCS#1 v1.5: EM = 0x00 || 0x02 || PS (não-nulo >= 8B) || 0x00 || M
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

/// Remove e valida o preenchimento PKCS#1 v1.5.
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
// TESTES UNITÁRIOS DE PADDING (Execute com: zig test src/core/padding.zig)
// ============================================================================

test "Etapa 3.1: Ciclo completo OAEP e não-determinismo (aleatoriedade)" {
    var prng = std.Random.DefaultPrng.init(2026);
    const rand = prng.random();

    const msg = "Segredo matematico RSA-2048 em Zig!";
    const block1 = try encodeOaep(msg, rand);
    const block2 = try encodeOaep(msg, rand);

    // O primeiro byte deve ser sempre 0x00 para garantir m < n
    try std.testing.expectEqual(@as(u8, 0x00), block1[0]);

    // Duas cifragens da mesma mensagem devem gerar blocos inteiramente distintos
    try std.testing.expect(!std.mem.eql(u8, &block1, &block2));

    // A decodificação de ambos deve restaurar a mensagem original
    var out1: [OAEP_MAX_MSG_LEN]u8 = undefined;
    var out2: [OAEP_MAX_MSG_LEN]u8 = undefined;
    const dec1 = try decodeOaep(&block1, &out1);
    const dec2 = try decodeOaep(&block2, &out2);

    try std.testing.expectEqualStrings(msg, dec1);
    try std.testing.expectEqualStrings(msg, dec2);
}

test "Etapa 3.2: Detecção de adulteração em bloco OAEP" {
    var prng = std.Random.DefaultPrng.init(77);
    const rand = prng.random();

    var block = try encodeOaep("Teste de integridade OAEP", rand);
    // Corrompe 1 bit no meio do maskedDB
    block[100] ^= 0x01;

    var out: [OAEP_MAX_MSG_LEN]u8 = undefined;
    try std.testing.expectError(PaddingError.InvalidPadding, decodeOaep(&block, &out));
}

test "Etapa 3.3: Ciclo completo PKCS#1 v1.5" {
    var prng = std.Random.DefaultPrng.init(99);
    const rand = prng.random();

    const msg = "Modo didatico PKCS#1 v1.5";
    const block = try encodePkcs1v15(msg, rand);

    var out: [PKCS1_MAX_MSG_LEN]u8 = undefined;
    const decoded = try decodePkcs1v15(&block, &out);
    try std.testing.expectEqualStrings(msg, decoded);
}

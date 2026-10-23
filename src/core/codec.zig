const std = @import("std");

pub const PUB_RAW_LEN: usize = 256 + 8; // n (256B) + e (8B) = 264 bytes
pub const PUB_B64_LEN: usize = std.base64.standard.Encoder.calcSize(PUB_RAW_LEN);

pub const PRIV_RAW_LEN: usize = 256 + 256 + (5 * 128); // n, d (256B) + p, q, dp, dq, q_inv (128B) = 1152 bytes
pub const PRIV_B64_LEN: usize = std.base64.standard.Encoder.calcSize(PRIV_RAW_LEN);

pub const CIPHER_RAW_LEN: usize = 256;
pub const CIPHER_B64_LEN: usize = std.base64.standard.Encoder.calcSize(CIPHER_RAW_LEN);

pub const PUB_HEADER = "-----INICIO CHAVE PUBLICA RSA-----";
pub const PUB_FOOTER = "-----FIM CHAVE PUBLICA RSA-----";
pub const PRIV_HEADER = "-----INICIO CHAVE PRIVADA RSA-----";
pub const PRIV_FOOTER = "-----FIM CHAVE PRIVADA RSA -----";

pub const CodecError = error{
    InvalidFormat,
    InvalidBase64,
    InvalidLength,
};

pub const RawPublicKey = struct {
    n: u2048,
    e: u64,
};

pub const RawPrivateKey = struct {
    n: u2048,
    d: u2048,
    p: u1024,
    q: u1024,
    dp: u1024,
    dq: u1024,
    q_inv: u1024,
};

/// Serializa uma Chave Pública em formato PEM (Base64 com cabeçalho e rodapé).
pub fn encodePublicKeyPem(key: RawPublicKey, out_buf: []u8) ![]const u8 {
    var raw: [PUB_RAW_LEN]u8 = undefined;
    std.mem.writeInt(u2048, raw[0..256], key.n, .big);
    std.mem.writeInt(u64, raw[256..264], key.e, .big);

    var b64_buf: [PUB_B64_LEN]u8 = undefined;
    const b64 = std.base64.standard.Encoder.encode(&b64_buf, &raw);

    return std.fmt.bufPrint(out_buf, "{s}\n{s}\n{s}\n", .{ PUB_HEADER, b64, PUB_FOOTER });
}

/// Desserializa uma Chave Pública a partir de texto PEM ou Base64 puro.
pub fn decodePublicKeyPem(input: []const u8) CodecError!RawPublicKey {
    var clean_buf: [PUB_B64_LEN + 64]u8 = undefined;
    const b64_slice = try extractBase64Payload(input, PUB_HEADER, PUB_FOOTER, &clean_buf);

    if (b64_slice.len != PUB_B64_LEN) return CodecError.InvalidLength;

    var raw: [PUB_RAW_LEN]u8 = undefined;
    std.base64.standard.Decoder.decode(&raw, b64_slice) catch return CodecError.InvalidBase64;

    return RawPublicKey{
        .n = std.mem.readInt(u2048, raw[0..256], .big),
        .e = std.mem.readInt(u64, raw[256..264], .big),
    };
}

/// Serializa uma Chave Privada completa (com parâmetros CRT) em formato PEM.
pub fn encodePrivateKeyPem(key: RawPrivateKey, out_buf: []u8) ![]const u8 {
    var raw: [PRIV_RAW_LEN]u8 = undefined;
    std.mem.writeInt(u2048, raw[0..256], key.n, .big);
    std.mem.writeInt(u2048, raw[256..512], key.d, .big);
    std.mem.writeInt(u1024, raw[512..640], key.p, .big);
    std.mem.writeInt(u1024, raw[640..768], key.q, .big);
    std.mem.writeInt(u1024, raw[768..896], key.dp, .big);
    std.mem.writeInt(u1024, raw[896..1024], key.dq, .big);
    std.mem.writeInt(u1024, raw[1024..1152], key.q_inv, .big);
    defer std.crypto.secureZero(u8, &raw);

    var b64_buf: [PRIV_B64_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &b64_buf);
    const b64 = std.base64.standard.Encoder.encode(&b64_buf, &raw);

    return std.fmt.bufPrint(out_buf, "{s}\n{s}\n{s}\n", .{ PRIV_HEADER, b64, PRIV_FOOTER });
}

/// Desserializa uma Chave Privada a partir de texto PEM.
pub fn decodePrivateKeyPem(input: []const u8) CodecError!RawPrivateKey {
    var clean_buf: [PRIV_B64_LEN + 64]u8 = undefined;
    const b64_slice = try extractBase64Payload(input, PRIV_HEADER, PRIV_FOOTER, &clean_buf);

    if (b64_slice.len != PRIV_B64_LEN) return CodecError.InvalidLength;

    var raw: [PRIV_RAW_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw);
    std.base64.standard.Decoder.decode(&raw, b64_slice) catch return CodecError.InvalidBase64;

    return RawPrivateKey{
        .n = std.mem.readInt(u2048, raw[0..256], .big),
        .d = std.mem.readInt(u2048, raw[256..512], .big),
        .p = std.mem.readInt(u1024, raw[512..640], .big),
        .q = std.mem.readInt(u1024, raw[640..768], .big),
        .dp = std.mem.readInt(u1024, raw[768..896], .big),
        .dq = std.mem.readInt(u1024, raw[896..1024], .big),
        .q_inv = std.mem.readInt(u1024, raw[1024..1152], .big),
    };
}

/// Codifica um inteiro cifrado `c` (u2048) em uma string Base64 de 344 caracteres.
pub fn encodeCiphertextBase64(c: u2048, out_buf: *[CIPHER_B64_LEN]u8) []const u8 {
    var raw: [CIPHER_RAW_LEN]u8 = undefined;
    std.mem.writeInt(u2048, &raw, c, .big);
    return std.base64.standard.Encoder.encode(out_buf, &raw);
}

/// Decodifica uma string Base64 de volta para o inteiro cifrado `c` (u2048).
pub fn decodeCiphertextBase64(b64_input: []const u8) CodecError!u2048 {
    const trimmed = std.mem.trim(u8, b64_input, " \t\r\n");
    if (trimmed.len != CIPHER_B64_LEN) return CodecError.InvalidLength;

    var raw: [CIPHER_RAW_LEN]u8 = undefined;
    std.base64.standard.Decoder.decode(&raw, trimmed) catch return CodecError.InvalidBase64;
    return std.mem.readInt(u2048, &raw, .big);
}

/// Remove cabeçalhos PEM e quebras de linha, extraindo apenas os caracteres Base64.
fn extractBase64Payload(input: []const u8, header: []const u8, footer: []const u8, out_clean: []u8) CodecError![]const u8 {
    var slice = std.mem.trim(u8, input, " \t\r\n");
    if (std.mem.startsWith(u8, slice, header)) {
        slice = slice[header.len..];
    }
    if (std.mem.endsWith(u8, slice, footer)) {
        slice = slice[0 .. slice.len - footer.len];
    }

    var idx: usize = 0;
    for (slice) |ch| {
        if (ch == ' ' or ch == '\n' or ch == '\r' or ch == '\t') continue;
        if (idx >= out_clean.len) return CodecError.InvalidLength;
        out_clean[idx] = ch;
        idx += 1;
    }
    return out_clean[0..idx];
}

// ============================================================================
// TESTES UNITÁRIOS DE CODEC (Execute com: zig test src/core/codec.zig)
// ============================================================================

test "Etapa 3.4: Serialização e Desserialização de Chave Pública PEM" {
    const pub_orig = RawPublicKey{
        .n = (@as(u2048, 0xDEADBEEF) << 2000) | 0xCAFEBABE,
        .e = 65537,
    };

    var pem_buf: [512]u8 = undefined;
    const pem_str = try encodePublicKeyPem(pub_orig, &pem_buf);

    const pub_dec = try decodePublicKeyPem(pem_str);
    try std.testing.expectEqual(pub_orig.n, pub_dec.n);
    try std.testing.expectEqual(pub_orig.e, pub_dec.e);
}

test "Etapa 3.5: Serialização e Desserialização de Chave Privada CRT e Cifra" {
    const priv_orig = RawPrivateKey{
        .n = (@as(u2048, 1) << 2047) + 12345,
        .d = (@as(u2048, 1) << 2040) + 67890,
        .p = (@as(u1024, 1) << 1023) + 111,
        .q = (@as(u1024, 1) << 1023) + 222,
        .dp = 333,
        .dq = 444,
        .q_inv = 555,
    };

    var pem_buf: [2048]u8 = undefined;
    const pem_str = try encodePrivateKeyPem(priv_orig, &pem_buf);

    const priv_dec = try decodePrivateKeyPem(pem_str);
    try std.testing.expectEqual(priv_orig.n, priv_dec.n);
    try std.testing.expectEqual(priv_orig.d, priv_dec.d);
    try std.testing.expectEqual(priv_orig.p, priv_dec.p);
    try std.testing.expectEqual(priv_orig.q_inv, priv_dec.q_inv);

    // Teste de cifra em Base64
    var c_buf: [CIPHER_B64_LEN]u8 = undefined;
    const c_b64 = encodeCiphertextBase64(priv_orig.n, &c_buf);
    const c_dec = try decodeCiphertextBase64(c_b64);
    try std.testing.expectEqual(priv_orig.n, c_dec);
}

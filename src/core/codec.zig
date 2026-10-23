//! ============================================================================
//! codec.zig — Etapa 3: Serialização e Desserialização (PEM, Base64 e Hex)
//! ============================================================================
//!
//! Fornece funções para codificação e decodificação na stack (zero heap):
//!   - Chave Pública em PEM (Base64 com cabeçalho/rodapé):
//!       -----INICIO CHAVE PUBLICA RSA-----
//!       ... (n em 256 bytes Big-Endian + e em 8 bytes Big-Endian) ...
//!       -----FIM CHAVE PUBLICA RSA-----
//!   - Chave Privada CRT em PEM:
//!       -----INICIO CHAVE PRIVADA RSA-----
//!       ... (n[256B] || d[256B] || p[128B] || q[128B] || dp[128B] || dq[128B] || q_inv[128B]) ...
//!       -----FIM CHAVE PRIVADA RSA-----
//!   - Texto cifrado em Base64 (344 caracteres correspondentes a 256 bytes)
//!   - Codificação e decodificação Hexadecimal (base 16)
//!
//! Todas as rotinas que manuseiam a chave privada invocam `std.crypto.secureZero`
//! para prevenir vazamento de material criptográfico na stack.
//! ============================================================================

const std = @import("std");

/// Tamanho bruto da chave pública: n (256B) + e (8B) = 264 bytes.
pub const PUB_RAW_LEN: usize = 256 + 8;
/// Tamanho da representação Base64 da chave pública: 352 caracteres.
pub const PUB_B64_LEN: usize = std.base64.standard.Encoder.calcSize(PUB_RAW_LEN);

/// Tamanho bruto da chave privada completa (com parâmetros CRT):
/// n (256B) + d (256B) + p (128B) + q (128B) + dp (128B) + dq (128B) + q_inv (128B) = 1152 bytes.
pub const PRIV_RAW_LEN: usize = 256 + 256 + (5 * 128);
/// Tamanho da representação Base64 da chave privada: 1536 caracteres.
pub const PRIV_B64_LEN: usize = std.base64.standard.Encoder.calcSize(PRIV_RAW_LEN);

/// Tamanho bruto do bloco criptografado RSA-2048: 256 bytes.
pub const CIPHER_RAW_LEN: usize = 256;
/// Tamanho da representação Base64 do bloco cifrado: 344 caracteres.
pub const CIPHER_B64_LEN: usize = std.base64.standard.Encoder.calcSize(CIPHER_RAW_LEN);

pub const PUB_HEADER = "-----INICIO CHAVE PUBLICA RSA-----";
pub const PUB_FOOTER = "-----FIM CHAVE PUBLICA RSA-----";
pub const PRIV_HEADER = "-----INICIO CHAVE PRIVADA RSA-----";
pub const PRIV_FOOTER = "-----FIM CHAVE PRIVADA RSA-----";

pub const CodecError = error{
    InvalidFormat,
    InvalidBase64,
    InvalidHex,
    InvalidLength,
    BufferTooSmall,
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

    pub fn wipe(self: *RawPrivateKey) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

/// Serializa uma Chave Pública em formato PEM.
pub fn encodePublicKeyPem(key: RawPublicKey, out_buf: []u8) ![]const u8 {
    var raw: [PUB_RAW_LEN]u8 = undefined;
    std.mem.writeInt(u2048, raw[0..256], key.n, .big);
    std.mem.writeInt(u64, raw[256..264], key.e, .big);

    var b64_buf: [PUB_B64_LEN]u8 = undefined;
    const b64 = std.base64.standard.Encoder.encode(&b64_buf, &raw);

    return std.fmt.bufPrint(out_buf, "{s}\n{s}\n{s}\n", .{ PUB_HEADER, b64, PUB_FOOTER });
}

/// Desserializa uma Chave Pública a partir de texto PEM ou Base64.
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

/// Serializa uma Chave Privada completa (com CRT) em formato PEM.
pub fn encodePrivateKeyPem(key: RawPrivateKey, out_buf: []u8) ![]const u8 {
    var raw: [PRIV_RAW_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw);

    std.mem.writeInt(u2048, raw[0..256], key.n, .big);
    std.mem.writeInt(u2048, raw[256..512], key.d, .big);
    std.mem.writeInt(u1024, raw[512..640], key.p, .big);
    std.mem.writeInt(u1024, raw[640..768], key.q, .big);
    std.mem.writeInt(u1024, raw[768..896], key.dp, .big);
    std.mem.writeInt(u1024, raw[896..1024], key.dq, .big);
    std.mem.writeInt(u1024, raw[1024..1152], key.q_inv, .big);

    var b64_buf: [PRIV_B64_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &b64_buf);
    const b64 = std.base64.standard.Encoder.encode(&b64_buf, &raw);

    return std.fmt.bufPrint(out_buf, "{s}\n{s}\n{s}\n", .{ PRIV_HEADER, b64, PRIV_FOOTER });
}

/// Desserializa uma Chave Privada a partir de texto PEM.
pub fn decodePrivateKeyPem(input: []const u8) CodecError!RawPrivateKey {
    var clean_buf: [PRIV_B64_LEN + 64]u8 = undefined;
    defer std.crypto.secureZero(u8, &clean_buf);

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

// ----------------------------------------------------------------------------
// Funções de conversão Hexadecimal na Stack
// ----------------------------------------------------------------------------

const HEX_CHARS = "0123456789abcdef";

/// Codifica bytes em formato hexadecimal minúsculo no buffer `out_hex`.
/// Requer `out_hex.len >= bytes.len * 2`.
pub fn encodeHex(bytes: []const u8, out_hex: []u8) CodecError![]const u8 {
    if (out_hex.len < bytes.len * 2) return CodecError.BufferTooSmall;
    for (bytes, 0..) |b, i| {
        out_hex[i * 2] = HEX_CHARS[b >> 4];
        out_hex[i * 2 + 1] = HEX_CHARS[b & 0x0F];
    }
    return out_hex[0 .. bytes.len * 2];
}

/// Decodifica uma sequência hexadecimal (com ou sem prefixo "0x") para `out_bytes`.
pub fn decodeHex(hex_str: []const u8, out_bytes: []u8) CodecError![]const u8 {
    var clean = std.mem.trim(u8, hex_str, " \t\r\n");
    if (std.mem.startsWith(u8, clean, "0x") or std.mem.startsWith(u8, clean, "0X")) {
        clean = clean[2..];
    }
    if (clean.len % 2 != 0) return CodecError.InvalidLength;
    const byte_count = clean.len / 2;
    if (out_bytes.len < byte_count) return CodecError.BufferTooSmall;

    for (0..byte_count) |i| {
        const h1 = hexVal(clean[i * 2]) orelse return CodecError.InvalidHex;
        const h0 = hexVal(clean[i * 2 + 1]) orelse return CodecError.InvalidHex;
        out_bytes[i] = (h1 << 4) | h0;
    }
    return out_bytes[0..byte_count];
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Extrai a carga útil Base64 removendo delimitadores PEM opcionais e caracteres de espaço.
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
// TESTES UNITÁRIOS — ETAPA 3 (CODEC)
// ============================================================================

const testing = std.testing;

test "Etapa 3.5: Serialização e Desserialização de Chave Pública PEM" {
    const pub_orig = RawPublicKey{
        .n = (@as(u2048, 0xDEADBEEF) << 2000) | 0xCAFEBABE,
        .e = 65537,
    };

    var pem_buf: [512]u8 = undefined;
    const pem_str = try encodePublicKeyPem(pub_orig, &pem_buf);

    try testing.expect(std.mem.startsWith(u8, pem_str, PUB_HEADER));
    try testing.expect(std.mem.endsWith(u8, std.mem.trimEnd(u8, pem_str, "\n"), PUB_FOOTER));

    const pub_dec = try decodePublicKeyPem(pem_str);
    try testing.expectEqual(pub_orig.n, pub_dec.n);
    try testing.expectEqual(pub_orig.e, pub_dec.e);
}

test "Etapa 3.6: Serialização e Desserialização de Chave Privada CRT e Cifra" {
    var priv_orig = RawPrivateKey{
        .n = (@as(u2048, 1) << 2047) + 12345,
        .d = (@as(u2048, 1) << 2040) + 67890,
        .p = (@as(u1024, 1) << 1023) + 111,
        .q = (@as(u1024, 1) << 1023) + 222,
        .dp = 333,
        .dq = 444,
        .q_inv = 555,
    };
    defer priv_orig.wipe();

    var pem_buf: [2048]u8 = undefined;
    defer std.crypto.secureZero(u8, &pem_buf);
    const pem_str = try encodePrivateKeyPem(priv_orig, &pem_buf);

    try testing.expect(std.mem.startsWith(u8, pem_str, PRIV_HEADER));
    try testing.expect(std.mem.endsWith(u8, std.mem.trimEnd(u8, pem_str, "\n"), PRIV_FOOTER));

    var priv_dec = try decodePrivateKeyPem(pem_str);
    defer priv_dec.wipe();

    try testing.expectEqual(priv_orig.n, priv_dec.n);
    try testing.expectEqual(priv_orig.d, priv_dec.d);
    try testing.expectEqual(priv_orig.p, priv_dec.p);
    try testing.expectEqual(priv_orig.q, priv_dec.q);
    try testing.expectEqual(priv_orig.dp, priv_dec.dp);
    try testing.expectEqual(priv_orig.dq, priv_dec.dq);
    try testing.expectEqual(priv_orig.q_inv, priv_dec.q_inv);

    // Teste de cifra em Base64
    var c_buf: [CIPHER_B64_LEN]u8 = undefined;
    const c_b64 = encodeCiphertextBase64(priv_orig.n, &c_buf);
    const c_dec = try decodeCiphertextBase64(c_b64);
    try testing.expectEqual(priv_orig.n, c_dec);
}

test "Etapa 3.7: Codificação e Decodificação Hexadecimal" {
    const raw = [_]u8{ 0x00, 0x12, 0x34, 0xAB, 0xCD, 0xEF };
    var hex_buf: [12]u8 = undefined;
    const hex = try encodeHex(&raw, &hex_buf);
    try testing.expectEqualStrings("001234abcdef", hex);

    var dec_buf: [6]u8 = undefined;
    const dec = try decodeHex(hex, &dec_buf);
    try testing.expectEqualSlices(u8, &raw, dec);

    // Teste com prefixo 0x e maiúsculas
    const dec_prefix = try decodeHex("0x001234ABCDEF", &dec_buf);
    try testing.expectEqualSlices(u8, &raw, dec_prefix);

    // Rejeição de hex inválido ou comprimento ímpar
    try testing.expectError(CodecError.InvalidHex, decodeHex("00123G", &dec_buf));
    try testing.expectError(CodecError.InvalidLength, decodeHex("00123", &dec_buf));
}

//! ============================================================================
//! root.zig — Exportador Central do Núcleo Matemático e Suíte de Integração
//! ============================================================================
//!
//! Este arquivo unifica todos os componentes matemáticos do RSA-2048:
//!   - euclid: MDC, MMC, Algoritmo de Euclides Estendido (modInverse com i4096)
//!   - prime:  Crivo de 256 primos + Miller-Rabin de 64 rodadas (std.crypto.ff.Modulus(1024))
//!   - padding: OAEP-SHA256 (MGF1) e PKCS#1 v1.5
//!   - codec:  Serialização PEM (Base64), Cifras Base64 e Utilitários Hex
//!   - rsa:    Geração de Chaves, Criptografia e Descriptografia via CRT (Garner)
//!
//! Todo o diretório `src/core/` opera com ZERO ALOCAÇÃO DINÂMICA (stack-only),
//! garantindo execução segura em sistemas embarcados e alvos WebAssembly freestanding.
//! ============================================================================

const std = @import("std");

pub const euclid = @import("euclid.zig");
pub const prime = @import("prime.zig");
pub const padding = @import("padding.zig");
pub const codec = @import("codec.zig");
pub const rsa = @import("rsa.zig");

test {
    // Referencia recursivamente todas as declarações e testes dos submódulos
    // para que `zig test src/core/root.zig` execute a suíte matemática completa.
    std.testing.refAllDecls(@This());
}

test "Etapa 4.3: Teste de Integração Ponta a Ponta (Keygen -> PEM -> Encrypt -> Base64 -> Decrypt CRT)" {
    var prng = std.Random.DefaultPrng.init(777);
    const rand = prng.random();

    // 1. Gera o par de chaves RSA-2048 completo
    var kp = try rsa.KeyPair.generateWithRounds(rand, 16);
    defer kp.wipe();

    // 2. Serializa as chaves pública e privada para PEM em buffers na stack
    var pub_pem_buf: [512]u8 = undefined;
    var priv_pem_buf: [2048]u8 = undefined;
    defer std.crypto.secureZero(u8, &priv_pem_buf);

    const pub_pem = try codec.encodePublicKeyPem(kp.public_key, &pub_pem_buf);
    const priv_pem = try codec.encodePrivateKeyPem(kp.private_key, &priv_pem_buf);

    // 3. Desserializa as chaves simulando carregamento a partir de arquivo ou rede
    const loaded_pub = try codec.decodePublicKeyPem(pub_pem);
    var loaded_priv = try codec.decodePrivateKeyPem(priv_pem);
    defer loaded_priv.wipe();

    // 4. Cifra uma mensagem confidencial com padding OAEP-SHA256
    const secret = "Integracao completa em stack: PEM + OAEP + Montgomery + CRT!";
    const ciphertext = try rsa.encryptOaep(loaded_pub, secret, rand);

    // 5. Converte o texto cifrado para Base64 (formato de transporte)
    var c_b64_buf: [codec.CIPHER_B64_LEN]u8 = undefined;
    const c_b64 = codec.encodeCiphertextBase64(ciphertext, &c_b64_buf);

    // 6. Decodifica o Base64 e descriptografa usando o Teorema Chinês dos Restos (CRT)
    const decoded_ciphertext = try codec.decodeCiphertextBase64(c_b64);
    var plain_buf: [padding.OAEP_MAX_MSG_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain_buf);

    const plain = try rsa.decryptOaep(loaded_priv, decoded_ciphertext, &plain_buf);
    try std.testing.expectEqualStrings(secret, plain);
}

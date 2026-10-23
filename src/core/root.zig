const std = @import("std");

pub const euclid = @import("euclid.zig");
pub const prime = @import("prime.zig");
pub const padding = @import("padding.zig");
pub const codec = @import("codec.zig");
pub const rsa = @import("rsa.zig");

test {
    // Referencia todos os submódulos para que `zig test src/core/root.zig`
    // execute a suíte completa das Etapas 1, 2, 3 e 4 de uma só vez.
    std.testing.refAllDecls(@This());
}

test "Etapa 4.2: Teste de Integração Ponta a Ponta (Keygen -> PEM -> Encrypt -> Base64 -> Decrypt)" {
    var prng = std.Random.DefaultPrng.init(777);
    const rand = prng.random();

    // 1. Gera o par de chaves
    var kp = try rsa.KeyPair.generateWithRounds(rand, 16);
    defer kp.wipe();

    // 2. Serializa chaves para PEM em buffers na stack
    var pub_pem_buf: [512]u8 = undefined;
    var priv_pem_buf: [2048]u8 = undefined;
    const pub_pem = try codec.encodePublicKeyPem(kp.public_key, &pub_pem_buf);
    const priv_pem = try codec.encodePrivateKeyPem(kp.private_key, &priv_pem_buf);

    // 3. Desserializa as chaves como se tivessem sido lidas do disco
    const loaded_pub = try codec.decodePublicKeyPem(pub_pem);
    const loaded_priv = try codec.decodePrivateKeyPem(priv_pem);

    // 4. Cifra uma mensagem e converte o resultado para Base64
    const secret = "Integracao completa em stack: PEM + OAEP + Montgomery + CRT!";
    const ciphertext = try rsa.encryptOaep(loaded_pub, secret, rand);

    var c_b64_buf: [codec.CIPHER_B64_LEN]u8 = undefined;
    const c_b64 = codec.encodeCiphertextBase64(ciphertext, &c_b64_buf);

    // 5. Decodifica o Base64 e decifra via CRT
    const decoded_ciphertext = try codec.decodeCiphertextBase64(c_b64);
    var plain_buf: [padding.OAEP_MAX_MSG_LEN]u8 = undefined;
    const plain = try rsa.decryptOaep(loaded_priv, decoded_ciphertext, &plain_buf);

    try std.testing.expectEqualStrings(secret, plain);
}

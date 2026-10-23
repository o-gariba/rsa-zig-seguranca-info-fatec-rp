const std = @import("std");
const core = @import("core/root.zig");

/// Buffers estáticos globais na memória linear do WebAssembly para comunicação zero-copy com o JS.
var seed_buf: [64]u8 = @splat(0);
var pub_pem_buf: [512]u8 = @splat(0);
var priv_pem_buf: [2048]u8 = @splat(0);
var msg_buf: [256]u8 = @splat(0);
var cipher_b64_buf: [core.codec.CIPHER_B64_LEN]u8 = @splat(0);
var inspect_json_buf: [4096]u8 = @splat(0);

var pub_pem_len: usize = 0;
var priv_pem_len: usize = 0;
var msg_len: usize = 0;
var inspect_json_len: usize = 0;

export fn wasm_get_seed_ptr() [*]u8 {
    return &seed_buf;
}
export fn wasm_get_pub_ptr() [*]u8 {
    return &pub_pem_buf;
}
export fn wasm_get_pub_len() usize {
    return pub_pem_len;
}
export fn wasm_get_priv_ptr() [*]u8 {
    return &priv_pem_buf;
}
export fn wasm_get_priv_len() usize {
    return priv_pem_len;
}
export fn wasm_get_msg_ptr() [*]u8 {
    return &msg_buf;
}
export fn wasm_get_msg_len() usize {
    return msg_len;
}
export fn wasm_get_cipher_ptr() [*]u8 {
    return &cipher_b64_buf;
}
export fn wasm_get_cipher_len() usize {
    return core.codec.CIPHER_B64_LEN;
}
export fn wasm_get_inspect_ptr() [*]const u8 {
    return &inspect_json_buf;
}
export fn wasm_get_inspect_len() usize {
    return inspect_json_len;
}

/// Inicializa um CSPRNG determinístico ChaCha20 no Wasm semeado pelos 32 bytes
/// fornecidos por `window.crypto.getRandomValues` no navegador.
fn initCsprngFromBrowserSeed() std.Random.DefaultCsprng {
    var seed32: [32]u8 = undefined;
    @memcpy(&seed32, seed_buf[0..32]);
    return std.Random.DefaultCsprng.init(seed32);
}

/// Gera par de chaves RSA-2048 no navegador e preenche pub_pem_buf, priv_pem_buf e inspect_json_buf.
/// Retorna 0 em sucesso, ou código de erro > 0.
export fn wasm_keygen(rounds: usize) u32 {
    var csprng = initCsprngFromBrowserSeed();
    const rand = csprng.random();

    const actual_rounds = if (rounds == 0) 32 else rounds;
    var kp = core.rsa.KeyPair.generateWithRounds(rand, actual_rounds) catch return 1;
    defer kp.wipe();

    const pub_slice = core.codec.encodePublicKeyPem(kp.public_key, &pub_pem_buf) catch return 2;
    pub_pem_len = pub_slice.len;

    const priv_slice = core.codec.encodePrivateKeyPem(kp.private_key, &priv_pem_buf) catch return 3;
    priv_pem_len = priv_slice.len;

    const json_slice = std.fmt.bufPrint(
        &inspect_json_buf,
        "{{\"e\":\"{d}\",\"p\":\"0x{X}\",\"q\":\"0x{X}\",\"n\":\"0x{X}\",\"d\":\"0x{X}\",\"dp\":\"0x{X}\",\"dq\":\"0x{X}\",\"q_inv\":\"0x{X}\"}}",
        .{
            kp.public_key.e,
            kp.private_key.p,
            kp.private_key.q,
            kp.public_key.n,
            kp.private_key.d,
            kp.private_key.dp,
            kp.private_key.dq,
            kp.private_key.q_inv,
        },
    ) catch return 4;
    inspect_json_len = json_slice.len;

    return 0;
}

/// Criptografa a mensagem em `msg_buf[0..in_msg_len]` usando a chave pública em `pub_pem_buf[0..in_pub_len]`.
/// Escreve o resultado Base64 em `cipher_b64_buf`. Retorna 0 em sucesso.
export fn wasm_encrypt(in_pub_len: usize, in_msg_len: usize) u32 {
    if (in_pub_len > pub_pem_buf.len or in_msg_len > core.padding.OAEP_MAX_MSG_LEN) return 1;

    var csprng = initCsprngFromBrowserSeed();
    const rand = csprng.random();

    const pub_key = core.codec.decodePublicKeyPem(pub_pem_buf[0..in_pub_len]) catch return 2;
    const ciphertext = core.rsa.encryptOaep(pub_key, msg_buf[0..in_msg_len], rand) catch return 3;
    _ = core.codec.encodeCiphertextBase64(ciphertext, &cipher_b64_buf);

    return 0;
}

/// Descriptografa a cifra Base64 em `cipher_b64_buf` usando a chave privada em `priv_pem_buf[0..in_priv_len]`.
/// Escreve o texto plano restaurado em `msg_buf` e atualiza `msg_len`. Retorna 0 em sucesso.
export fn wasm_decrypt(in_priv_len: usize, in_cipher_len: usize) u32 {
    if (in_priv_len > priv_pem_buf.len or in_cipher_len != core.codec.CIPHER_B64_LEN) return 1;

    var priv_key = core.codec.decodePrivateKeyPem(priv_pem_buf[0..in_priv_len]) catch return 2;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&priv_key));

    const ciphertext = core.codec.decodeCiphertextBase64(cipher_b64_buf[0..in_cipher_len]) catch return 3;

    var out_plain: [core.padding.OAEP_MAX_MSG_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &out_plain);

    const plain = core.rsa.decryptOaep(priv_key, ciphertext, &out_plain) catch return 4;
    @memcpy(msg_buf[0..plain.len], plain);
    msg_len = plain.len;

    return 0;
}

//! ============================================================================
//! main_cli.zig — Ponto de Entrada da Interface de Linha de Comando (CLI)
//! ============================================================================
//!
//! Fornece comandos compatíveis com pipes POSIX, sem alocação dinâmica no
//! núcleo de processamento criptográfico:
//!
//!   1. `rsa-cli keygen [--pub <arq>] [--priv <arq>] [--inspect]`
//!   2. `rsa-cli encrypt --pub <arq> [--in <arq>] [--out <arq>] [--inspect]`
//!   3. `rsa-cli decrypt --priv <arq> [--in <arq>] [--out <arq>] [--inspect]`
//!
//! Com `--inspect`, detalhes matemáticos e comparativos de desempenho
//! são impressos exclusivamente em `stderr`, preservando o fluxo de `stdout`.
//! ============================================================================

const std = @import("std");
const core = @import("core/root.zig");

const USAGE =
    \\Uso:
    \\  rsa-cli keygen [--pub <arq>] [--priv <arq>] [--inspect]
    \\  rsa-cli encrypt --pub <arq> [--in <arq>] [--out <arq>] [--inspect]
    \\  rsa-cli decrypt --priv <arq> [--in <arq>] [--out <arq>] [--inspect]
    \\
    \\Exemplos com pipes POSIX:
    \\  rsa-cli keygen --pub id_rsa.pub --priv id_rsa.key --inspect
    \\  echo "Mensagem secreta" | rsa-cli encrypt --pub id_rsa.pub > msg.enc
    \\  rsa-cli decrypt --priv id_rsa.key < msg.enc
    \\
;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    if (args.len < 2) {
        printStderr(io, "{s}", .{USAGE});
        std.process.exit(1);
    }

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "keygen")) {
        try runKeygen(io, args[2..]);
    } else if (std.mem.eql(u8, cmd, "encrypt")) {
        try runEncrypt(io, args[2..]);
    } else if (std.mem.eql(u8, cmd, "decrypt")) {
        try runDecrypt(io, args[2..]);
    } else if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        printStderr(io, "{s}", .{USAGE});
    } else {
        printStderr(io, "Comando desconhecido: '{s}'\n\n{s}", .{ cmd, USAGE });
        std.process.exit(1);
    }
}

fn printStderr(io: std.Io, comptime fmt: []const u8, args: anytype) void {
    var stderr = std.Io.File.stderr();
    var p_buf: [4096]u8 = undefined;
    var w = stderr.writer(io, &p_buf);
    w.interface.print(fmt, args) catch {};
    w.flush() catch {};
}

fn readInput(io: std.Io, in_path: ?[]const u8, buf: []u8) ![]u8 {
    if (in_path) |path| {
        return try std.Io.Dir.cwd().readFile(io, path, buf);
    } else {
        var stdin = std.Io.File.stdin();
        var r_buf: [1024]u8 = undefined;
        var r = stdin.readerStreaming(io, &r_buf);
        var total: usize = 0;
        while (total < buf.len) {
            const n = r.interface.readSliceShort(buf[total..]) catch |err| switch (err) {
                error.ReadFailed => return r.err.?,
            };
            if (n == 0) break;
            total += n;
        }
        return buf[0..total];
    }
}

fn writeOutput(io: std.Io, out_path: ?[]const u8, data: []const u8) !void {
    if (out_path) |path| {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
    } else {
        var stdout = std.Io.File.stdout();
        try stdout.writeStreamingAll(io, data);
    }
}

fn runKeygen(io: std.Io, args: []const [:0]const u8) !void {
    var pub_path: []const u8 = "id_rsa.pub";
    var priv_path: []const u8 = "id_rsa.key";
    var inspect = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--pub") and i + 1 < args.len) {
            pub_path = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--priv") and i + 1 < args.len) {
            priv_path = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--inspect")) {
            inspect = true;
        }
    }

    printStderr(io, "[*] Gerando par de chaves RSA-2048 (64 rodadas Miller-Rabin)...\n", .{});

    var io_source = std.Random.IoSource{ .io = io };
    const rand = io_source.interface();

    const start = std.Io.Timestamp.now(io, .awake);
    var kp = try core.rsa.KeyPair.generate(rand);
    defer kp.wipe();

    const elapsed_ms = start.untilNow(io, .awake).toMilliseconds();

    var pub_pem_buf: [512]u8 = undefined;
    var priv_pem_buf: [2048]u8 = undefined;
    defer std.crypto.secureZero(u8, &priv_pem_buf);

    const pub_pem = try core.codec.encodePublicKeyPem(kp.public_key, &pub_pem_buf);
    const priv_pem = try core.codec.encodePrivateKeyPem(kp.private_key, &priv_pem_buf);

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = pub_path, .data = pub_pem });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = priv_path, .data = priv_pem });

    printStderr(io, "[+] Chaves geradas com sucesso em '{s}' e '{s}' ({d} ms).\n", .{ pub_path, priv_path, elapsed_ms });

    if (inspect) {
        printStderr(
            io,
            \\
            \\=== INSPEÇÃO MATEMÁTICA (RSA-2048 / CRT) ===
            \\  e (Expoente Público) : {d} (0x{X})
            \\  p (Primo 1024-bit)   : 0x{X}
            \\  q (Primo 1024-bit)   : 0x{X}
            \\  n = p * q (2048-bit) : 0x{X}
            \\  d = e^-1 mod λ(n)    : 0x{X}
            \\  dp = d mod (p - 1)   : 0x{X}
            \\  dq = d mod (q - 1)   : 0x{X}
            \\  q_inv = q^-1 mod p   : 0x{X}
            \\============================================
            \\
        , .{
            kp.public_key.e,
            kp.public_key.e,
            kp.private_key.p,
            kp.private_key.q,
            kp.public_key.n,
            kp.private_key.d,
            kp.private_key.dp,
            kp.private_key.dq,
            kp.private_key.q_inv,
        });
    }
}

fn runEncrypt(io: std.Io, args: []const [:0]const u8) !void {
    var pub_path: ?[]const u8 = null;
    var in_path: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;
    var inspect = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--pub") and i + 1 < args.len) {
            pub_path = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--in") and i + 1 < args.len) {
            in_path = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--out") and i + 1 < args.len) {
            out_path = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--inspect")) {
            inspect = true;
        }
    }

    const p_path = pub_path orelse {
        printStderr(io, "Erro: informe --pub <arquivo_chave_publica>\n", .{});
        std.process.exit(1);
    };

    var pub_buf: [1024]u8 = undefined;
    const pub_pem = try std.Io.Dir.cwd().readFile(io, p_path, &pub_buf);
    const pub_key = try core.codec.decodePublicKeyPem(pub_pem);

    var msg_buf: [512]u8 = undefined;
    const msg = try readInput(io, in_path, &msg_buf);

    if (msg.len > core.padding.OAEP_MAX_MSG_LEN) {
        printStderr(io, "Erro: mensagem excede o limite de {d} bytes do OAEP-SHA256.\n", .{core.padding.OAEP_MAX_MSG_LEN});
        std.process.exit(1);
    }

    var io_source = std.Random.IoSource{ .io = io };
    const rand = io_source.interface();

    const start = std.Io.Timestamp.now(io, .awake);
    const ciphertext = try core.rsa.encryptOaep(pub_key, msg, rand);
    const elapsed_us = start.untilNow(io, .awake).toMicroseconds();

    var b64_buf: [core.codec.CIPHER_B64_LEN]u8 = undefined;
    const b64_cipher = core.codec.encodeCiphertextBase64(ciphertext, &b64_buf);

    var formatted_cipher: [core.codec.CIPHER_B64_LEN + 1]u8 = undefined;
    @memcpy(formatted_cipher[0..b64_cipher.len], b64_cipher);
    formatted_cipher[b64_cipher.len] = '\n';

    try writeOutput(io, out_path, &formatted_cipher);

    if (inspect) {
        printStderr(
            io,
            \\
            \\=== INSPEÇÃO DE CRIPTOGRAFIA (OAEP-SHA256 + RSAEP) ===
            \\  Tamanho da mensagem : {d} bytes
            \\  Tempo de cifragem   : {d} μs
            \\  Texto cifrado (Hex) : 0x{X}
            \\=======================================================
            \\
        , .{
            msg.len,
            elapsed_us,
            ciphertext,
        });
    }
}

fn runDecrypt(io: std.Io, args: []const [:0]const u8) !void {
    var priv_path: ?[]const u8 = null;
    var in_path: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;
    var inspect = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--priv") and i + 1 < args.len) {
            priv_path = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--in") and i + 1 < args.len) {
            in_path = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--out") and i + 1 < args.len) {
            out_path = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--inspect")) {
            inspect = true;
        }
    }

    const k_path = priv_path orelse {
        printStderr(io, "Erro: informe --priv <arquivo_chave_privada>\n", .{});
        std.process.exit(1);
    };

    var priv_buf: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &priv_buf);
    const priv_pem = try std.Io.Dir.cwd().readFile(io, k_path, &priv_buf);
    var priv_key = try core.codec.decodePrivateKeyPem(priv_pem);
    defer priv_key.wipe();

    var cipher_buf: [1024]u8 = undefined;
    const cipher_slice = try readInput(io, in_path, &cipher_buf);

    const ciphertext = try core.codec.decodeCiphertextBase64(cipher_slice);

    var out_plain: [core.padding.OAEP_MAX_MSG_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &out_plain);

    const crt_start = std.Io.Timestamp.now(io, .awake);
    const plain = try core.rsa.decryptOaep(priv_key, ciphertext, &out_plain);
    const crt_us = crt_start.untilNow(io, .awake).toMicroseconds();

    if (inspect) {
        const direct_start = std.Io.Timestamp.now(io, .awake);
        _ = try core.rsa.decryptRawDirect(priv_key, ciphertext);
        const direct_us = direct_start.untilNow(io, .awake).toMicroseconds();

        printStderr(
            io,
            \\
            \\=== COMPARAÇÃO CRT vs EXPONENCIAÇÃO DIRETA ===
            \\  Tempo CRT (Algoritmo de Garner) : {d} μs
            \\  Tempo Direto (c^d mod n)       : {d} μs
            \\  Aceleração observada            : {d:.2}x mais rápido
            \\==============================================
            \\
        , .{
            crt_us,
            direct_us,
            if (crt_us > 0) @as(f64, @floatFromInt(direct_us)) / @as(f64, @floatFromInt(crt_us)) else 0.0,
        });
    }

    try writeOutput(io, out_path, plain);
}

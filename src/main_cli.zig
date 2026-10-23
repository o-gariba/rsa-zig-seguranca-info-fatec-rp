const std = @import("std");
const core = @import("core/root.zig");

const USAGE =
    \\Uso:
    \\  rsa-cli keygen [--pub <arq>] [--priv <arq>] [--inspect]
    \\  rsa-cli encrypt --pub <arq> [--in <arq>] [--out <arq>]
    \\  rsa-cli decrypt --priv <arq> [--in <arq>] [--out <arq>] [--inspect]
    \\
    \\Exemplos com pipes POSIX:
    \\  rsa-cli keygen --pub id_rsa.pub --priv id_rsa.key --inspect
    \\  echo "Mensagem secreta" | rsa-cli encrypt --pub id_rsa.pub > msg.enc
    \\  rsa-cli decrypt --priv id_rsa.key < msg.enc
    \\
;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    if (args.len < 2) {
        std.debug.print("{s}", .{USAGE});
        std.process.exit(1);
    }

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "keygen")) {
        try runKeygen(init.io, args[2..]);
    } else if (std.mem.eql(u8, cmd, "encrypt")) {
        try runEncrypt(init.io, args[2..]);
    } else if (std.mem.eql(u8, cmd, "decrypt")) {
        try runDecrypt(args[2..]);
    } else {
        std.debug.print("{s}", .{USAGE});
        std.process.exit(1);
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

    std.debug.print("[*] Gerando par de chaves RSA-2048 (64 rodadas Miller-Rabin)...\n", .{});

    const start = std.Io.Clock.now(.awake, io);
    var kp = try core.rsa.KeyPair.generate(std.crypto.random);
    defer kp.wipe();

    const elapsed_ms = start
    .durationTo(std.Io.Clock.now(.awake, io))
    .toMilliseconds();


    var pub_pem_buf: [512]u8 = undefined;
    var priv_pem_buf: [2048]u8 = undefined;
    defer std.crypto.secureZero(u8, &priv_pem_buf);

    const pub_pem = try core.codec.encodePublicKeyPem(kp.public_key, &pub_pem_buf);
    const priv_pem = try core.codec.encodePrivateKeyPem(kp.private_key, &priv_pem_buf);

    try std.fs.cwd().writeFile(.{ .sub_path = pub_path, .data = pub_pem });
    try std.fs.cwd().writeFile(.{ .sub_path = priv_path, .data = priv_pem });

    std.debug.print("[+] Chaves salvas em '{s}' e '{s}' ({d} ms).\n", .{ pub_path, priv_path, elapsed_ms });

    if (inspect) {
        std.debug.print(
            \\
            \\=== INSPECÃO MATEMÁTICA (RSA-2048 / CRT) ===
            \\  e (Expoente Público) : {d} (0x{X})
            \\  p (Primo 1024-bit)   : 0x{X}
            \\  q (Primo 1024-bit)   : 0x{X}
            \\  n = p * q (2048-bit) : 0x{X}
            \\  d = e^-1 mod lambda  : 0x{X}
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

fn runEncrypt(args: []const [:0]const u8) !void {
    var pub_path: ?[]const u8 = null;
    var in_path: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;

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
        }
    }

    const p_path = pub_path orelse {
        std.debug.print("Erro: informe --pub <arquivo_chave_publica>\n");
        std.process.exit(1);
    };

    var pub_buf: [1024]u8 = undefined;
    const pub_pem = try std.fs.cwd().readFile(p_path, &pub_buf);
    const pub_key = try core.codec.decodePublicKeyPem(pub_pem);

    var msg_buf: [512]u8 = undefined;
    const msg_len = if (in_path) |ip|
        (try std.fs.cwd().readFile(ip, &msg_buf)).len
    else
        try std.io.getStdIn().readAll(&msg_buf);

    const msg = msg_buf[0..msg_len];
    if (msg.len > core.padding.OAEP_MAX_MSG_LEN) {
	std.debug.print("Erro: mensagem excede o limite de {d} bytes do OAEP-SHA256.\n", .{core.padding.OAEP_MAX_MSG_LEN});
        std.process.exit(1);
    }

    const ciphertext = try core.rsa.encryptOaep(pub_key, msg, std.crypto.random);

    var b64_buf: [core.codec.CIPHER_B64_LEN]u8 = undefined;
    const b64_cipher = core.codec.encodeCiphertextBase64(ciphertext, &b64_buf);

    if (out_path) |op| {
        try std.fs.cwd().writeFile(.{ .sub_path = op, .data = b64_cipher });
    } else {
        const stdout = std.io.getStdOut().writer();
        try stdout.print("{s}\n", .{b64_cipher});
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
	std.debug.print("Erro: informe --priv <arquivo_chave_privada>\n");
        std.process.exit(1);
    };

    var priv_buf: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &priv_buf);
    const priv_pem = try std.fs.cwd().readFile(k_path, &priv_buf);
    var priv_key = try core.codec.decodePrivateKeyPem(priv_pem);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&priv_key));

    var cipher_buf: [1024]u8 = undefined;
    const cipher_len = if (in_path) |ip|
        (try std.fs.cwd().readFile(ip, &cipher_buf)).len
    else
        try std.io.getStdIn().readAll(&cipher_buf);

    const ciphertext = try core.codec.decodeCiphertextBase64(cipher_buf[0..cipher_len]);

    const crt_start = std.Io.Clock.now(.awake, io);
    const plain = try core.rsa.decryptOaep(priv_key, ciphertext, &out_plain);
    const crt_ns = crt_start
	.durationTo(std.Io.Clock.now(.awake, io))
	.toNanoseconds();

    if (inspect) {
	const direct_start = std.Io.Clock.now(.awake, io);
	_ = try core.rsa.decryptRawDirect(priv_key, ciphertext);
	const direct_ns = direct_start
		.durationTo(std.Io.Clock.now(.awake, io))
		.toNanoseconds();
        std.debug.print(
            "[*] Tempo CRT (Garner): {d} us | Tempo Exponenciacao Direta: {d} us\n",
            .{ crt_ns / 1000, direct_ns / 1000 },
        );
    }

    if (out_path) |op| {
        try std.fs.cwd().writeFile(.{ .sub_path = op, .data = plain });
    } else {
        try std.io.getStdOut().writeAll(plain);
    }
}

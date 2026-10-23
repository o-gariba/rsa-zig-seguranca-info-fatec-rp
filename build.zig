const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 1. Executável CLI Nativo (zig build)
    const cli_exe = b.addExecutable(.{
        .name = "rsa-cli",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main_cli.zig"),
            .target = target,
            .optimize = optimize,
            .strip = optimize != .debug,
        }),
    });
    b.installArtifact(cli_exe);

    // Permite rodar `zig build run -- keygen --inspect`
    const run_cmd = b.addRunArtifact(cli_exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Executa o rsa-cli diretamente");
    run_step.dependOn(&run_cmd.step);

    // 2. Artefato WebAssembly para o GitHub Pages (zig build wasm)
    const wasm_step = b.step("wasm", "Compila o motor RSA para WebAssembly (web/rsa.wasm)");
    const wasm_exe = b.addExecutable(.{
        .name = "rsa",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main_wasm.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .wasm32,
                .os_tag = .freestanding,
            }),
            .optimize = .small,
            .strip = true,
        }),
    });
    wasm_exe.entry = .disabled;
    wasm_exe.rdynamic = true;

    const install_wasm = b.addInstallArtifact(wasm_exe, .{
        .dest_dir = .{ .override = .{ .custom = "../web" } },
    });
    wasm_step.dependOn(&install_wasm.step);

    // 3. Suíte de Testes Unitários Completa (zig build test --summary all)
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Executa a suite completa de 27 testes matematicos do RSA");
    test_step.dependOn(&run_unit_tests.step);

    // Testes por etapa individual
    const test_e1 = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/euclid.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const step_e1 = b.step("test-etapa1", "Etapa 1: Testa GCD, LCM e Euclides Estendido (modInverse)");
    step_e1.dependOn(&b.addRunArtifact(test_e1).step);

    const test_e2 = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/prime.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const step_e2 = b.step("test-etapa2", "Etapa 2: Testa Crivo de 256 Primos e Miller-Rabin");
    step_e2.dependOn(&b.addRunArtifact(test_e2).step);

    const test_e3_pad = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/padding.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const test_e3_cod = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/codec.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const step_e3 = b.step("test-etapa3", "Etapa 3: Testa Padding (OAEP/PKCS1) e Codec (PEM/B64/Hex)");
    step_e3.dependOn(&b.addRunArtifact(test_e3_pad).step);
    step_e3.dependOn(&b.addRunArtifact(test_e3_cod).step);

    const test_e4 = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/rsa.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const step_e4 = b.step("test-etapa4", "Etapa 4: Testa Keygen, RSAEP e RSADP com Teorema Chines dos Restos");
    step_e4.dependOn(&b.addRunArtifact(test_e4).step);
}

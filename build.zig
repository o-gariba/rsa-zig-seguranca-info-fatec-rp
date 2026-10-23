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

    // 3. Suíte de Testes Unitários (zig build test --summary all)
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Executa todos os 16 testes matematicos do RSA");
    test_step.dependOn(&run_unit_tests.step);
}

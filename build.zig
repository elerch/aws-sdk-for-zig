const std = @import("std");
const builtin = @import("builtin");
const Builder = @import("std").Build;

const models_subdir = "codegen/sdk-codegen/aws-models/"; // note will probably not work on windows

// UNCOMMENT AFTER MODEL GEN TO USE IN BUILD SCRIPTS //pub const aws = @import("src/aws.zig");

const test_targets = [_]std.Target.Query{
    .{}, // native
    .{ .cpu_arch = .x86_64, .os_tag = .linux },
    .{ .cpu_arch = .aarch64, .os_tag = .linux },
    .{ .cpu_arch = .riscv64, .os_tag = .linux },
    .{ .cpu_arch = .arm, .os_tag = .linux },
    .{ .cpu_arch = .x86_64, .os_tag = .windows },
    .{ .cpu_arch = .aarch64, .os_tag = .macos },
    .{ .cpu_arch = .x86_64, .os_tag = .macos },
    // .{ .cpu_arch = .wasm32, .os_tag = .wasi },
};

pub fn build(b: *Builder) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const no_llvm = b.option(
        bool,
        "no-llvm",
        "Disable LLVM",
    ) orelse false;
    const broken_windows = b.option(
        bool,
        "broken-windows",
        "Windows is broken in this environment (do not run Windows tests)",
    ) orelse false;
    const no_bin = b.option(bool, "no-bin", "skip emitting binary") orelse false;

    const test_filters: []const []const u8 = b.option(
        []const []const u8,
        "test-filter",
        "Skip tests that do not match any of the specified filters",
    ) orelse &.{};

    const dep_mods = try getDependencyModules(b, .{
        .target = target,
        .optimize = optimize,
    });

    const mod_exe = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    configure(mod_exe, dep_mods, true);

    const exe = b.addExecutable(.{
        .name = "demo",
        .root_module = mod_exe,
        .use_llvm = !no_llvm,
    });

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const cg = b.step("gen", "Generate zig service code from smithy models");

    const cg_mod = b.createModule(.{
        .root_source_file = b.path("codegen/src/main.zig"),
        // We need this generated for the host, not the real target
        .target = b.graph.host,
        .optimize = if (b.verbose) .Debug else .ReleaseSafe,
    });
    configure(cg_mod, dep_mods, false);

    const cg_exe = b.addExecutable(.{
        .name = "codegen",
        .root_module = cg_mod,
    });
    var cg_cmd = b.addRunArtifact(cg_exe);
    cg_cmd.addArg("--models");
    cg_cmd.addArg(try std.fs.path.join(
        b.allocator,
        &[_][]const u8{
            try b.dependency("models", .{}).path("").getPath3(b, null).toString(b.allocator),
            models_subdir,
        },
    ));
    cg_cmd.addArg("--output");
    const cg_output_dir = cg_cmd.addOutputDirectoryArg("src/models");
    if (b.verbose)
        cg_cmd.addArg("--verbose");
    // cg_cmd.step.dependOn(&fetch_step.step);
    // TODO: this should use zig_exe from std.Build
    // codegen should store a hash in a comment
    // this would be hash of the exe that created the file
    // concatenated with hash of input json. this would
    // allow skipping generated files. May not include hash
    // of contents of output file as maybe we want to tweak
    // manually??
    //
    // All the hashes can be in service_manifest.zig, which
    // could be fun to just parse and go nuts. Top of
    // file, generator exe hash. Each import has comment
    // with both input and output hash and we can decide
    // later about warning on manual changes...

    cg.dependOn(&cg_cmd.step);

    exe.step.dependOn(cg);

    // This allows us to have each module depend on the
    // generated service manifest.
    const service_manifest_module = b.createModule(.{
        .root_source_file = cg_output_dir.path(b, "service_manifest.zig"),
        .target = target,
        .optimize = optimize,
    });
    configure(service_manifest_module, dep_mods, true);

    mod_exe.addImport("service_manifest", service_manifest_module);

    // Expose module to others
    const mod_aws = b.addModule("aws", .{
        .root_source_file = b.path("src/aws.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod_aws.addImport("service_manifest", service_manifest_module);
    configure(mod_aws, dep_mods, true);

    // Expose module to others
    const mod_aws_signing = b.addModule("aws-signing", .{
        .root_source_file = b.path("src/aws_signing.zig"),
    });
    configure(mod_aws_signing, dep_mods, false);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");

    // // Creates a step for unit testing. This only builds the test executable
    // // but does not run it.
    // const unit_tests = b.addTest(.{
    //     .root_source_file = .{ .path = "src/aws.zig" },
    //     .target = target,
    //     .optimize = optimize,
    // });
    // unit_tests.root_module.addImport("smithy", smithy_dep.module("smithy"));
    // unit_tests.step.dependOn(gen_step);
    //
    // const run_unit_tests = b.addRunArtifact(unit_tests);
    // run_unit_tests.skip_foreign_checks = true;

    // test_step.dependOn(&run_unit_tests.step);
    for (test_targets) |t| {
        if (broken_windows and t.os_tag == .windows) continue;

        const mod_unit_tests = b.createModule(.{
            .root_source_file = b.path("src/aws.zig"),
            .target = b.resolveTargetQuery(t),
            .optimize = optimize,
        });
        mod_unit_tests.addImport("service_manifest", service_manifest_module);
        configure(mod_unit_tests, dep_mods, true);

        // Creates a step for unit testing. This only builds the test executable
        // but does not run it.
        const unit_tests = b.addTest(.{
            .root_module = mod_unit_tests,
            .filters = test_filters,
        });

        unit_tests.step.dependOn(cg);
        unit_tests.use_llvm = !no_llvm;

        const run_unit_tests = b.addRunArtifact(unit_tests);
        run_unit_tests.skip_foreign_checks = true;

        test_step.dependOn(&run_unit_tests.step);
    }
    const check = b.step("check", "Check compilation errors");
    check.dependOn(&exe.step);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const smoke_test_step = b.step("smoke-test", "Run unit tests");

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const smoke_test = b.addTest(.{
        .root_module = mod_aws,
        .filters = test_filters,
    });
    smoke_test.use_llvm = !no_llvm;
    smoke_test.step.dependOn(cg);

    const run_smoke_test = b.addRunArtifact(smoke_test);

    smoke_test_step.dependOn(&run_smoke_test.step);
    if (no_bin) {
        b.getInstallStep().dependOn(&exe.step);
    } else {
        b.installArtifact(exe);
    }
}

fn configure(compile: *std.Build.Module, modules: std.StringHashMap(*std.Build.Module), include_time: bool) void {
    compile.addImport("smithy", modules.get("smithy").?);
    compile.addImport("date", modules.get("date").?);
    compile.addImport("json", modules.get("json").?);
    if (include_time) compile.addImport("zeit", modules.get("zeit").?);
}

fn getDependencyModules(b: *std.Build, args: anytype) !std.StringHashMap(*std.Build.Module) {
    var result = std.StringHashMap(*std.Build.Module).init(b.allocator);

    // External dependencies
    const dep_smithy = b.dependency("smithy", args);
    const mod_smithy = dep_smithy.module("smithy");
    try result.putNoClobber("smithy", mod_smithy);

    const dep_zeit = b.dependency("zeit", args);
    const mod_zeit = dep_zeit.module("zeit");
    try result.putNoClobber("zeit", mod_zeit);
    // End External dependencies

    // Private modules/dependencies
    const dep_json = b.dependency("json", args);
    const mod_json = dep_json.module("json");
    try result.putNoClobber("json", mod_json);

    const dep_date = b.dependency("date", args);
    const mod_date = dep_date.module("date");
    try result.putNoClobber("date", mod_date);
    // End private modules/dependencies

    return result;
}

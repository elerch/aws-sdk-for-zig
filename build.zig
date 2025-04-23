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

    // TODO: Embed the current git version in the code. We can do this
    // by looking for .git/HEAD (if it exists, follow the ref to /ref/heads/whatevs,
    // grab that commit, and use b.addOptions/exe.addOptions to generate the
    // Options file. See https://github.com/ziglang/zig/issues/14979 for usage
    // example.
    //
    // From there, I'm not sure what the generated file looks like or quite how
    // to use, but that should be easy. It may also give some ideas on the
    // code gen piece itself, though it might be nice to leave as a seperate
    // executable
    // TODO: This executable should not be built when importing as a package.
    // It relies on code gen and is all fouled up when getting imported
    const mod_exe = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "demo",
        .root_module = mod_exe,
        .use_llvm = !no_llvm,
    });

    // External dependencies
    const dep_smithy = b.dependency("smithy", .{
        .target = target,
        .optimize = optimize,
    });
    const mod_smithy = dep_smithy.module("smithy");
    mod_exe.addImport("smithy", mod_smithy); // not sure this should be here...

    const dep_zeit = b.dependency("zeit", .{
        .target = target,
        .optimize = optimize,
    });
    const mod_zeit = dep_zeit.module("zeit");
    mod_exe.addImport("zeit", mod_zeit);
    // End External dependencies

    // Private modules/dependencies
    const mod_json = b.createModule(.{
        .root_source_file = b.path("codegen/src/json.zig"),
        .target = target,
        .optimize = optimize,
    });

    const dep_date = b.dependency("date", .{
        .target = target,
        .optimize = optimize,
    });
    const mod_date = dep_date.module("date");
    mod_exe.addImport("date", mod_date);
    // End private modules/dependencies

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
    cg_mod.addImport("smithy", mod_smithy);
    cg_mod.addImport("date", mod_date);

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
    service_manifest_module.addImport("smithy", mod_smithy);
    service_manifest_module.addImport("date", mod_date);
    service_manifest_module.addImport("json", mod_json);
    service_manifest_module.addImport("zeit", mod_zeit);

    exe.root_module.addImport("service_manifest", service_manifest_module);

    // Expose module to others
    const mod_aws = b.addModule("aws", .{
        .root_source_file = b.path("src/aws.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod_aws.addImport("smithy", mod_smithy);
    mod_aws.addImport("service_manifest", service_manifest_module);
    mod_aws.addImport("date", mod_date);
    mod_aws.addImport("zeit", mod_zeit);

    // Expose module to others
    const mod_aws_signing = b.addModule("aws-signing", .{
        .root_source_file = b.path("src/aws_signing.zig"),
    });
    mod_aws_signing.addImport("date", mod_date);
    mod_aws_signing.addImport("smithy", mod_smithy);

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
        mod_unit_tests.addImport("smithy", mod_smithy);
        mod_unit_tests.addImport("service_manifest", service_manifest_module);
        mod_unit_tests.addImport("date", mod_date);
        mod_unit_tests.addImport("zeit", mod_zeit);

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

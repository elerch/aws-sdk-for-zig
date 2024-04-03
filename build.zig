const std = @import("std");
const builtin = @import("builtin");
const Builder = @import("std").Build;

const models_subdir = "codegen/sdk-codegen/aws-models/"; // note will probably not work on windows

const test_targets = [_]std.zig.CrossTarget{
    .{}, // native
    .{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
    },
    .{
        .cpu_arch = .aarch64,
        .os_tag = .linux,
    },
    // // The test executable just spins forever in LLVM using nominated zig 0.12 March 2024
    // // This is likely a LLVM problem unlikely to be fixed in zig 0.12
    // .{
    //     .cpu_arch = .riscv64,
    //     .os_tag = .linux,
    // },
    .{
        .cpu_arch = .arm,
        .os_tag = .linux,
    },
    .{
        .cpu_arch = .x86_64,
        .os_tag = .windows,
    },
    .{
        .cpu_arch = .aarch64,
        .os_tag = .macos,
    },
    .{
        .cpu_arch = .x86_64,
        .os_tag = .macos,
    },
    // .{
    //     .cpu_arch = .wasm32,
    //     .os_tag = .wasi,
    // },
};

pub fn build(b: *Builder) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const optimize = b.standardOptimizeOption(.{});

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
    const exe = b.addExecutable(.{
        .name = "demo",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    const smithy_dep = b.dependency("smithy", .{
        // These are the arguments to the dependency. It expects a target and optimization level.
        .target = target,
        .optimize = optimize,
    });
    const smithy_module = smithy_dep.module("smithy");
    exe.root_module.addImport("smithy", smithy_module); // not sure this should be here...

    // Expose module to others
    _ = b.addModule("aws", .{
        .root_source_file = .{ .path = "src/aws.zig" },
        .imports = &.{.{ .name = "smithy", .module = smithy_module }},
    });

    // Expose module to others
    _ = b.addModule("aws-signing", .{
        .root_source_file = .{ .path = "src/aws_signing.zig" },
        .imports = &.{.{ .name = "smithy", .module = smithy_module }},
    });
    // TODO: This does not work correctly due to https://github.com/ziglang/zig/issues/16354
    //
    // We are working here with kind of a weird dependency though. So we can do this
    // another way
    //
    // TODO: These target/optimize are not correct, as we need to run the thing
    // const codegen = b.anonymousDependency("codegen/", @import("codegen/build.zig"), .{
    //     .target = target,
    //     .optimize = optimize,
    // });
    // const codegen_cmd = b.addRunArtifact(codegen.artifact("codegen"));
    // exe.step.dependOn(&codegen_cmd.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const gen_step = blk: {
        const cg = b.step("gen", "Generate zig service code from smithy models");

        const cg_exe = b.addExecutable(.{
            .name = "codegen",
            .root_source_file = .{ .path = "codegen/src/main.zig" },
            // We need this generated for the host, not the real target
            .target = b.host,
            .optimize = if (b.verbose) .Debug else .ReleaseSafe,
        });
        cg_exe.root_module.addImport("smithy", smithy_dep.module("smithy"));
        var cg_cmd = b.addRunArtifact(cg_exe);
        cg_cmd.addArg("--models");
        const hash = hash_blk: {
            for (b.available_deps) |dep| {
                const dep_name = dep.@"0";
                const dep_hash = dep.@"1";
                if (std.mem.eql(u8, dep_name, "models"))
                    break :hash_blk dep_hash;
            }
            return error.DependencyNamedModelsNotFoundInBuildZigZon;
        };
        cg_cmd.addArg(try std.fs.path.join(
            b.allocator,
            &[_][]const u8{
                b.graph.global_cache_root.path.?,
                "p",
                hash,
                models_subdir,
            },
        ));
        cg_cmd.addArg("--output");
        cg_cmd.addDirectoryArg(std.Build.LazyPath.relative("src/models"));
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
        break :blk cg;
    };

    exe.step.dependOn(gen_step);

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
        // Creates a step for unit testing. This only builds the test executable
        // but does not run it.
        const unit_tests = b.addTest(.{
            .root_source_file = .{ .path = "src/aws.zig" },
            .target = b.resolveTargetQuery(t),
            .optimize = optimize,
        });
        unit_tests.root_module.addImport("smithy", smithy_dep.module("smithy"));
        unit_tests.step.dependOn(gen_step);

        const run_unit_tests = b.addRunArtifact(unit_tests);
        run_unit_tests.skip_foreign_checks = true;

        test_step.dependOn(&run_unit_tests.step);
    }
    b.installArtifact(exe);
}

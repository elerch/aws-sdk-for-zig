const std = @import("std");
const builtin = @import("builtin");
const Builder = @import("std").build.Builder;
const tst = @import("build_test.zig");

pub fn build(b: *Builder) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const optimize = b.standardOptimizeOption(.{});

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
    exe.addModule("smithy", smithy_dep.module("smithy"));
    // TODO: Smithy needs to be in a different repo
    // https://github.com/ziglang/zig/issues/855
    // exe.addModulePath("smithy", "smithy/src/smithy.zig");

    if (target.getOs().tag != .macos) exe.linkage = .static;

    // Strip is controlled by optimize options
    // exe.strip = b.option(bool, "strip", "strip exe [true]") orelse true;

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // TODO: Demo for testing is kind of terrible. Proper testing
    // var test_step = try tst.addTestStep(b, optimize, exe.packages.items);

    var codegen: ?*std.build.Step = null;
    if (target.getOs().tag == .linux and false) {
        // TODO: Support > linux with RunStep
        // std.build.RunStep.create(null,null).cwd(std.fs.path.resolve(b.build_root, "codegen")).addArgs(...)
        codegen = b.step("gen", "Generate zig service code from smithy models");
        const cg = codegen.?;
        cg.dependOn(&b.addSystemCommand(&.{ "/bin/sh", "-c", "cd codegen && zig build" }).step);

        // This can probably be triggered instead by GitRepoStep cloning the repo
        // with models
        // Since codegen binary is built every time, if it's newer than our
        // service manifest we know it needs to be regenerated. So this step
        // will remove the service manifest if codegen has been touched, thereby
        // triggering the re-gen
        cg.dependOn(&b.addSystemCommand(&.{
            "/bin/sh", "-c",
            \\ [ ! -f src/models/service_manifest.zig ] || \
            \\ [ $(find codegen -type f -newer src/models/service_manifest.zig -print -quit |wc -c) = '0' ] || \
            \\ rm src/models/service_manifest.zig
        }).step);
        cg.dependOn(&b.addSystemCommand(&.{
            "/bin/sh", "-c",
            \\ mkdir -p src/models/ && \
            \\ [ -f src/models/service_manifest.zig ] || \
            \\ ( cd codegen/models && ../codegen *.json && mv *.zig ../../src/models )
        }).step);
        exe.step.dependOn(cg);
    }

    b.installArtifact(exe);
}

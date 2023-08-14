const std = @import("std");
const builtin = @import("builtin");
const Builder = @import("std").build.Builder;

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

    // TODO: Proper testing

    var codegen: ?*std.build.Step = null;
    if (target.getOs().tag == .linux and false) {
        // TODO: Support > linux with RunStep
        // std.build.RunStep.create(null,null).cwd(std.fs.path.resolve(b.build_root, "codegen")).addArgs(...)
        codegen = b.step("gen", "Generate zig service code from smithy models");
        const cg = codegen.?;
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
        //
        // this scheme would permit cross plat codegen and maybe
        // we can have codegen added in a seperate repo,
        // though not sure how necessary that is
        cg.dependOn(&b.addSystemCommand(&.{ "/bin/sh", "-c", "cd codegen && zig build" }).step);

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

const std = @import("std");
const builtin = @import("builtin");
const Builder = @import("std").build.Builder;
const GitRepoStep = @import("GitRepoStep.zig");
const CopyStep = @import("CopyStep.zig");
const tst = @import("build_test.zig");
const VersionStep = @import("VersionStep.zig");

pub fn build(b: *Builder) !void {
    const zfetch_repo = GitRepoStep.create(b, .{
        .url = "https://github.com/truemedian/zfetch",
        // .branch = "0.1.10", // branch also takes tags. Tag 0.1.10 isn't quite new enough
        .sha = "271cab5da4d12c8f08e67aa0cd5268da100e52f1",
    });

    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("demo", "src/main.zig");

    // https://github.com/ziglang/zig/issues/855
    exe.addPackagePath("smithy", "smithy/src/smithy.zig");

    exe.setTarget(target);
    exe.setBuildMode(mode);

    exe.linkage = .static;

    // TODO: Strip doesn't actually fully strip the executable. If we're on
    //       linux we can run strip on the result, probably at the expense
    //       of busting cache logic
    exe.strip = b.option(bool, "strip", "strip exe [true]") orelse true;
    const copy_deps = CopyStep.create(
        b,
        "zfetch_deps.zig",
        "libs/zfetch/deps.zig",
    );
    copy_deps.step.dependOn(&zfetch_repo.step);

    const version = VersionStep.create(b, null);
    exe.step.dependOn(&version.step);
    exe.step.dependOn(&copy_deps.step);

    // This import won't work unless we're already cloned. The way around
    // this is to have a multi-stage build process, but that's a lot of work.
    // Instead, I've copied the addPackage and tweaked it for the build prefix
    // so we'll have to keep that in sync with upstream
    // const zfetch = @import("libs/zfetch/build.zig");
    exe.addPackage(getZfetchPackage(b, "libs/zfetch") catch unreachable);
    exe.addPackagePath("iguanaTLS", "libs/zfetch/libs/iguanaTLS/src/main.zig");

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    var test_step = try tst.addTestStep(b, mode, exe.packages.items);
    test_step.dependOn(&version.step);

    if (target.getOs().tag == .linux) {
        // TODO: Support > linux with RunStep
        // std.build.RunStep.create(null,null).cwd(std.fs.path.resolve(b.build_root, "codegen")).addArgs(...)
        const codegen = b.step("gen", "Generate zig service code from smithy models");
        codegen.dependOn(&b.addSystemCommand(&.{ "/bin/sh", "-c", "cd codegen && zig build" }).step);

        // This can probably be triggered instead by GitRepoStep cloning the repo
        // with models
        // Since codegen binary is built every time, if it's newer than our
        // service manifest we know it needs to be regenerated. So this step
        // will remove the service manifest if codegen has been touched, thereby
        // triggering the re-gen
        codegen.dependOn(&b.addSystemCommand(&.{
            "/bin/sh", "-c",
            \\ [ ! -f src/models/service_manifest.zig ] || \
            \\ [ src/models/service_manifest.zig -nt codegen/codegen ] || \
            \\ rm src/models/service_manifest.zig
        }).step);
        codegen.dependOn(&b.addSystemCommand(&.{
            "/bin/sh", "-c",
            \\ mkdir -p src/models/ && \
            \\ [ -f src/models/service_manifest.zig ] || \
            \\ ( cd codegen/models && ../codegen *.json && mv *.zig ../../src/models )
        }).step);
        b.getInstallStep().dependOn(codegen);
        test_step.dependOn(codegen);
    }

    exe.install();
}

fn getDependency(comptime lib_prefix: []const u8, comptime name: []const u8, comptime root: []const u8) !std.build.Pkg {
    const path = lib_prefix ++ "/libs/" ++ name ++ "/" ++ root;

    // We don't actually care if the dependency has been checked out, as
    // GitRepoStep will handle that for us
    // Make sure that the dependency has been checked out.
    // std.fs.cwd().access(path, .{}) catch |err| switch (err) {
    //     error.FileNotFound => {
    //         std.log.err("zfetch: dependency '{s}' not checked out", .{name});
    //
    //         return err;
    //     },
    //     else => return err,
    // };

    return std.build.Pkg{
        .name = name,
        .path = .{ .path = path },
    };
}

pub fn getZfetchPackage(b: *std.build.Builder, comptime lib_prefix: []const u8) !std.build.Pkg {
    var dependencies = b.allocator.alloc(std.build.Pkg, 4) catch unreachable;

    dependencies[0] = try getDependency(lib_prefix, "iguanaTLS", "src/main.zig");
    dependencies[1] = try getDependency(lib_prefix, "network", "network.zig");
    dependencies[2] = try getDependency(lib_prefix, "uri", "uri.zig");
    dependencies[3] = try getDependency(lib_prefix, "hzzp", "src/main.zig");

    return std.build.Pkg{
        .name = "zfetch",
        .path = .{ .path = lib_prefix ++ "/src/main.zig" },
        .dependencies = dependencies,
    };
}

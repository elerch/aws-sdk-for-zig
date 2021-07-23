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
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("demo", "src/main.zig");

    // https://github.com/ziglang/zig/issues/855
    exe.addPackagePath("smithy", "smithy/src/smithy.zig");

    // This bitfield workaround will end up requiring a bunch of headers that
    // currently mean building in the docker container is the best way to build
    // TODO: Determine if it's a good idea to copy these files out of our
    // docker container to the local fs so we can just build even outside
    // the container. And maybe, just maybe these even get committed to
    // source control?
    exe.addCSourceFile("src/bitfield-workaround.c", &[_][]const u8{"-std=c99"});
    const c_include_dirs = .{
        "./src/",
        "/usr/local/include",
    };
    inline for (c_include_dirs) |dir|
        exe.addIncludeDir(dir);

    const dependent_objects = .{
        "/usr/local/lib64/libs2n.a",
        "/usr/local/lib64/libcrypto.a",
        "/usr/local/lib64/libssl.a",
        "/usr/local/lib64/libaws-c-auth.a",
        "/usr/local/lib64/libaws-c-cal.a",
        "/usr/local/lib64/libaws-c-common.a",
        "/usr/local/lib64/libaws-c-compression.a",
        "/usr/local/lib64/libaws-c-http.a",
        "/usr/local/lib64/libaws-c-io.a",
    };
    inline for (dependent_objects) |obj|
        exe.addObjectFile(obj);

    exe.linkSystemLibrary("c");
    exe.setTarget(target);
    exe.setBuildMode(mode);

    // This line works as of c5d412268
    // Earliest nightly is 05b5e49bc on 2021-06-12
    // https://ziglang.org/builds/zig-linux-x86_64-0.9.0-dev.113+05b5e49bc.tar.xz
    // exe.override_dest_dir = .{ .Custom = ".." };
    exe.override_dest_dir = .{ .custom = ".." };

    // Static linkage flag was nonfunctional until 2b2efa24d0855
    // Did not notice this until 2021-06-28, and that nightly is:
    // https://ziglang.org/builds/zig-linux-x86_64-0.9.0-dev.321+15a030ef3.tar.xz
    exe.linkage = .static;

    // TODO: Strip doesn't actually fully strip the executable. If we're on
    //       linux we can run strip on the result, probably at the expense
    //       of busting cache logic
    const is_strip = b.option(bool, "strip", "strip exe [true]") orelse true;
    exe.strip = is_strip;

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run library tests");
    var build_dir = try std.fs.openDirAbsolute(b.build_root, .{});
    defer build_dir.close();
    var src_dir = try build_dir.openDir("src", .{ .iterate = true });
    defer src_dir.close();
    var iterator = src_dir.iterate();
    while (try iterator.next()) |entry| {
        if (std.mem.endsWith(u8, entry.name, ".zig")) {
            const name = try std.fmt.allocPrint(b.allocator, "src/{s}", .{entry.name});
            defer b.allocator.free(name);
            const t = b.addTest(name);
            t.addPackagePath("smithy", "smithy/src/smithy.zig");
            t.setBuildMode(mode);
            test_step.dependOn(&t.step);
        }
    }

    // TODO: Support > linux
    if (std.builtin.os.tag == .linux) {
        const codegen = b.step("gen", "Generate zig service code from smithy models");
        codegen.dependOn(&b.addSystemCommand(&.{ "/bin/sh", "-c", "cd codegen && zig build" }).step);
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

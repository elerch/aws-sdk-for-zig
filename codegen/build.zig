const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("codegen", "src/main.zig");
    exe.addPackagePath("smithy", "../smithy/src/smithy.zig");
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

    const is_strip = b.option(bool, "strip", "strip exe") orelse true;
    exe.strip = !is_strip;
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run library tests");
    var src_dir = try std.fs.openDirAbsolute(b.build_root, .{});
    defer src_dir.close();
    var iterable = try src_dir.openIterableDir(".", .{});
    defer iterable.close();
    var iterator = iterable.iterate();
    while (try iterator.next()) |entry| {
        if (std.mem.endsWith(u8, entry.name, ".zig") and
            !std.mem.eql(u8, entry.name, "main.zig"))
        {
            const name = try std.fmt.allocPrint(b.allocator, "src/{s}", .{entry.name});
            defer b.allocator.free(name);
            const t = b.addTest(name);
            t.setBuildMode(mode);
            test_step.dependOn(&t.step);
        }
    }
}

// const std = @import("std");
const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("demo", "src/main.zig");

    // TODO: Generate src/models.zig

    exe.addCSourceFile("src/bitfield-workaround.c", &[_][]const u8{"-std=c99"});
    exe.addIncludeDir("./src/");
    exe.addIncludeDir("/usr/local/include");
    exe.addObjectFile("/usr/local/lib64/libs2n.a");
    exe.addObjectFile("/usr/local/lib64/libcrypto.a");
    exe.addObjectFile("/usr/local/lib64/libssl.a");
    exe.addObjectFile("/usr/local/lib64/libaws-c-auth.a");
    exe.addObjectFile("/usr/local/lib64/libaws-c-cal.a");
    exe.addObjectFile("/usr/local/lib64/libaws-c-common.a");
    exe.addObjectFile("/usr/local/lib64/libaws-c-compression.a");
    exe.addObjectFile("/usr/local/lib64/libaws-c-http.a");
    exe.addObjectFile("/usr/local/lib64/libaws-c-io.a");
    exe.linkSystemLibrary("c");
    exe.setTarget(target);
    exe.setBuildMode(mode);

    // This line works as of c5d412268
    // Earliest nightly is 05b5e49bc on 2021-06-12
    // https://ziglang.org/builds/zig-linux-x86_64-0.9.0-dev.113+05b5e49bc.tar.xz
    // exe.override_dest_dir = .{ .Custom = ".." };
    exe.override_dest_dir = .{ .custom = ".." };
    exe.linkage = .static;

    exe.strip = true;
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}

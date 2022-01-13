//! Publish Date: 2022-01-12
//! This file is hosted at ??? and is meant to be copied
//! to projects that use it. Sample usage:
//!
//! const @"test" = @import("build_test.zig");
//! var test_step = try @"test".addTestStep(b, mode, exe.packages.items);
const std = @import("std");

pub fn addTestStep(b: *std.build.Builder, mode: std.builtin.Mode, packages: []std.build.Pkg) !*std.build.Step {
    const test_step = b.step("test", "Run all tests");
    var src_dir = try std.fs.openDirAbsolute(try std.fs.path.resolve(b.allocator, &[_][]const u8{
        b.build_root,
        "src",
    }), .{ .iterate = true });
    defer src_dir.close();
    var iterator = src_dir.iterate();
    while (try iterator.next()) |entry| {
        if (std.mem.endsWith(u8, entry.name, ".zig")) {
            const name = try std.fmt.allocPrint(b.allocator, "src/{s}", .{entry.name});
            defer b.allocator.free(name);
            const t = b.addTest(name);
            for (packages) |package| t.addPackage(package);
            t.setBuildMode(mode);
            test_step.dependOn(&t.step);
        }
    }
    return test_step;
}

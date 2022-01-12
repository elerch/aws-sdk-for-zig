//! Publish Date: 2022-01-12
//! This file is hosted at ??? and is meant to be copied
//! to projects that use it. Sample usage:
//!
//! ??
//! ??

const std = @import("std");
const Step = @This();

step: std.build.Step,
builder: *std.build.Builder,
version_path: []const u8,

// Creates a step that will add the git version info in a file in src/
// so it can be consumed by additional code. If version_path is not specified,
// it will default to "git_version.zig". This should be part of .gitignore
pub fn create(b: *std.build.Builder, version_path: ?[]const u8) *Step {
    var result = b.allocator.create(Step) catch @panic("memory");
    result.* = Step{
        .step = std.build.Step.init(.custom, "create version file", b.allocator, make),
        .builder = b,
        .version_path = std.fs.path.resolve(b.allocator, &[_][]const u8{
            b.build_root,
            "src",
            version_path orelse "git_version.zig",
        }) catch @panic("memory"),
    };
    return result;
}

fn make(step: *std.build.Step) !void {
    const self = @fieldParentPtr(Step, "step", step);
    const file = try std.fs.createFileAbsolute(self.version_path, .{});
    defer file.close();
    try file.writer().print("pub const version = {s};\n", .{"\"to be implemented\""});
}

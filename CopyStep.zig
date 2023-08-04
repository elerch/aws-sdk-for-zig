const std = @import("std");
const CopyStep = @This();

step: std.build.Step,
builder: *std.build.Builder,
from_path: ?[]const u8 = null,
to_path: ?[]const u8 = null,

pub fn create(
    b: *std.build.Builder,
    from_path_relative: []const u8,
    to_path_relative: []const u8,
) *CopyStep {
    var result = b.allocator.create(CopyStep) catch @panic("memory");
    result.* = CopyStep{
        .step = std.build.Step.init(.custom, "copy a file", b.allocator, make),
        .builder = b,
        .from_path = std.fs.path.resolve(b.allocator, &[_][]const u8{
            b.build_root,
            from_path_relative,
        }) catch @panic("memory"),
        .to_path = std.fs.path.resolve(b.allocator, &[_][]const u8{
            b.build_root,
            to_path_relative,
        }) catch @panic("memory"),
    };
    return result;
}

fn make(step: *std.build.Step) !void {
    const self = @fieldParentPtr(CopyStep, "step", step);
    std.fs.copyFileAbsolute(self.from_path.?, self.to_path.?, .{}) catch |e| {
        std.log.err("Error copying {s} to {s}: {}", .{ self.from_path.?, self.to_path.?, e });
        std.os.exit(1);
    };
}

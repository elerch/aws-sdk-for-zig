//! Publish Date: 2022-01-12
//! This file is hosted at ??? and is meant to be copied
//! to projects that use it. Sample usage:
//!
//! const version = VersionStep.create(b, null);
//! exe.step.dependOn(&version.step);

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
    const version = try getGitVersion(
        self.builder.allocator,
        self.builder.build_root,
        self.builder.env_map,
    );
    defer version.deinit();
    try file.writer().print(
        \\pub const hash = "{s}";
        \\pub const abbreviated_hash = "{s}";
        \\pub const commit_date = "{s}";
        \\pub const branch = "{s}";
        \\pub const dirty = {};
        \\pub const pretty_version = "{s}";
    , .{
        version.hash,
        version.abbreviated_hash,
        version.commit_date,
        version.branch,
        version.dirty,
        version.pretty_version,
    });
}

const GitVersion = struct {
    hash: []const u8,
    abbreviated_hash: []const u8,
    commit_date: []const u8,
    branch: []const u8,
    dirty: bool,
    pretty_version: []const u8,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.allocator.free(self.hash);
        self.allocator.free(self.abbreviated_hash);
        self.allocator.free(self.commit_date);
        self.allocator.free(self.branch);
        self.allocator.free(self.pretty_version);
    }
};

fn getGitVersion(allocator: std.mem.Allocator, git_working_root: ?[]const u8, env: anytype) !GitVersion {
    // git log -1 --pretty="%H%n%h%n%ci%n%D"
    // 3bf6adc13e4aa653a7b75b1b5e9c9db5215df8e1
    // 3bf6adc
    // 2022-01-12 12:21:28 -0800
    // HEAD -> zig-native

    const log_output = run(
        allocator,
        &[_][]const u8{
            "git",
            "log",
            "-1",
            "--pretty=%H%n%h%n%ci%n%D",
        },
        git_working_root,
        env,
    ) catch |e| {
        if (std.os.getenv("DRONE_COMMIT_SHA") != null)
            return getGitVersionFromDrone(allocator);
        return e;
    };
    defer allocator.free(log_output);
    const line_data = try getLines(allocator, 4, log_output);
    const hash = line_data[0];
    const abbrev_hash = line_data[1];
    const date = line_data[2];
    const branch = line_data[3];

    // git status --porcelain
    const status_output = try run(
        allocator,
        &[_][]const u8{
            "git",
            "status",
            "--porcelain",
        },
        git_working_root,
        env,
    );
    const dirty = blk: {
        if (status_output.len > 0) {
            allocator.free(status_output);
            break :blk true;
        }
        break :blk false;
    };
    const dirty_str = blk: {
        if (dirty) {
            break :blk " (dirty)";
        }
        break :blk "";
    };

    return GitVersion{
        .hash = hash,
        .abbreviated_hash = abbrev_hash,
        .commit_date = date,
        .branch = branch,
        .allocator = allocator,
        .dirty = dirty,
        .pretty_version = try prettyVersion(allocator, abbrev_hash, date, dirty_str),
    };
}
fn prettyVersion(allocator: std.mem.Allocator, abbrev_hash: []const u8, date: []const u8, dirty_str: []const u8) ![]const u8 {
    const pretty_version: []const u8 = try std.fmt.allocPrint(
        allocator,
        "version {s}, committed at {s}{s}",
        .{
            abbrev_hash,
            date,
            dirty_str,
        },
    );
    return pretty_version;
}

fn getGitVersionFromDrone(allocator: std.mem.Allocator) !GitVersion {
    const abbrev_hash = std.os.getenv("DRONE_COMMIT_SHA").?[0..7]; // This isn't quite how git works, but ok
    const date = std.os.getenv("DRONE_BUILD_STARTED").?; // this is a timestamp :(
    return GitVersion{
        .hash = std.os.getenv("DRONE_COMMIT_SHA").?,
        .abbreviated_hash = abbrev_hash,
        .commit_date = date,
        .branch = std.os.getenv("DRONE_COMMIT_BRANCH").?,
        .allocator = allocator,
        .dirty = false,
        .pretty_version = try prettyVersion(allocator, abbrev_hash, date, ""),
    };
}
fn getLines(allocator: std.mem.Allocator, comptime line_count: u32, data: []const u8) ![line_count][]u8 {
    var line: u32 = 0;
    var start: u32 = 0;
    var current: u32 = 0;
    var line_data: [line_count][]u8 = undefined;
    errdefer {
        while (line > 0) {
            allocator.free(line_data[line]);
            line -= 1;
        }
    }
    for (data) |c| {
        // try std.io.getStdErr().writer().print("line: {d}, c: {c}, cur: {d}, strt: {d}\n", .{ line, c, current, start });
        if (c == '\n') {
            line_data[line] = try allocator.dupe(u8, data[start..current]);
            // try std.io.getStdErr().writer().print("c: {d}, s: {d}, data: '{s}'\n", .{ current, start, line_data[line] });
            start = current + 1;
            line += 1;
        }
        current += 1;
    }
    return line_data;
}

// env is a std.process.BufMap, but that's private, which is a little weird tbh
fn run(allocator: std.mem.Allocator, argv: []const []const u8, cwd: ?[]const u8, env: anytype) ![]const u8 {
    {
        var msg = std.ArrayList(u8).init(allocator);
        defer msg.deinit();
        const writer = msg.writer();
        var prefix: []const u8 = "";
        for (argv) |arg| {
            try writer.print("{s}\"{s}\"", .{ prefix, arg });
            prefix = " ";
        }
        // std.log.debug("[RUN] {s}", .{msg.items});
    }

    const result = try std.ChildProcess.exec(.{
        .allocator = allocator,
        .argv = argv,
        .cwd = cwd,
        .env_map = env,
    });
    defer if (result.stderr.len > 0) allocator.free(result.stderr);
    try std.io.getStdErr().writer().writeAll(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) {
            std.log.err("process failed with exit code: {}", .{code});

            std.os.exit(0xff);
        },
        else => {
            std.log.err("process failed due to exception: {}", .{result});
            std.os.exit(0xff);
        },
    }
    return result.stdout;
}

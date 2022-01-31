//! Implements the standard credential chain:
//! 1. Environment variables
//! 2. Web identity token from STS
//! 3. Credentials/config files
//! 4. ECS Container credentials, using AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
//! 5. EC2 instance profile credentials
const std = @import("std");
const builtin = @import("builtin");
const auth = @import("aws_authentication.zig");

const log = std.log.scoped(.aws_credentials);

pub const Profile = struct {
    /// Credential file. Defaults to AWS_SHARED_CREDENTIALS_FILE or ~/.aws/credentials
    credential_file: ?[]const u8 = null,
    /// Config file. Defaults to AWS_CONFIG_FILE or ~/.aws/config
    config_file: ?[]const u8 = null,
    /// Config file. Defaults to AWS_PROFILE or default
    profile_name: ?[]const u8 = null,
};

pub const Options = struct {
    profile: Profile = .{},
};

pub fn getCredentials(allocator: std.mem.Allocator, options: Options) !auth.Credentials {
    if (try getEnvironmentCredentials(allocator)) |cred| return cred;
    // TODO: 2-5
    // Note that boto and Java disagree on where this fits in the order
    if (try getWebIdentityToken(allocator)) |cred| return cred;
    if (try getProfileCredentials(allocator, options.profile)) |cred| return cred;
    return error.NotImplemented;
}

fn getEnvironmentCredentials(allocator: std.mem.Allocator) !?auth.Credentials {
    const secret_key = (try getEnvironmentVariable(allocator, "AWS_SECRET_ACCESS_KEY")) orelse return null;
    defer allocator.free(secret_key); //yes, we're not zeroing. But then, the secret key is in an environment var anyway
    const mutable_key = try allocator.dupe(u8, secret_key);
    // Use cross-platform API (requires allocation)
    return auth.Credentials.init(
        allocator,
        (try getEnvironmentVariable(allocator, "AWS_ACCESS_KEY_ID")) orelse return null,
        mutable_key,
        (try getEnvironmentVariable(allocator, "AWS_SESSION_TOKEN")) orelse
            try getEnvironmentVariable(allocator, "AWS_SECURITY_TOKEN"), // Security token is backward compat only
    );
}

fn getEnvironmentVariable(allocator: std.mem.Allocator, key: []const u8) !?[]const u8 {
    return std.process.getEnvVarOwned(allocator, key) catch |e| switch (e) {
        std.process.GetEnvVarOwnedError.EnvironmentVariableNotFound => return null,
        else => return e,
    };
}

fn getWebIdentityToken(allocator: std.mem.Allocator) !?auth.Credentials {
    _ = allocator;
    // This API does not require signing. We can just use zfetch to
    // shoot a raw request over.
    // https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
    // https://github.com/boto/boto3/blob/85b975af30c408f93b654a21930218edd58336ad/docs/source/guide/credentials.rst#assume-role-with-web-identity-provider
    // https://github.com/aws/aws-sdk-java-v2/blob/master/core/auth/src/main/java/software/amazon/awssdk/auth/credentials/WebIdentityTokenFileCredentialsProvider.java
    // TODO: implement
    return null;
}

fn getProfileCredentials(allocator: std.mem.Allocator, options: Profile) !?auth.Credentials {
    var default_path: ?[]const u8 = null;
    defer if (default_path) |p| allocator.free(p);

    const creds_file_path = try filePath(
        allocator,
        options.credential_file,
        "AWS_SHARED_CREDENTIALS_FILE",
        default_path,
        "credentials",
    );
    defer allocator.free(creds_file_path.evaluated_path);
    default_path = default_path orelse creds_file_path.home;
    const config_file_path = try filePath(
        allocator,
        options.credential_file,
        "AWS_SHARED_CREDENTIALS_FILE",
        default_path,
        "config",
    );
    defer allocator.free(config_file_path.evaluated_path);
    default_path = default_path orelse config_file_path.home;

    // Get active profile
    const profile = (try getEnvironmentVariable(allocator, "AWS_PROFILE")) orelse
        try allocator.dupe(u8, "default");
    defer allocator.free(profile);
    log.debug("Looking for file credentials using profile '{s}'", .{profile});
    log.debug("Checking credentials file: {s}", .{creds_file_path.evaluated_path});
    const credentials_file = std.fs.openFileAbsolute(creds_file_path.evaluated_path, .{}) catch null;
    defer if (credentials_file) |f| f.close();
    // It's much more likely that we'll find credentials in the credentials file
    // so we'll try that first
    const creds_file_creds = try credsForFile(allocator, credentials_file, profile);
    var conf_file_creds = PartialCredentials{};
    if (creds_file_creds.access_key == null or creds_file_creds.secret_key == null) {
        log.debug("Checking config file: {s}", .{config_file_path.evaluated_path});
        const config_file = std.fs.openFileAbsolute(creds_file_path.evaluated_path, .{}) catch null;
        defer if (config_file) |f| f.close();
        conf_file_creds = try credsForFile(allocator, config_file, profile);
    }
    const access_key = keyFrom(allocator, creds_file_creds.access_key, conf_file_creds.access_key);
    const secret_key = keyFrom(allocator, creds_file_creds.secret_key, conf_file_creds.secret_key);
    defer if (secret_key) |k| allocator.free(k);

    if (access_key == null or secret_key == null) {
        const partial = access_key != null or secret_key != null;
        if (partial) {
            log.warn("Could not find credentials in file (partial creds detected)", .{});
        } else {
            log.info("Could not find credentials in file", .{});
        }
        if (access_key) |k| allocator.free(k);
        return null;
    }
    log.debug("Got full credentials from filesystem. Access key: {s}", .{access_key.?});
    return auth.Credentials.init(
        allocator,
        access_key.?,
        try allocator.dupe(u8, secret_key.?),
        null,
    );
}

fn keyFrom(allocator: std.mem.Allocator, priority_1: ?[]const u8, priority_2: ?[]const u8) ?[]const u8 {
    if (priority_1) |p1| {
        if (priority_2) |p2| allocator.free(p2);
        return p1;
    }
    return priority_2;
}

// We could conceivably find different portions of the creds in different
// files, so let's be super-loose here
const PartialCredentials = struct {
    access_key: ?[]const u8 = null,
    secret_key: ?[]const u8 = null,
};
fn credsForFile(allocator: std.mem.Allocator, file: ?std.fs.File, profile: []const u8) !PartialCredentials {
    if (file == null) return PartialCredentials{};
    const text = try file.?.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(text);
    const partial_creds = try credsForText(text, profile);
    var ak: ?[]const u8 = null;
    if (partial_creds.access_key) |k|
        ak = try allocator.dupe(u8, k);
    var sk: ?[]const u8 = null;
    if (partial_creds.secret_key) |k|
        sk = try allocator.dupe(u8, k);

    return PartialCredentials{
        .access_key = ak,
        .secret_key = sk,
    };
}

const LineIterator = struct {
    text: []const u8,
    inx: usize = 0,

    const Self = @This();

    pub fn init(text: []const u8) Self {
        return .{
            .text = text,
            .inx = 0,
        };
    }

    pub fn next(self: *Self) ?[]const u8 {
        if (self.inx >= self.text.len) return null;
        var current = self.inx;
        var start = self.inx;
        for (self.text[self.inx..]) |c, i| {
            if (c == '\n') {
                // log.debug("got \\n: {d}", .{i});
                current += i + 1;
                break;
            }
        }
        // log.debug("{d}:{d}", .{ current, self.inx });
        if (current != self.inx) {
            self.inx = current;
        } else { // no \n found
            self.inx = self.text.len + 1; // add one to capture the last char in return
        }
        return self.text[start .. self.inx - 1];
    }
};
fn credsForText(text: []const u8, profile: []const u8) !PartialCredentials {
    var lines = LineIterator.init(text);
    var is_in_profile = false;
    var was_in_profile = false;
    var done = false;
    var creds: [2]?[]const u8 = [_]?[]const u8{ null, null };

    while (lines.next()) |line| {
        // log.debug("line: {s}", .{line});
        var section_start: ?usize = 0;
        for (line) |c, i| {
            switch (c) {
                '#' => break,
                '[' => section_start = i + 1,
                ']' => {
                    if (section_start) |s| {
                        const current_section = line[s..i];
                        log.debug("got section: {s}", .{current_section});
                        is_in_profile = std.ascii.eqlIgnoreCase(current_section, profile);
                        if (was_in_profile and !is_in_profile) {
                            done = true;
                            break;
                        }

                        was_in_profile = is_in_profile;
                        break; // got what we need from this line
                    }
                },
                '=' => {
                    if (!is_in_profile) continue;
                    const key = std.mem.trim(u8, line[0..i], " \t"); // other whitespace we care about?
                    log.debug("got key: {s}", .{key});
                    for (&[_][]const u8{
                        "aws_access_key_id",
                        "aws_secret_access_key",
                    }) |needle, inx| {
                        if (std.ascii.eqlIgnoreCase(key, needle)) {
                            // TODO: Trim this out
                            creds[inx] = trim(line[i + 1 ..]);
                        }
                    }
                },
                else => {},
            }
        }
        if (done) {
            log.debug("no longer in target section: bailing", .{});
            break;
        }
    }
    log.debug("done parsing text", .{});
    return PartialCredentials{
        .access_key = creds[0],
        .secret_key = creds[1],
    };
}

fn trim(text: []const u8) []const u8 {
    // "  myval # yo";
    var start: ?usize = null;
    var end: ?usize = null;

    for (text) |c, i| switch (c) {
        ' ', '\t' => {},
        '#' => return trimmed(text, start, end),
        else => {
            if (start == null) start = i;
            end = i + 1;
        },
    };
    return trimmed(text, start, end);
}

fn trimmed(text: []const u8, start: ?usize, end: ?usize) []const u8 {
    if (start == null) return "";
    if (end == null) return text[start.?..];
    return text[start.?..end.?];
}

fn filePath(
    allocator: std.mem.Allocator,
    specified_path: ?[]const u8,
    env_var_name: []const u8,
    config_dir: ?[]const u8,
    config_file_name: []const u8,
) !EvaluatedPath {
    if (specified_path) |p| return EvaluatedPath{ .evaluated_path = try allocator.dupe(u8, p) };
    // Not specified. Check environment variable, otherwise, hard coded default
    if (try getEnvironmentVariable(allocator, env_var_name)) |v| return EvaluatedPath{ .evaluated_path = v };

    // Not in environment variable either. Go fish
    return try getDefaultPath(allocator, config_dir, ".aws", config_file_name);
}

const EvaluatedPath = struct {
    home: ?[]const u8 = null,
    evaluated_path: []const u8,
};
fn getDefaultPath(allocator: std.mem.Allocator, home_dir: ?[]const u8, dir: []const u8, file: []const u8) !EvaluatedPath {
    var home = home_dir orelse try getHomeDir(allocator);
    log.debug("Home directory: {s}", .{home});
    const rc = try std.fs.path.join(allocator, &[_][]const u8{ home, dir, file });
    log.debug("Path evaluated as: {s}", .{rc});
    return EvaluatedPath{ .home = home, .evaluated_path = rc };
}

fn getHomeDir(allocator: std.mem.Allocator) ![]const u8 {
    switch (builtin.os.tag) {
        .windows => {
            var dir_path_ptr: [*:0]u16 = undefined;
            // https://docs.microsoft.com/en-us/windows/win32/shell/knownfolderid
            const FOLDERID_Profile = std.os.windows.GUID.parse("{5E6C858F-0E22-4760-9AFE-EA3317B67173}");
            switch (std.os.windows.shell32.SHGetKnownFolderPath(
                &FOLDERID_Profile,
                std.os.windows.KF_FLAG_CREATE,
                null,
                &dir_path_ptr,
            )) {
                std.os.windows.S_OK => {
                    defer std.os.windows.ole32.CoTaskMemFree(@ptrCast(*anyopaque, dir_path_ptr));
                    const global_dir = std.unicode.utf16leToUtf8Alloc(allocator, std.mem.sliceTo(dir_path_ptr, 0)) catch |err| switch (err) {
                        error.UnexpectedSecondSurrogateHalf => return error.HomeDirUnavailable,
                        error.ExpectedSecondSurrogateHalf => return error.HomeDirUnavailable,
                        error.DanglingSurrogateHalf => return error.HomeDirUnavailable,
                        error.OutOfMemory => return error.OutOfMemory,
                    };
                    return global_dir;
                    // defer allocator.free(global_dir);
                },
                std.os.windows.E_OUTOFMEMORY => return error.OutOfMemory,
                else => return error.HomeDirUnavailable,
            }
        },
        .macos, .linux, .freebsd, .netbsd, .dragonfly, .openbsd, .solaris => {
            const home_dir = std.os.getenv("HOME") orelse {
                // TODO look in /etc/passwd
                return error.HomeDirUnavailable;
            };
            return allocator.dupe(u8, home_dir);
        },
        // Code from https://github.com/ziglang/zig/blob/9f9f215305389c08a21730859982b68bf2681932/lib/std/fs/get_app_data_dir.zig
        // be_user_settings magic number is probably different for home directory
        // .haiku => {
        //     var dir_path_ptr: [*:0]u8 = undefined;
        //     // TODO look into directory_which
        //     const be_user_settings = 0xbbe;
        //     const rc = os.system.find_directory(be_user_settings, -1, true, dir_path_ptr, 1);
        //     const settings_dir = try allocator.dupeZ(u8, mem.sliceTo(dir_path_ptr, 0));
        //     defer allocator.free(settings_dir);
        //     switch (rc) {
        //         0 => return fs.path.join(allocator, &[_][]const u8{ settings_dir, appname }),
        //         else => return error.AppDataDirUnavailable,
        //     }
        // },
        else => @compileError("Unsupported OS"),
    }
}

test "filePath" {
    const allocator = std.testing.allocator;
    std.testing.log_level = .debug;
    log.debug("\n", .{});
    const path = try filePath(allocator, null, "NOTHING", null, "hello");
    defer allocator.free(path.evaluated_path);
    defer allocator.free(path.home.?);
    try std.testing.expect(path.evaluated_path.len > 10);
    try std.testing.expectEqualStrings("hello", path.evaluated_path[path.evaluated_path.len - 5 ..]);
    try std.testing.expect(path.home != null);
}

test "ini to creds" {
    std.testing.log_level = .debug;
    log.debug("\n", .{});
    const partial_creds = try credsForText(
        \\
        \\# Amazon Web Services Credentials File used by AWS CLI, SDKs, and tools
        \\# This file was created by the AWS Toolkit for Visual Studio Code extension.
        \\#
        \\# Your AWS credentials are represented by access keys associated with IAM users.
        \\# For information about how to create and manage AWS access keys for a user, see:
        \\# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
        \\#
        \\# This credential file can store multiple access keys by placing each one in a
        \\# named "profile". For information about how to change the access keys in a
        \\# profile or to add a new profile with a different access key, see:
        \\# https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html
        \\#
        \\[other_section]
        \\access_key_id = NOTYOURACCESSKEY
        \\
        \\  [default]
        \\  # The access key and secret key pair identify your account and grant access to AWS.
        \\aws_access_key_id = AKIDEXAMPLE # access key
        \\
        \\[another_section]
        \\access_key_id = NOTYOURACCESSKEYEITHER
    , "default");

    try std.testing.expect(partial_creds.access_key != null);
    try std.testing.expectEqualStrings("AKIDEXAMPLE", partial_creds.access_key.?);
    try std.testing.expect(partial_creds.secret_key == null);
}

//! Implements the standard credential chain:
//! 1. Environment variables
//! 2. Web identity token from STS
//! 3. Credentials/config files
//! 4. ECS Container credentials, using AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
//! 5. EC2 instance profile credentials
//!
//! For testing purposes, you can also set the static credentials object, which
//! will override all of the above
const std = @import("std");
const builtin = @import("builtin");
const auth = @import("aws_authentication.zig");

const scoped_log = std.log.scoped(.aws_credentials);
/// Specifies logging level. This should not be touched unless the normal
/// zig logging capabilities are inaccessible (e.g. during a build)
pub var log_level: std.log.Level = .debug;

/// Turn off logging completely
pub var logs_off: bool = false;
const log = struct {
    /// Log an error message. This log level is intended to be used
    /// when something has gone wrong. This might be recoverable or might
    /// be followed by the program exiting.
    pub fn err(
        comptime format: []const u8,
        args: anytype,
    ) void {
        if (!logs_off and @intFromEnum(std.log.Level.err) <= @intFromEnum(log_level))
            scoped_log.err(format, args);
    }

    /// Log a warning message. This log level is intended to be used if
    /// it is uncertain whether something has gone wrong or not, but the
    /// circumstances would be worth investigating.
    pub fn warn(
        comptime format: []const u8,
        args: anytype,
    ) void {
        if (!logs_off and @intFromEnum(std.log.Level.warn) <= @intFromEnum(log_level))
            scoped_log.warn(format, args);
    }

    /// Log an info message. This log level is intended to be used for
    /// general messages about the state of the program.
    pub fn info(
        comptime format: []const u8,
        args: anytype,
    ) void {
        if (!logs_off and @intFromEnum(std.log.Level.info) <= @intFromEnum(log_level))
            scoped_log.info(format, args);
    }

    /// Log a debug message. This log level is intended to be used for
    /// messages which are only useful for debugging.
    pub fn debug(
        comptime format: []const u8,
        args: anytype,
    ) void {
        if (!logs_off and @intFromEnum(std.log.Level.debug) <= @intFromEnum(log_level))
            scoped_log.debug(format, args);
    }
};

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

pub var static_credentials: ?auth.Credentials = null;

pub fn getCredentials(allocator: std.mem.Allocator, io: std.Io, options: Options) !auth.Credentials {
    if (static_credentials) |c| return c;
    if (try getEnvironmentCredentials(allocator)) |cred| {
        log.debug("Found credentials in environment. Access key: {s}", .{cred.access_key});
        return cred;
    }
    // Note that boto and Java disagree on where this fits in the order
    // GetWebIdentity is not currently implemented. The rest are tested and gtg
    // Note: Lambda just sets environment variables
    if (try getWebIdentityToken(allocator)) |cred| return cred;
    if (try getProfileCredentials(allocator, io, options.profile)) |cred| return cred;

    if (try getContainerCredentials(allocator, io)) |cred| return cred;
    // I don't think we need v1 at all?
    if (try getImdsv2Credentials(allocator, io)) |cred| return cred;
    return error.CredentialsNotFound;
}

fn getEnvironmentCredentials(allocator: std.mem.Allocator) !?auth.Credentials {
    const secret_key = (try getEnvironmentVariable(allocator, "AWS_SECRET_ACCESS_KEY")) orelse return null;
    defer allocator.free(secret_key); //yes, we're not zeroing. But then, the secret key is in an environment var anyway
    // Use cross-platform API (requires allocation)
    return auth.Credentials.init(
        allocator,
        (try getEnvironmentVariable(allocator, "AWS_ACCESS_KEY_ID")) orelse return null,
        try allocator.dupe(u8, secret_key),
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
fn getContainerCredentials(allocator: std.mem.Allocator, io: std.Io) !?auth.Credentials {
    // A note on testing: The best way I have found to test this process is
    // the following. Setup an ECS Fargate cluster and create a task definition
    // with the command  ["/bin/bash","-c","while true; do sleep 10; done"].
    //
    // In the console, this would be represented as:
    //
    // /bin/bash,-c,while true; do sleep 10; done
    //
    // Then we run the task with ECS exec-command enabled. The cli for this
    // will look something like the following:
    //
    // aws ecs run-task --enable-execute-command \
    //   --cluster Fargate \
    //   --network-configuration "awsvpcConfiguration={subnets=[subnet-1f3f4278],securityGroups=[sg-0aab58c6b2bde2105],assignPublicIp=ENABLED}" \
    //   --launch-type FARGATE \
    //   --task-definition zig-demo:3
    //
    //   Of course, subnets and security groups will be different. Public
    //   IP is necessary or you won't be able to pull the image. I used
    //   AL2 from the ECR public image:
    //
    //   public.ecr.aws/amazonlinux/amazonlinux:latest
    //
    // With the task running, now we need to execute it. I used CloudShell
    // from the AWS console because everything is already installed and
    // configured, ymmv. You need AWS CLI v2 with the session manager extension.
    //
    // It's good to do a pre-flight check to make sure you can run the
    // execute command. I used this tool to do so:
    //
    // https://github.com/aws-containers/amazon-ecs-exec-checker
    //
    // A couple yellows were ok, but no red.
    //
    // From there, get your task id and Bob's your uncle:
    //
    // aws ecs execute-command --cluster Fargate --command "/bin/bash" --interactive --task ec65b4d9887b429cba5d45ec70a8afa1
    //
    // Compile code, copy to S3, install AWS CLI within the session, download
    // from s3 and run
    const container_relative_uri = (try getEnvironmentVariable(allocator, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")) orelse return null;
    defer allocator.free(container_relative_uri);
    const container_uri = try std.fmt.allocPrint(allocator, "http://169.254.170.2{s}", .{container_relative_uri});
    defer allocator.free(container_uri);

    var cl = std.http.Client{ .allocator = allocator, .io = io };
    defer cl.deinit(); // I don't belive connection pooling would help much here as it's non-ssl and local
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    const response_payload = &aw.writer;
    const req = try cl.fetch(.{
        .location = .{ .url = container_uri },
        .response_writer = response_payload,
    });
    if (req.status != .ok and req.status != .not_found) {
        log.warn("Bad status code received from container credentials endpoint: {}", .{@intFromEnum(req.status)});
        return null;
    }
    if (req.status == .not_found) return null;

    log.debug("Read {d} bytes from container credentials endpoint", .{aw.written().len});
    if (aw.written().len == 0) return null;

    const CredsResponse = struct {
        AccessKeyId: []const u8,
        Expiration: []const u8,
        RoleArn: []const u8,
        SecretAccessKey: []const u8,
        Token: []const u8,
    };
    const creds_response = blk: {
        const res = std.json.parseFromSlice(CredsResponse, allocator, aw.written(), .{}) catch |e| {
            log.err("Unexpected Json response from container credentials endpoint: {s}", .{aw.written()});
            log.err("Error parsing json: {}", .{e});
            if (@errorReturnTrace()) |trace| {
                std.debug.dumpStackTrace(trace);
            }

            return null;
        };
        break :blk res;
    };
    defer creds_response.deinit();

    return auth.Credentials.init(
        allocator,
        try allocator.dupe(u8, creds_response.value.AccessKeyId),
        try allocator.dupe(u8, creds_response.value.SecretAccessKey),
        try allocator.dupe(u8, creds_response.value.Token),
    );
}

fn getImdsv2Credentials(allocator: std.mem.Allocator, io: std.Io) !?auth.Credentials {
    var token: ?[]u8 = null;
    defer if (token) |t| allocator.free(t);
    var cl = std.http.Client{ .allocator = allocator, .io = io };
    defer cl.deinit(); // I don't belive connection pooling would help much here as it's non-ssl and local
    // Get token
    {
        var aw: std.Io.Writer.Allocating = .init(allocator);
        defer aw.deinit();
        const response_payload = &aw.writer;
        const req = try cl.fetch(.{
            .method = .PUT,
            .location = .{ .url = "http://169.254.169.254/latest/api/token" },
            .extra_headers = &[_]std.http.Header{
                .{ .name = "X-aws-ec2-metadata-token-ttl-seconds", .value = "21600" },
            },
            .response_writer = response_payload,
        });
        if (req.status != .ok) {
            log.warn("Bad status code received from IMDS v2: {}", .{@intFromEnum(req.status)});
            return null;
        }
        if (aw.written().len == 0) {
            log.warn("Unexpected zero response from IMDS v2", .{});
            return null;
        }

        token = try aw.toOwnedSlice();
        errdefer if (token) |t| allocator.free(t);
    }
    std.debug.assert(token != null);
    log.debug("Got token from IMDSv2: {s}", .{token.?});
    const role_name = try getImdsRoleName(allocator, &cl, token.?);
    if (role_name == null) {
        log.info("No role is associated with this instance", .{});
        return null;
    }
    defer allocator.free(role_name.?);
    log.debug("Got role name '{s}'", .{role_name.?});
    return getImdsCredentials(allocator, &cl, role_name.?, token.?);
}

fn getImdsRoleName(allocator: std.mem.Allocator, client: *std.http.Client, imds_token: []u8) !?[]const u8 {
    //     {
    //   "Code" : "Success",
    //   "LastUpdated" : "2022-02-09T05:42:09Z",
    //   "InstanceProfileArn" : "arn:aws:iam::550620852718:instance-profile/ec2-dev",
    //   "InstanceProfileId" : "AIPAYAM4POHXCFNKZ7HU2"
    // }
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    const response_payload = &aw.writer;
    const req = try client.fetch(.{
        .method = .GET,
        .location = .{ .url = "http://169.254.169.254/latest/meta-data/iam/info" },
        .extra_headers = &[_]std.http.Header{
            .{ .name = "X-aws-ec2-metadata-token", .value = imds_token },
        },
        .response_writer = response_payload,
    });

    if (req.status != .ok and req.status != .not_found) {
        log.warn("Bad status code received from IMDS iam endpoint: {}", .{@intFromEnum(req.status)});
        return null;
    }
    if (req.status == .not_found) return null;
    if (aw.written().len == 0) {
        log.warn("Unexpected empty response from IMDS endpoint post token", .{});
        return null;
    }

    const ImdsResponse = struct {
        Code: []const u8,
        LastUpdated: []const u8,
        InstanceProfileArn: []const u8,
        InstanceProfileId: []const u8,
    };
    const imds_response = std.json.parseFromSlice(ImdsResponse, allocator, aw.written(), .{}) catch |e| {
        log.err("Unexpected Json response from IMDS endpoint: {s}", .{aw.written()});
        log.err("Error parsing json: {}", .{e});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace);
        }
        return null;
    };
    defer imds_response.deinit();

    const role_arn = imds_response.value.InstanceProfileArn;
    const first_slash = std.mem.indexOf(u8, role_arn, "/"); // I think this is valid
    if (first_slash == null) {
        log.err("Could not find role name in arn '{s}'", .{role_arn});
        return null;
    }
    return try allocator.dupe(u8, role_arn[first_slash.? + 1 ..]);
}

/// Note - this internal function assumes zfetch is initialized prior to use
fn getImdsCredentials(allocator: std.mem.Allocator, client: *std.http.Client, role_name: []const u8, imds_token: []u8) !?auth.Credentials {
    const url = try std.fmt.allocPrint(allocator, "http://169.254.169.254/latest/meta-data/iam/security-credentials/{s}/", .{role_name});
    defer allocator.free(url);
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    const response_payload = &aw.writer;
    const req = try client.fetch(.{
        .method = .GET,
        .location = .{ .url = url },
        .extra_headers = &[_]std.http.Header{
            .{ .name = "X-aws-ec2-metadata-token", .value = imds_token },
        },
        .response_writer = response_payload,
    });

    if (req.status != .ok and req.status != .not_found) {
        log.warn("Bad status code received from IMDS role endpoint: {}", .{@intFromEnum(req.status)});
        return null;
    }
    if (req.status == .not_found) return null;
    if (aw.written().len == 0) {
        log.warn("Unexpected empty response from IMDS role endpoint", .{});
        return null;
    }

    // log.debug("Read {d} bytes from imds v2 credentials endpoint", .{read});
    const ImdsResponse = struct {
        Code: []const u8,
        LastUpdated: []const u8,
        Type: []const u8,
        AccessKeyId: []const u8,
        SecretAccessKey: []const u8,
        Token: []const u8,
        Expiration: []const u8,
    };
    const imds_response = std.json.parseFromSlice(ImdsResponse, allocator, aw.written(), .{}) catch |e| {
        log.err("Unexpected Json response from IMDS endpoint: {s}", .{aw.written()});
        log.err("Error parsing json: {}", .{e});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace);
        }

        return null;
    };
    defer imds_response.deinit();

    const ret = auth.Credentials.init(
        allocator,
        try allocator.dupe(u8, imds_response.value.AccessKeyId),
        try allocator.dupe(u8, imds_response.value.SecretAccessKey),
        try allocator.dupe(u8, imds_response.value.Token),
    );
    log.debug("IMDSv2 credentials found. Access key: {s}", .{ret.access_key});

    return ret;

    // {
    //   "Code" : "Success",
    //   "LastUpdated" : "2022-02-08T23:49:02Z",
    //   "Type" : "AWS-HMAC",
    //   "AccessKeyId" : "ASEXAMPLE",
    //   "SecretAccessKey" : "example",
    //   "Token" : "IQoJb==",
    //   "Expiration" : "2022-02-09T06:02:23Z"
    // }

}

fn getProfileCredentials(allocator: std.mem.Allocator, io: std.Io, options: Profile) !?auth.Credentials {
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
    const creds_file_creds = try credsForFile(allocator, io, credentials_file, profile);
    var conf_file_creds = PartialCredentials{};
    if (creds_file_creds.access_key == null or creds_file_creds.secret_key == null) {
        log.debug("Checking config file: {s}", .{config_file_path.evaluated_path});
        const config_file = std.fs.openFileAbsolute(creds_file_path.evaluated_path, .{}) catch null;
        defer if (config_file) |f| f.close();
        conf_file_creds = try credsForFile(allocator, io, config_file, profile);
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
fn credsForFile(allocator: std.mem.Allocator, io: std.Io, file: ?std.fs.File, profile: []const u8) !PartialCredentials {
    if (file == null) return PartialCredentials{};
    var fbuf: [1024]u8 = undefined;
    var freader = file.?.reader(io, &fbuf);
    var reader = &freader.interface;
    const text = try reader.allocRemaining(allocator, .unlimited);
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
        const start = self.inx;
        for (self.text[self.inx..], 0..) |c, i| {
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
        for (line, 0..) |c, i| {
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
                    }, 0..) |needle, inx| {
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

    for (text, 0..) |c, i| switch (c) {
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
    const home = home_dir orelse try getHomeDir(allocator);
    log.debug("Home directory: {s}", .{home});
    const rc = try std.fs.path.join(allocator, &[_][]const u8{ home, dir, file });
    log.debug("Path evaluated as: {s}", .{rc});
    return EvaluatedPath{ .home = home, .evaluated_path = rc };
}

fn getHomeDir(allocator: std.mem.Allocator) ![]const u8 {
    switch (builtin.os.tag) {
        .windows => {
            return std.process.getEnvVarOwned(allocator, "USERPROFILE") catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                else => return error.HomeDirUnavailable,
            };
        },
        .macos, .linux, .freebsd, .netbsd, .dragonfly, .openbsd, .illumos => {
            const home_dir = std.posix.getenv("HOME") orelse {
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
    // std.testing.log_level = .debug;
    // log.debug("\n", .{});
    const path = try filePath(allocator, null, "NOTHING", null, "hello");
    defer allocator.free(path.evaluated_path);
    defer allocator.free(path.home.?);
    try std.testing.expect(path.evaluated_path.len > 10);
    try std.testing.expectEqualStrings("hello", path.evaluated_path[path.evaluated_path.len - 5 ..]);
    try std.testing.expect(path.home != null);
}

test "ini to creds" {
    // std.testing.log_level = .debug;
    // log.debug("\n", .{});
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

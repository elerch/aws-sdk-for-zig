//! This module provides a low level http interface for working with AWS
//! It also provides an option to operate outside the AWS ecosystem through
//! the makeRequest call with a null signingOptions.
//!
//! Typical usage:
//! const client = awshttp.AwsHttp.init(allocator);
//! defer client.deinit()
//! const result = client.callApi (or client.makeRequest)
//! defer result.deinit();
const std = @import("std");
const base = @import("aws_http_base.zig");
const signing = @import("aws_signing.zig");
const credentials = @import("aws_credentials.zig");

const CN_NORTH_1_HASH = std.hash_map.hashString("cn-north-1");
const CN_NORTHWEST_1_HASH = std.hash_map.hashString("cn-northwest-1");
const US_ISO_EAST_1_HASH = std.hash_map.hashString("us-iso-east-1");
const US_ISOB_EAST_1_HASH = std.hash_map.hashString("us-isob-east-1");

const scoped_log = std.log.scoped(.awshttp);

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

pub const AwsError = error{
    AddHeaderError,
    AlpnError,
    CredentialsError,
    HttpClientConnectError,
    HttpRequestError,
    SignableError,
    SigningInitiationError,
    TlsError,
    RequestCreateError,
    SetupConnectionError,
    StatusCodeError,
    SetRequestMethodError,
    SetRequestPathError,
};

pub const Options = struct {
    region: []const u8 = "aws-global",
    dualstack: bool = false,
    sigv4_service_name: ?[]const u8 = null,

    mock: ?Mock = null,
};

/// mocking methods for isolated testing
pub const Mock = struct {
    /// Used to provide consistent signing
    signing_time: ?i64,
    /// context is desiged to be type-erased pointer (@intFromPtr)
    context: usize = 0,
    request_fn: *const fn (
        usize,
        std.http.Method,
        std.Uri,
        std.http.Client.RequestOptions,
    ) std.http.Client.RequestError!std.http.Client.Request,
    send_body_complete: *const fn (usize, []u8) std.Io.Writer.Error!void,
    receive_head: *const fn (usize) std.http.Client.Request.ReceiveHeadError!std.http.Client.Response,
    reader_decompressing: *const fn (usize) *std.Io.Reader,

    fn request(m: Mock, method: std.http.Method, uri: std.Uri, options: std.http.Client.RequestOptions) std.http.Client.RequestError!std.http.Client.Request {
        return m.request_fn(m.context, method, uri, options);
    }
    fn sendBodyComplete(m: Mock, body: []u8) std.Io.Writer.Error!void {
        return m.send_body_complete(m.context, body);
    }
    fn receiveHead(m: Mock) std.http.Client.Request.ReceiveHeadError!std.http.Client.Response {
        return m.receive_head(m.context);
    }
    fn readerDecompressing(m: Mock) *std.Io.Reader {
        return m.reader_decompressing(m.context);
    }
};

pub const Header = std.http.Header;
pub const HttpRequest = base.Request;
pub const HttpResult = base.Result;

const EndPoint = struct {
    uri: []const u8,
    host: []const u8,
    scheme: []const u8,
    port: u16,
    path: []const u8,
    allocator: std.mem.Allocator,

    fn deinit(self: EndPoint) void {
        self.allocator.free(self.uri);
        self.allocator.free(self.host);
        self.allocator.free(self.path);
    }
};
pub const AwsHttp = struct {
    allocator: std.mem.Allocator,
    proxy: ?std.http.Client.Proxy,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, proxy: ?std.http.Client.Proxy) Self {
        return Self{
            .allocator = allocator,
            .proxy = proxy,
            // .credentialsProvider = // creds provider could be useful
        };
    }

    pub fn deinit(self: *AwsHttp) void {
        _ = self;
        log.debug("Deinit complete", .{});
    }

    /// callApi allows the calling of AWS APIs through a higher-level interface.
    /// It will calculate the appropriate endpoint and action parameters for the
    /// service called, and will set up the signing options. The return
    /// value is simply a raw HttpResult
    pub fn callApi(self: Self, service: []const u8, request: HttpRequest, options: Options) !HttpResult {
        // This function or regionSubDomain needs altering for virtual host
        // addressing (for S3). Botocore, and I suspect other SDKs, have
        // hardcoded exceptions for S3:
        // https://github.com/boto/botocore/blob/f2b0dbb800b8dc2a3541334d5ca1190faf900150/botocore/utils.py#L2160-L2181
        // Boto assumes virtual host addressing unless the endpoint url is configured
        //
        // NOTE: There are 4 rest_xml services. They are:
        // * CloudFront
        // * Route53
        // * S3
        // * S3 control
        //
        // All 4 are non-standard. Route53 and CloudFront are global endpoints
        // S3 uses virtual host addressing (except when it doesn't), and
        // S3 control uses <account-id>.s3-control.<region>.amazonaws.com
        //
        // So this regionSubDomain call needs to handle generic customization
        const endpoint = try endpointForRequest(self.allocator, service, request, options);
        defer endpoint.deinit();
        log.debug("Calling endpoint {s}", .{endpoint.uri});
        // TODO: Should we allow customization here?
        const creds = try credentials.getCredentials(self.allocator, .{});
        defer creds.deinit();
        const signing_config: signing.Config = .{
            .region = getRegion(service, options.region),
            .service = options.sigv4_service_name orelse service,
            .credentials = creds,
            .signing_time = if (options.mock) |m| m.signing_time else null,
        };
        return try self.makeRequest(endpoint, request, signing_config, options);
    }

    /// makeRequest is a low level http/https function that can be used inside
    /// or outside the context of AWS services. To use it outside AWS, simply
    /// pass a null value in for signing_options.
    ///
    /// Otherwise, it will simply take a URL endpoint (without path information),
    /// HTTP method (e.g. GET, POST, etc.), and request body.
    ///
    /// At the moment this does not allow changing headers, but addtional
    /// ones are possible. This is likely to change. Current headers are:
    ///
    /// Accept: application/json
    /// User-Agent: zig-aws 1.0, Powered by the AWS Common Runtime.
    /// Content-Type: application/x-www-form-urlencoded
    /// Content-Length: (length of body)
    ///
    /// Return value is an HttpResult, which will need the caller to deinit().
    pub fn makeRequest(
        self: Self,
        endpoint: EndPoint,
        request: HttpRequest,
        signing_config: ?signing.Config,
        options: Options,
    ) !HttpResult {
        var request_cp = request;

        log.debug("Request Path: {s}", .{request_cp.path});
        log.debug("Endpoint Path (actually used): {s}", .{endpoint.path});
        log.debug("Query: {s}", .{request_cp.query});
        log.debug("Request additional header count: {d}", .{request_cp.headers.len});
        log.debug("Method: {s}", .{request_cp.method});
        log.debug("body length: {d}", .{request_cp.body.len});
        log.debug("Body\n====\n{s}\n====", .{request_cp.body});

        // Endpoint calculation might be different from the request (e.g. S3 requests)
        // We will use endpoint instead
        request_cp.path = endpoint.path;

        var request_headers = std.ArrayList(std.http.Header){};
        defer request_headers.deinit(self.allocator);

        const len = try addHeaders(self.allocator, &request_headers, endpoint.host, request_cp.body, request_cp.content_type, request_cp.headers);
        defer if (len) |l| self.allocator.free(l);
        request_cp.headers = request_headers.items;

        if (signing_config) |opts| request_cp = try signing.signRequest(self.allocator, request_cp, opts);
        defer {
            if (signing_config) |opts| {
                signing.freeSignedRequest(self.allocator, &request_cp, opts);
            }
        }

        var headers = std.ArrayList(std.http.Header){};
        defer headers.deinit(self.allocator);
        for (request_cp.headers) |header|
            try headers.append(self.allocator, .{ .name = header.name, .value = header.value });
        log.debug("All Request Headers:", .{});
        for (headers.items) |h| {
            log.debug("\t{s}: {s}", .{ h.name, h.value });
        }

        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}{s}", .{ endpoint.uri, request_cp.path, request_cp.query });
        defer self.allocator.free(url);
        log.debug("Request url: {s}", .{url});
        // TODO: Fix this proxy stuff. This is all a kludge just to compile, but std.http.Client has it all built in now
        var cl = std.http.Client{ .allocator = self.allocator, .https_proxy = if (self.proxy) |*p| @constCast(p) else null };
        defer cl.deinit(); // TODO: Connection pooling
        const method = std.meta.stringToEnum(std.http.Method, request_cp.method).?;

        // Fetch API in 0.15.1 is insufficient as it does not provide
        // server headers. We'll construct and send the request ourselves
        const uri = try std.Uri.parse(url);
        const req_options: std.http.Client.RequestOptions = .{
            // we need full control over most headers. I wish libraries would do a
            // better job of having default headers as an opt-in...
            .headers = .{
                .host = .omit,
                .authorization = .omit,
                .user_agent = .omit,
                .connection = .default, // we can let the client manage this...it has no impact to us
                .accept_encoding = .default, // accept encoding (gzip, deflate) *should* be ok
                .content_type = .omit,
            },
            .extra_headers = headers.items,
        };

        var req = if (options.mock) |m|
            try m.request(method, uri, req_options) // This will call the test harness
        else
            try cl.request(method, uri, req_options);
        defer req.deinit();
        // TODO: Need to test for payloads > 2^14. I believe one of our tests does this, but not sure
        // if (request_cp.body.len > 0) {
        //     // Workaround for https://github.com/ziglang/zig/issues/15626
        //     const max_bytes: usize = 1 << 14;
        //     var inx: usize = 0;
        //     while (request_cp.body.len > inx) {
        //         try req.writeAll(request_cp.body[inx..@min(request_cp.body.len, inx + max_bytes)]);
        //         inx += max_bytes;
        //     }
        //
        //     try req.finish();
        // }
        // try req.wait();

        if (request_cp.body.len > 0) {
            // This seems a bit silly, but we can't have a []const u8 here
            // because when it sends, it's using a writer, and this becomes
            // the buffer of the writer. It's conceivable that something
            // in the chain then does actually modify the body of the request
            // so we'll need to duplicate it here
            const req_body = try self.allocator.dupe(u8, request_cp.body);
            defer self.allocator.free(req_body); // docs for sendBodyComplete say it flushes, so no need to outlive this
            if (options.mock) |m|
                try m.sendBodyComplete(req_body)
            else
                try req.sendBodyComplete(req_body);
        } else if (options.mock == null) try req.sendBodiless();

        // if (options.mock == null) log.err("Request sent. Body len {d}, uri {f}", .{ request_cp.body.len, uri });
        var response = if (options.mock) |m| try m.receiveHead() else try req.receiveHead(&.{});

        // TODO: Timeout - is this now above us?
        log.debug(
            "Request Complete. Response code {d}: {?s}",
            .{ @intFromEnum(response.head.status), response.head.status.phrase() },
        );
        log.debug("Response headers:", .{});
        var resp_headers = std.ArrayList(Header){};
        defer resp_headers.deinit(self.allocator);
        var it = response.head.iterateHeaders();
        while (it.next()) |h| { // even though we don't expect to fill the buffer,
            // we don't get a length, but looks via stdlib source
            // it should be ok to call next on the undefined memory
            log.debug("    {s}: {s}", .{ h.name, h.value });
            try resp_headers.append(self.allocator, .{
                .name = try (self.allocator.dupe(u8, h.name)),
                .value = try (self.allocator.dupe(u8, h.value)),
            });
        }
        // This is directly lifted from fetch, as there is no function in
        // 0.15.1 client to negotiate decompression
        const decompress_buffer: []u8 = switch (response.head.content_encoding) {
            .identity => &.{},
            .zstd => try self.allocator.alloc(u8, std.compress.zstd.default_window_len),
            .deflate, .gzip => try self.allocator.alloc(u8, std.compress.flate.max_window_len),
            .compress => return error.UnsupportedCompressionMethod,
        };
        defer self.allocator.free(decompress_buffer);

        var transfer_buffer: [64]u8 = undefined;
        var decompress: std.http.Decompress = undefined;
        const reader = response.readerDecompressing(&transfer_buffer, &decompress, decompress_buffer);

        // Not sure on optimal size here, but should definitely be > 0
        var aw = try std.Io.Writer.Allocating.initCapacity(self.allocator, 128);
        defer aw.deinit();
        const response_writer = &aw.writer;
        _ = reader.streamRemaining(response_writer) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };
        log.debug("raw response body:\n{s}", .{aw.written()});

        const rc = HttpResult{
            .response_code = @intFromEnum(response.head.status),
            .body = try aw.toOwnedSlice(),
            .headers = try resp_headers.toOwnedSlice(self.allocator),
            .allocator = self.allocator,
        };
        return rc;
    }
};

fn getRegion(service: []const u8, region: []const u8) []const u8 {
    if (std.mem.eql(u8, service, "cloudfront")) return "us-east-1";
    if (std.mem.eql(u8, service, "iam")) return "us-east-1";
    return region;
}

fn addHeaders(
    allocator: std.mem.Allocator,
    headers: *std.ArrayList(std.http.Header),
    host: []const u8,
    body: []const u8,
    content_type: []const u8,
    additional_headers: []const Header,
) !?[]const u8 {
    // We don't need body because they were to add a Content-Length header. But
    // that is being added by the client send() function, so we don't want it
    // on the request twice. But I also feel pretty strongly that send() should
    // be providing us control, because I think if we don't add it here, it
    // won't get signed, and we would really prefer it to be signed. So, we
    // will wait and watch for this situation to change in stdlib

    _ = body;
    var has_content_type = false;
    for (additional_headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "Content-Type")) {
            has_content_type = true;
            break;
        }
    }
    try headers.append(allocator, .{ .name = "Accept", .value = "application/json" });
    try headers.append(allocator, .{ .name = "Host", .value = host });
    try headers.append(allocator, .{ .name = "User-Agent", .value = "zig-aws 1.0" });
    if (!has_content_type)
        try headers.append(allocator, .{ .name = "Content-Type", .value = content_type });
    try headers.appendSlice(allocator, additional_headers);
    return null;
}

fn getEnvironmentVariable(allocator: std.mem.Allocator, key: []const u8) !?[]const u8 {
    return std.process.getEnvVarOwned(allocator, key) catch |e| switch (e) {
        std.process.GetEnvVarOwnedError.EnvironmentVariableNotFound => return null,
        else => return e,
    };
}

/// override endpoint url. Intended for use in testing. Normally, you should
/// rely on AWS_ENDPOINT_URL environment variable for this
pub var endpoint_override: ?[]const u8 = null;

fn endpointForRequest(allocator: std.mem.Allocator, service: []const u8, request: HttpRequest, options: Options) !EndPoint {
    if (endpoint_override) |override| {
        const uri = try allocator.dupe(u8, override);
        return endPointFromUri(allocator, uri, request.path);
    }
    const environment_override = try getEnvironmentVariable(allocator, "AWS_ENDPOINT_URL");
    if (environment_override) |override| {
        defer allocator.free(override);
        const uri = try allocator.dupe(u8, override);
        return endPointFromUri(allocator, uri, request.path);
    }
    // Fallback to us-east-1 if global endpoint does not exist.
    const realregion = if (std.mem.eql(u8, options.region, "aws-global")) "us-east-1" else options.region;
    const dualstack = if (options.dualstack) ".dualstack" else "";

    const domain = switch (std.hash_map.hashString(options.region)) {
        US_ISO_EAST_1_HASH => "c2s.ic.gov",
        CN_NORTH_1_HASH, CN_NORTHWEST_1_HASH => "amazonaws.com.cn",
        US_ISOB_EAST_1_HASH => "sc2s.sgov.gov",
        else => "amazonaws.com",
    };

    if (try endpointException(allocator, service, request, options, realregion, dualstack, domain)) |e|
        return e;

    const uri = try std.fmt.allocPrint(allocator, "https://{s}{s}.{s}.{s}", .{ service, dualstack, realregion, domain });
    const host = try allocator.dupe(u8, uri["https://".len..]);
    log.debug("host: {s}, scheme: {s}, port: {}", .{ host, "https", 443 });
    return EndPoint{
        .uri = uri,
        .host = host,
        .scheme = "https",
        .port = 443,
        .allocator = allocator,
        .path = try allocator.dupe(u8, request.path),
    };
}

fn endpointException(
    allocator: std.mem.Allocator,
    service: []const u8,
    request: HttpRequest,
    options: Options,
    realregion: []const u8,
    dualstack: []const u8,
    domain: []const u8,
) !?EndPoint {
    // Global endpoints (https://docs.aws.amazon.com/general/latest/gr/rande.html#global-endpoints):
    //   ✓ Amazon CloudFront
    //   AWS Global Accelerator
    //   ✓ AWS Identity and Access Management (IAM)
    //   AWS Network Manager
    //   AWS Organizations
    //   Amazon Route 53
    //   AWS Shield Advanced
    //   AWS WAF Classic

    if (std.mem.eql(u8, service, "iam")) {
        return EndPoint{
            .uri = try allocator.dupe(u8, "https://iam.amazonaws.com"),
            .host = try allocator.dupe(u8, "iam.amazonaws.com"),
            .scheme = "https",
            .port = 443,
            .allocator = allocator,
            .path = try allocator.dupe(u8, request.path),
        };
    }
    if (std.mem.eql(u8, service, "cloudfront")) {
        return EndPoint{
            .uri = try allocator.dupe(u8, "https://cloudfront.amazonaws.com"),
            .host = try allocator.dupe(u8, "cloudfront.amazonaws.com"),
            .scheme = "https",
            .port = 443,
            .allocator = allocator,
            .path = try allocator.dupe(u8, request.path),
        };
    }
    if (std.mem.eql(u8, service, "s3")) {
        if (request.path.len == 1 or std.mem.indexOf(u8, request.path[1..], "/") == null)
            return null;

        // We need to adjust the host and the path to accomodate virtual
        // host addressing. This only applies to bucket operations, but
        // right now I'm hoping that bucket operations do not include a path
        // component, so will be handled by the return null statement above.
        const bucket_name = s3BucketFromPath(request.path);
        const rest_of_path = request.path[bucket_name.len + 1 ..];
        // TODO: Implement
        _ = options;
        const uri = try std.fmt.allocPrint(allocator, "https://{s}.{s}{s}.{s}.{s}", .{ bucket_name, service, dualstack, realregion, domain });
        const host = try allocator.dupe(u8, uri["https://".len..]);
        log.debug("S3 host: {s}, scheme: {s}, port: {}", .{ host, "https", 443 });
        return EndPoint{
            .uri = uri,
            .host = host,
            .scheme = "https",
            .port = 443,
            .allocator = allocator,
            .path = try allocator.dupe(u8, rest_of_path),
        };
    }
    return null;
}

fn s3BucketFromPath(path: []const u8) []const u8 {
    var in_bucket = false;
    var start: usize = 0;
    for (path, 0..) |c, inx| {
        if (c == '/') {
            if (in_bucket) return path[start..inx];
            start = inx + 1;
            in_bucket = true;
        }
    }
    unreachable;
}
/// creates an endpoint from a uri string.
///
/// allocator: Will be used only to construct the EndPoint struct
/// uri: string constructed in such a way that deallocation is needed
fn endPointFromUri(allocator: std.mem.Allocator, uri: []const u8, path: []const u8) !EndPoint {
    const parsed_uri = try std.Uri.parse(uri);

    const scheme = parsed_uri.scheme;
    const host = try allocator.dupe(u8, parsed_uri.host.?.percent_encoded);
    const port: u16 = blk: {
        if (parsed_uri.port) |port| break :blk port;
        if (std.mem.eql(u8, scheme, "http")) break :blk 80;
        if (std.mem.eql(u8, scheme, "https")) break :blk 443;
        break :blk 0;
    };

    log.debug("host: {s}, scheme: {s}, port: {}", .{ host, scheme, port });

    return EndPoint{
        .uri = uri,
        .host = host,
        .scheme = scheme,
        .allocator = allocator,
        .port = port,
        .path = try allocator.dupe(u8, path),
    };
}

test "endpointForRequest standard operation" {
    const request: HttpRequest = .{};
    const options: Options = .{
        .region = "us-west-2",
        .dualstack = false,
        .sigv4_service_name = null,
    };
    const allocator = std.testing.allocator;
    const service = "dynamodb";

    const endpoint = try endpointForRequest(allocator, service, request, options);
    defer endpoint.deinit();
    try std.testing.expectEqualStrings("https://dynamodb.us-west-2.amazonaws.com", endpoint.uri);
}

test "endpointForRequest for cloudfront" {
    const request = HttpRequest{};
    const options = Options{
        .region = "us-west-2",
        .dualstack = false,
        .sigv4_service_name = null,
    };
    const allocator = std.testing.allocator;
    const service = "cloudfront";

    const endpoint = try endpointForRequest(allocator, service, request, options);
    defer endpoint.deinit();
    try std.testing.expectEqualStrings("https://cloudfront.amazonaws.com", endpoint.uri);
}

test "endpointForRequest for s3" {
    const request = HttpRequest{};
    const options = Options{
        .region = "us-east-2",
        .dualstack = false,
        .sigv4_service_name = null,
    };
    const allocator = std.testing.allocator;
    const service = "s3";

    const endpoint = try endpointForRequest(allocator, service, request, options);
    defer endpoint.deinit();
    try std.testing.expectEqualStrings("https://s3.us-east-2.amazonaws.com", endpoint.uri);
}
test "endpointForRequest for s3 - specific bucket" {
    const request = HttpRequest{
        .path = "/bucket/key",
    };
    const options = Options{
        .region = "us-east-2",
        .dualstack = false,
        .sigv4_service_name = null,
    };
    const allocator = std.testing.allocator;
    const service = "s3";

    const endpoint = try endpointForRequest(allocator, service, request, options);
    defer endpoint.deinit();
    try std.testing.expectEqualStrings("https://bucket.s3.us-east-2.amazonaws.com", endpoint.uri);
    try std.testing.expectEqualStrings("/key", endpoint.path);
}

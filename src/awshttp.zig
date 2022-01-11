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

const CN_NORTH_1_HASH = std.hash_map.hashString("cn-north-1");
const CN_NORTHWEST_1_HASH = std.hash_map.hashString("cn-northwest-1");
const US_ISO_EAST_1_HASH = std.hash_map.hashString("us-iso-east-1");
const US_ISOB_EAST_1_HASH = std.hash_map.hashString("us-isob-east-1");

const httplog = std.log.scoped(.awshttp);

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
};

const SigningOptions = struct {
    region: []const u8 = "aws-global",
    service: []const u8,
};

pub const HttpRequest = struct {
    path: []const u8 = "/",
    query: []const u8 = "",
    body: []const u8 = "",
    method: []const u8 = "POST",
    content_type: []const u8 = "application/json", // Can we get away with this?
    headers: []Header = &[_]Header{},
};
pub const HttpResult = struct {
    response_code: u16, // actually 3 digits can fit in u10
    body: []const u8,
    headers: []Header,
    allocator: std.mem.Allocator,

    pub fn deinit(self: HttpResult) void {
        self.allocator.free(self.body);
        for (self.headers) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        }
        self.allocator.free(self.headers);
        httplog.debug("http result deinit complete", .{});
        return;
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

const EndPoint = struct {
    uri: []const u8,
    host: []const u8,
    scheme: []const u8,
    port: u16,
    allocator: std.mem.Allocator,

    fn deinit(self: EndPoint) void {
        self.allocator.free(self.uri);
    }
};

pub const AwsHttp = struct {
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            // .credentialsProvider = // creds provider could be useful
        };
    }

    pub fn deinit(self: *AwsHttp) void {
            httplog.debug("Deinit complete", .{});
    }

    /// callApi allows the calling of AWS APIs through a higher-level interface.
    /// It will calculate the appropriate endpoint and action parameters for the
    /// service called, and will set up the signing options. The return
    /// value is simply a raw HttpResult
    pub fn callApi(self: Self, service: []const u8, request: HttpRequest, options: Options) !HttpResult {
        const endpoint = try regionSubDomain(self.allocator, service, options.region, options.dualstack);
        defer endpoint.deinit();
        httplog.debug("Calling endpoint {s}", .{endpoint.uri});
        const signing_options: SigningOptions = .{
            .region = options.region,
            .service = if (options.sigv4_service_name) |name| name else service,
        };
        return try self.makeRequest(endpoint, request, signing_options);
    }

    /// makeRequest is a low level http/https function that can be used inside
    /// or outside the context of AWS services. To use it outside AWS, simply
    /// pass a null value in for signing_options.
    ///
    /// Otherwise, it will simply take a URL endpoint (without path information),
    /// HTTP method (e.g. GET, POST, etc.), and request body.
    ///
    /// At the moment this does not allow the controlling of headers
    /// This is likely to change. Current headers are:
    ///
    /// Accept: application/json
    /// User-Agent: zig-aws 1.0, Powered by the AWS Common Runtime.
    /// Content-Type: application/x-www-form-urlencoded
    /// Content-Length: (length of body)
    ///
    /// Return value is an HttpResult, which will need the caller to deinit().
    /// HttpResult currently contains the body only. The addition of Headers
    /// and return code would be a relatively minor change
    pub fn makeRequest(self: Self, endpoint: EndPoint, request: HttpRequest, signing_options: ?SigningOptions) !HttpResult {
        httplog.debug("Path: {s}", .{request.path});
        httplog.debug("Query: {s}", .{request.query});
        httplog.debug("Method: {s}", .{request.method});
        httplog.debug("body length: {d}", .{request.body.len});
        httplog.debug("Body\n====\n{s}\n====", .{request.body});
        // End CreateRequest. This should return a struct with a deinit function that can do
        // destroys, etc

        var context = RequestContext{
            .allocator = self.allocator,
        };
        try self.addHeaders(http_request.?, host, request.body, request.content_type, request.headers);
        if (signing_options) |opts| try self.signRequest(http_request.?, opts);

        // TODO: make req
        // TODO: Timeout
        httplog.debug("request_complete. Response code {d}", .{context.response_code.?});
        httplog.debug("headers:", .{});
        for (context.headers.?.items) |h| {
            httplog.debug("    {s}: {s}", .{ h.name, h.value });
        }
        httplog.debug("raw response body:\n{s}", .{context.body});

        // Headers would need to be allocated/copied into HttpResult similar
        // to RequestContext, so we'll leave this as a later excercise
        // if it becomes necessary
        const rc = HttpResult{
            .response_code = context.response_code.?,
            .body = final_body,
            .headers = context.headers.?.toOwnedSlice(),
            .allocator = self.allocator,
        };
        return rc;
    }

    fn signRequest(self: Self, http_request: *c.aws_http_message, options: SigningOptions) !void {
        const creds = try self.getCredentials();
        httplog.debug("Signing with access key: {s}", .{c.aws_string_c_str(access_key)});

        // const signing_region = try std.fmt.allocPrintZ(self.allocator, "{s}", .{options.region});
        // defer self.allocator.free(signing_region);
        // const signing_service = try std.fmt.allocPrintZ(self.allocator, "{s}", .{options.service});
        // defer self.allocator.free(signing_service);
        // const temp_signing_config = c.bitfield_workaround_aws_signing_config_aws{
        //     .algorithm = 0, // .AWS_SIGNING_ALGORITHM_V4, // https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L38
        //     .config_type = 1, // .AWS_SIGNING_CONFIG_AWS, // https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L24
        //     .signature_type = 0, // .AWS_ST_HTTP_REQUEST_HEADERS, // https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L49
        //     .region = c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, signing_region)),
        //     .service = c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, signing_service)),
        //     .should_sign_header = null,
        //     .should_sign_header_ud = null,
        //     // TODO: S3 does not double uri encode. Also not sure why normalizing
        //     //       the path here is a flag - seems like it should always do this?
        //     .flags = c.bitfield_workaround_aws_signing_config_aws_flags{
        //         .use_double_uri_encode = 1,
        //         .should_normalize_uri_path = 1,
        //         .omit_session_token = 1,
        //     },
        //     .signed_body_value = c.aws_byte_cursor_from_c_str(""),
        //     .signed_body_header = 1, // .AWS_SBHT_X_AMZ_CONTENT_SHA256, //or 0 = AWS_SBHT_NONE // https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L131
        //     .credentials = creds,
        //     .credentials_provider = self.credentialsProvider,
        //     .expiration_in_seconds = 0,
        // };
            // return AwsError.SignableError;
    }


    fn addHeaders(self: Self, request: *c.aws_http_message, host: []const u8, body: []const u8, content_type: []const u8, additional_headers: []Header) !void {
        // const accept_header = c.aws_http_header{
        //     .name = c.aws_byte_cursor_from_c_str("Accept"),
        //     .value = c.aws_byte_cursor_from_c_str("application/json"),
        //     .compression = 0, // .AWS_HTTP_HEADER_COMPRESSION_USE_CACHE, // https://github.com/awslabs/aws-c-http/blob/ec42882310900f2b414b279fc24636ba4653f285/include/aws/http/request_response.h#L37
        // };

        // const host_header = c.aws_http_header{
        //     .name = c.aws_byte_cursor_from_c_str("Host"),
        //     .value = c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, host)),
        //     .compression = 0, // .AWS_HTTP_HEADER_COMPRESSION_USE_CACHE,
        // };

        // const user_agent_header = c.aws_http_header{
        //     .name = c.aws_byte_cursor_from_c_str("User-Agent"),
        //     .value = c.aws_byte_cursor_from_c_str("zig-aws 1.0, Powered by the AWS Common Runtime."),
        //     .compression = 0, // .AWS_HTTP_HEADER_COMPRESSION_USE_CACHE,
        // };

        // AWS *does* seem to care about Content-Type. I don't think this header
        // will hold for all APIs
        const c_type = try std.fmt.allocPrintZ(self.allocator, "{s}", .{content_type});
        defer self.allocator.free(c_type);
        const content_type_header = c.aws_http_header{
            .name = c.aws_byte_cursor_from_c_str("Content-Type"),
            .value = c.aws_byte_cursor_from_c_str(c_type),
            .compression = 0, // .AWS_HTTP_HEADER_COMPRESSION_USE_CACHE,
        };

        for (additional_headers) |h| {
            const name = try std.fmt.allocPrintZ(self.allocator, "{s}", .{h.name});
            defer self.allocator.free(name);
            const value = try std.fmt.allocPrintZ(self.allocator, "{s}", .{h.value});
            defer self.allocator.free(value);
            const c_header = c.aws_http_header{
                .name = c.aws_byte_cursor_from_c_str(name),
                .value = c.aws_byte_cursor_from_c_str(value),
                .compression = 0, // .AWS_HTTP_HEADER_COMPRESSION_USE_CACHE,
            };
            if (c.aws_http_message_add_header(request, c_header) != c.AWS_OP_SUCCESS)
                return AwsError.AddHeaderError;
        }

        if (body.len > 0) {
            const len = try std.fmt.allocPrintZ(self.allocator, "{d}", .{body.len});
            // This defer seems to work ok, but I'm a bit concerned about why
            defer self.allocator.free(len);
            const content_length_header = c.aws_http_header{
                .name = c.aws_byte_cursor_from_c_str("Content-Length"),
                .value = c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, len)),
                .compression = 0, // .AWS_HTTP_HEADER_COMPRESSION_USE_CACHE,
            };
            if (c.aws_http_message_add_header(request, content_length_header) != c.AWS_OP_SUCCESS)
                return AwsError.AddHeaderError;
        }
    }


    fn getCredentials(self: Self) !*c.aws_credentials {
        // const get_async_result =
        _ = c.aws_credentials_provider_get_credentials(self.credentialsProvider, callback, &callback_results);

        if (credential_result.error_code != c.AWS_ERROR_SUCCESS) {
            httplog.err("Could not acquire credentials: {s}:{s}", .{ c.aws_error_name(credential_result.error_code), c.aws_error_str(credential_result.error_code) });
            return AwsError.CredentialsError;
        }
        return credential_result.result orelse unreachable;
    }
};

fn fullCast(comptime T: type, val: anytype) T {
    return @ptrCast(T, @alignCast(@alignOf(T), val));
}

fn regionSubDomain(allocator: std.mem.Allocator, service: []const u8, region: []const u8, useDualStack: bool) !EndPoint {
    const environment_override = std.os.getenv("AWS_ENDPOINT_URL");
    if (environment_override) |override| {
        const uri = try allocator.dupeZ(u8, override);
        return endPointFromUri(allocator, uri);
    }
    // Fallback to us-east-1 if global endpoint does not exist.
    const realregion = if (std.mem.eql(u8, region, "aws-global")) "us-east-1" else region;
    const dualstack = if (useDualStack) ".dualstack" else "";

    const domain = switch (std.hash_map.hashString(region)) {
        US_ISO_EAST_1_HASH => "c2s.ic.gov",
        CN_NORTH_1_HASH, CN_NORTHWEST_1_HASH => "amazonaws.com.cn",
        US_ISOB_EAST_1_HASH => "sc2s.sgov.gov",
        else => "amazonaws.com",
    };

    const uri = try std.fmt.allocPrintZ(allocator, "https://{s}{s}.{s}.{s}", .{ service, dualstack, realregion, domain });
    const host = uri["https://".len..];
    httplog.debug("host: {s}, scheme: {s}, port: {}", .{ host, "https", 443 });
    return EndPoint{
        .uri = uri,
        .host = host,
        .scheme = "https",
        .port = 443,
        .allocator = allocator,
    };
}

/// creates an endpoint from a uri string.
///
/// allocator: Will be used only to construct the EndPoint struct
/// uri: string constructed in such a way that deallocation is needed
fn endPointFromUri(allocator: std.mem.Allocator, uri: []const u8) !EndPoint {
    var scheme: []const u8 = "";
    var host: []const u8 = "";
    var port: u16 = 443;
    var host_start: usize = 0;
    var host_end: usize = 0;
    for (uri) |ch, i| {
        switch (ch) {
            ':' => {
                if (!std.mem.eql(u8, scheme, "")) {
                    // here to end is port - this is likely a bug if ipv6 address used
                    const rest_of_uri = uri[i + 1 ..];
                    port = try std.fmt.parseUnsigned(u16, rest_of_uri, 10);
                    host_end = i;
                }
            },
            '/' => {
                if (host_start == 0) {
                    host_start = i + 2;
                    scheme = uri[0 .. i - 1];
                    if (std.mem.eql(u8, scheme, "http")) {
                        port = 80;
                    } else {
                        port = 443;
                    }
                }
            },
            else => continue,
        }
    }
    if (host_end == 0) {
        host_end = uri.len;
    }
    host = uri[host_start..host_end];

    httplog.debug("host: {s}, scheme: {s}, port: {}", .{ host, scheme, port });
    return EndPoint{
        .uri = uri,
        .host = host,
        .scheme = scheme,
        .allocator = allocator,
        .port = port,
    };
}

const RequestContext = struct {
    connection: ?*c.aws_http_connection = null,
    connection_complete: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),
    request_complete: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),
    return_error: ?AwsError = null,
    allocator: std.mem.Allocator,
    body: ?[]const u8 = null,
    response_code: ?u16 = null,
    headers: ?std.ArrayList(Header) = null,

    const Self = @This();

    pub fn deinit(self: Self) void {
        // We're going to leave it to the caller to free the body
        // if (self.body) |b| self.allocator.free(b);
        if (self.headers) |hs| {
            for (hs.items) |h| {
                // deallocate the copied values
                self.allocator.free(h.name);
                self.allocator.free(h.value);
            }
            // deallocate the structure itself
            hs.deinit();
        }
    }

    pub fn appendToBody(self: *Self, fragment: []const u8) !void {
        var orig_body: []const u8 = "";
        if (self.body) |b| {
            orig_body = try self.allocator.dupe(u8, b);
            self.allocator.free(b);
            self.body = null;
        }
        defer self.allocator.free(orig_body);
        self.body = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ orig_body, fragment });
    }

    pub fn addHeader(self: *Self, name: []const u8, value: []const u8) !void {
        if (self.headers == null)
            self.headers = std.ArrayList(Header).init(self.allocator);

        const name_copy = try self.allocator.dupeZ(u8, name);
        const value_copy = try self.allocator.dupeZ(u8, value);

        try self.headers.?.append(.{
            .name = name_copy,
            .value = value_copy,
        });
    }
};

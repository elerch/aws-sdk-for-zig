const std = @import("std");
const base = @import("aws_http_base.zig");
const auth = @import("aws_authentication.zig");
const date = @import("date.zig");

const scoped_log = std.log.scoped(.aws_signing);

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
// TODO: Remove this?! This is an aws_signing, so we should know a thing
//       or two about aws. So perhaps the right level of abstraction here
//       is to have our service signing idiosyncracies dealt with in this
//       code base. Pretty much all these flags are specific to use with S3
//       except omit_session_token, which will likely apply to serveral services,
//       just not sure which one yet. I'll leave this here, commented for now
//       in case we need to revisit the decision
//
// see https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L186-L207
// pub const ConfigFlags = packed struct {
//     // We assume the uri will be encoded once in preparation for transmission.  Certain services
//     // do not decode before checking signature, requiring us to actually double-encode the uri in the canonical
//     // request in order to pass a signature check.
//
//     use_double_uri_encode: bool = true,
//
//     // Controls whether or not the uri paths should be normalized when building the canonical request
//     should_normalize_uri_path: bool = true,
//
//     // Controls whether "X-Amz-Security-Token" is omitted from the canonical request.
//     // "X-Amz-Security-Token" is added during signing, as a header or
//     // query param, when credentials have a session token.
//     // If false (the default), this parameter is included in the canonical request.
//     // If true, this parameter is still added, but omitted from the canonical request.
//     omit_session_token: bool = true,
// };
pub const Credentials = auth.Credentials;

pub const Config = struct {
    // These two should be all you need to set most of the time
    service: []const u8,
    credentials: Credentials,

    region: []const u8 = "aws-global",
    // https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L38
    algorithm: enum { v4, v4a } = .v4,
    // https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L24
    // config_type: ?? // CRT only has one value. We'll ignore for now

    // https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L49
    signature_type: enum {
        headers, // we only support this
        query_params,
        request_chunk,
        request_event, // not implemented by CRT
        canonical_request_headers,
        canonical_request_query_params,
    } = .headers,

    /// Used for testing. If null, will use current time
    signing_time: ?i64 = null,

    // In the CRT, should_sign_header is a function to allow header filtering.
    // The _ud would be a anyopaque user defined data for the function to use
    //     .should_sign_header = null,
    //     .should_sign_header_ud = null,

    // In the CRT, this is only used if the body has been precalculated. We don't have
    // this use case, and we'll ignore
    //     .signed_body_value = c.aws_byte_cursor_from_c_str(""),
    signed_body_header: SignatureType = .sha256, // https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L131

    // This is more complex in the CRT. We'll just take the creds. Someone
    // else can use a provider and get them in advance
    // https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L225-L251
    // If non-zero and the signing transform is query param, then signing will add X-Amz-Expires to the query
    // string, equal to the value specified here.  If this value is zero or if header signing is being used then
    // this parameter has no effect.
    expiration_in_seconds: u64 = 0,

    // flags: ConfigFlags = .{},
};

pub const SignatureType = enum { sha256, none };
pub const SigningError = error{
    NotImplemented,
    S3NotImplemented,

    // There are a number of forbidden headers that the signing process
    // basically "owns". For clarity, and because zig does not have a way
    // to provide an error message
    //
    /// Used if the request headers already includes X-Amz-Date
    /// If a specific date is required, use a specific signing_time in config
    XAmzDateHeaderInRequest,
    /// Used if the request headers already includes Authorization
    AuthorizationHeaderInRequest,
    /// Used if the request headers already includes x-amz-content-sha256
    XAmzContentSha256HeaderInRequest,
    /// Used if the request headers already includes x-amz-signature
    XAmzSignatureHeaderInRequest,
    /// Used if the request headers already includes x-amz-algorithm
    XAmzAlgorithmHeaderInRequest,
    /// Used if the request headers already includes x-amz-credential
    XAmzCredentialHeaderInRequest,
    /// Used if the request headers already includes x-amz-signedheaders
    XAmzSignedHeadersHeaderInRequest,
    /// Used if the request headers already includes x-amz-security-token
    XAmzSecurityTokenHeaderInRequest,
    /// Used if the request headers already includes x-amz-expires
    XAmzExpiresHeaderInRequest,
    /// Used if the request headers already includes x-amz-region-set
    XAmzRegionSetHeaderInRequest,
} || std.fmt.AllocPrintError;

const forbidden_headers = .{
    .{ .name = "x-amz-content-sha256", .err = SigningError.XAmzContentSha256HeaderInRequest },
    .{ .name = "Authorization", .err = SigningError.AuthorizationHeaderInRequest },
    .{ .name = "X-Amz-Signature", .err = SigningError.XAmzSignatureHeaderInRequest },
    .{ .name = "X-Amz-Algorithm", .err = SigningError.XAmzAlgorithmHeaderInRequest },
    .{ .name = "X-Amz-Credential", .err = SigningError.XAmzCredentialHeaderInRequest },
    .{ .name = "X-Amz-Date", .err = SigningError.XAmzDateHeaderInRequest },
    .{ .name = "X-Amz-SignedHeaders", .err = SigningError.XAmzSignedHeadersHeaderInRequest },
    .{ .name = "X-Amz-Security-Token", .err = SigningError.XAmzSecurityTokenHeaderInRequest },
    .{ .name = "X-Amz-Expires", .err = SigningError.XAmzExpiresHeaderInRequest },
    .{ .name = "X-Amz-Region-Set", .err = SigningError.XAmzRegionSetHeaderInRequest },
};

const skipped_headers = .{
    "x-amzn-trace-id",
    "User-Agent",
    "connection",
    "sec-websocket-key",
    "sec-websocket-protocol",
    "sec-websocket-version",
    "upgrade",
};

/// Signs a request. Only header signing is currently supported. Note that
/// This adds two headers to the request, which will need to be freed by the
/// caller. Use freeSignedRequest with the same parameters to free
pub fn signRequest(allocator: std.mem.Allocator, request: base.Request, config: Config) SigningError!base.Request {
    try validateConfig(config);
    for (request.headers) |h| {
        inline for (forbidden_headers) |f| {
            if (std.ascii.eqlIgnoreCase(h.name, f.name))
                return f.err;
        }
    }
    var rc = request;

    const signing_time = config.signing_time orelse std.time.timestamp();

    const signed_date = date.timestampToDateTime(signing_time);

    const signing_iso8601 = try std.fmt.allocPrint(
        allocator,
        "{:0>4}{:0>2}{:0>2}T{:0>2}{:0>2}{:0>2}Z",
        .{
            signed_date.year,
            signed_date.month,
            signed_date.day,
            signed_date.hour,
            signed_date.minute,
            signed_date.second,
        },
    );
    errdefer freeSignedRequest(allocator, &rc, config);

    var additional_header_count: u3 = 3;
    if (config.credentials.session_token != null)
        additional_header_count += 1;
    if (config.signed_body_header == .none)
        additional_header_count -= 1;
    const newheaders = try allocator.alloc(std.http.Header, rc.headers.len + additional_header_count);
    errdefer allocator.free(newheaders);
    const oldheaders = rc.headers;
    if (config.credentials.session_token) |t| {
        newheaders[newheaders.len - additional_header_count] = std.http.Header{
            .name = "X-Amz-Security-Token",
            .value = try allocator.dupe(u8, t),
        };
        additional_header_count -= 1;
    }
    errdefer freeSignedRequest(allocator, &rc, config);
    @memcpy(newheaders[0..oldheaders.len], oldheaders);
    newheaders[newheaders.len - additional_header_count] = std.http.Header{
        .name = "X-Amz-Date",
        .value = signing_iso8601,
    };
    additional_header_count -= 1;

    // We always need the sha256 of the payload for the signature,
    // regardless of whether we're sticking the header on the request
    std.debug.assert(config.signed_body_header == .none or
        config.signed_body_header == .sha256);
    const payload_hash = try hash(allocator, request.body, .sha256);
    if (config.signed_body_header == .sha256) {
        // From the AWS nitro enclaves SDK, it appears that there is no reason
        // to avoid *ALWAYS* adding the x-amz-content-sha256 header
        // https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/9ecb83d07fe953636e3c0b861d6dac0a15d00f82/source/rest.c#L464
        // However, for signature verification, we need to accomodate clients that
        // may not add this header
        // This will be freed in freeSignedRequest
        // defer allocator.free(payload_hash);
        newheaders[newheaders.len - additional_header_count] = std.http.Header{
            .name = "x-amz-content-sha256",
            .value = payload_hash,
        };
        additional_header_count -= 1;
    }

    rc.headers = newheaders[0 .. newheaders.len - 1];
    log.debug("Signing with access key: {s}", .{config.credentials.access_key});
    const canonical_request = try createCanonicalRequest(allocator, rc, payload_hash, config);
    defer {
        allocator.free(canonical_request.arr);
        allocator.free(canonical_request.hash);
        allocator.free(canonical_request.headers.str);
        allocator.free(canonical_request.headers.signed_headers);
    }
    log.debug("Canonical request:\n{s}", .{canonical_request.arr});
    log.debug("Canonical request hash: {s}", .{canonical_request.hash});
    const scope = try std.fmt.allocPrint(
        allocator,
        "{:0>4}{:0>2}{:0>2}/{s}/{s}/aws4_request",
        .{
            signed_date.year,
            signed_date.month,
            signed_date.day,
            config.region,
            config.service,
        },
    );
    defer allocator.free(scope);
    log.debug("Scope: {s}", .{scope});

    //Algorithm + \n +
    //RequestDateTime + \n +
    //CredentialScope + \n +
    //HashedCanonicalRequest
    const string_to_sign_fmt =
        \\AWS4-HMAC-SHA256
        \\{s}
        \\{s}
        \\{s}
    ;
    const string_to_sign = try std.fmt.allocPrint(
        allocator,
        string_to_sign_fmt,
        .{
            signing_iso8601,
            scope,
            canonical_request.hash,
        },
    );
    defer allocator.free(string_to_sign);
    log.debug("String to sign:\n{s}", .{string_to_sign});

    const signing_key = try getSigningKey(allocator, scope[0..8], config);
    defer allocator.free(signing_key);

    const signature = try hmac(allocator, signing_key, string_to_sign);
    defer allocator.free(signature);
    newheaders[newheaders.len - 1] = std.http.Header{
        .name = "Authorization",
        .value = try std.fmt.allocPrint(
            allocator,
            "AWS4-HMAC-SHA256 Credential={s}/{s}, SignedHeaders={s}, Signature={s}",
            .{
                config.credentials.access_key,
                scope,
                canonical_request.headers.signed_headers,
                std.fmt.fmtSliceHexLower(signature),
            },
        ),
    };
    rc.headers = newheaders;
    return rc;
}

/// Frees allocated resources for the request, including the headers array
pub fn freeSignedRequest(allocator: std.mem.Allocator, request: *base.Request, config: Config) void {
    validateConfig(config) catch |e| {
        log.err("Signing validation failed during signature free: {}", .{e});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        return;
    };

    for (request.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "X-Amz-Date") or
            std.ascii.eqlIgnoreCase(h.name, "Authorization") or
            std.ascii.eqlIgnoreCase(h.name, "X-Amz-Security-Token") or
            std.ascii.eqlIgnoreCase(h.name, "x-amz-content-sha256"))
            allocator.free(h.value);
    }

    allocator.free(request.headers);
}

pub const credentialsFn = *const fn ([]const u8) ?Credentials;

pub fn verifyServerRequest(allocator: std.mem.Allocator, request: *std.http.Server.Request, request_body_reader: anytype, credentials_fn: credentialsFn) !bool {
    var unverified_request = try UnverifiedRequest.init(allocator, request);
    defer unverified_request.deinit();
    return verify(allocator, unverified_request, request_body_reader, credentials_fn);
}

pub const UnverifiedRequest = struct {
    headers: []const std.http.Header,
    target: []const u8,
    method: std.http.Method,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, request: *std.http.Server.Request) !UnverifiedRequest {
        var al = std.ArrayList(std.http.Header).init(allocator);
        defer al.deinit();
        var it = request.iterateHeaders();
        while (it.next()) |h| try al.append(h);
        return .{
            .target = request.head.target,
            .method = request.head.method,
            .headers = try al.toOwnedSlice(),
            .allocator = allocator,
        };
    }

    pub fn getFirstHeaderValue(self: UnverifiedRequest, name: []const u8) ?[]const u8 {
        for (self.headers) |*h| {
            if (std.ascii.eqlIgnoreCase(name, h.name))
                return h.value; // I don't think this is the whole story here, but should suffice for now
            // We need to return the value before the first ';' IIRC
        }
        return null;
    }

    pub fn deinit(self: *UnverifiedRequest) void {
        self.allocator.free(self.headers);
    }
};

pub fn verify(allocator: std.mem.Allocator, request: UnverifiedRequest, request_body_reader: anytype, credentials_fn: credentialsFn) !bool {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    // Authorization: AWS4-HMAC-SHA256 Credential=ACCESS/20230908/us-west-2/s3/aws4_request, SignedHeaders=accept;content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, Signature=fcc43ce73a34c9bd1ddf17e8a435f46a859812822f944f9eeb2aabcd64b03523
    const auth_header_or_null = request.getFirstHeaderValue("Authorization");
    const auth_header = if (auth_header_or_null) |a| a else return error.AuthorizationHeaderMissing;
    if (!std.mem.startsWith(u8, auth_header, "AWS4-HMAC-SHA256")) return error.UnsupportedAuthorizationType;
    var credential: ?[]const u8 = null;
    var signed_headers: ?[]const u8 = null;
    var signature: ?[]const u8 = null;
    var split_iterator = std.mem.splitSequence(u8, auth_header, " ");
    while (split_iterator.next()) |auth_part| {
        // NOTE: auth_part likely to end with ,
        if (std.ascii.startsWithIgnoreCase(auth_part, "Credential=")) {
            credential = std.mem.trim(u8, auth_part["Credential=".len..], ",");
            continue;
        }
        if (std.ascii.startsWithIgnoreCase(auth_part, "SignedHeaders=")) {
            signed_headers = std.mem.trim(u8, auth_part["SignedHeaders=".len..], ",");
            continue;
        }
        if (std.ascii.startsWithIgnoreCase(auth_part, "Signature=")) {
            signature = std.mem.trim(u8, auth_part["Signature=".len..], ",");
            continue;
        }
    }
    if (credential == null) return error.AuthorizationHeaderMissingCredential;
    if (signed_headers == null) return error.AuthorizationHeaderMissingSignedHeaders;
    if (signature == null) return error.AuthorizationHeaderMissingSignature;
    return verifyParsedAuthorization(
        aa,
        request,
        request_body_reader,
        credential.?,
        signed_headers.?,
        signature.?,
        credentials_fn,
    );
}

fn verifyParsedAuthorization(
    allocator: std.mem.Allocator,
    request: UnverifiedRequest,
    request_body_reader: anytype,
    credential: []const u8,
    signed_headers: []const u8,
    signature: []const u8,
    credentials_fn: credentialsFn,
) !bool {
    // AWS4-HMAC-SHA256
    // Credential=ACCESS/20230908/us-west-2/s3/aws4_request
    // SignedHeaders=accept;content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class
    // Signature=fcc43ce73a34c9bd1ddf17e8a435f46a859812822f944f9eeb2aabcd64b03523
    var credential_iterator = std.mem.splitScalar(u8, credential, '/');
    const access_key = credential_iterator.next().?;
    const credentials = credentials_fn(access_key) orelse return error.CredentialsNotFound;
    // TODO: https://stackoverflow.com/questions/29276609/aws-authentication-requires-a-valid-date-or-x-amz-date-header-curl
    // For now I want to see this test pass
    const normalized_iso_date = request.getFirstHeaderValue("x-amz-date") orelse
        request.getFirstHeaderValue("Date").?;
    log.debug("Got date: {s}", .{normalized_iso_date});
    _ = credential_iterator.next().?; // skip the date...I don't think we need this
    const region = credential_iterator.next().?;
    const service = credential_iterator.next().?;
    const aws4_request = credential_iterator.next().?;
    if (!std.mem.eql(u8, aws4_request, "aws4_request")) return error.UnexpectedCredentialValue;
    var config = Config{
        .service = service,
        .credentials = credentials,
        .region = region,
        .algorithm = .v4,
        .signature_type = .headers,
        .signed_body_header = .none,
        .expiration_in_seconds = 0,
        .signing_time = try date.dateTimeToTimestamp(try date.parseIso8601ToDateTime(normalized_iso_date)),
    };

    var headers = try allocator.alloc(std.http.Header, std.mem.count(u8, signed_headers, ";") + 1);
    defer allocator.free(headers);
    var signed_headers_iterator = std.mem.splitSequence(u8, signed_headers, ";");
    var inx: usize = 0;
    while (signed_headers_iterator.next()) |signed_header| {
        if (std.ascii.eqlIgnoreCase(signed_header, "x-amz-content-sha256"))
            config.signed_body_header = .sha256;
        var is_forbidden = false;
        inline for (forbidden_headers) |forbidden| {
            if (std.ascii.eqlIgnoreCase(forbidden.name, signed_header)) {
                is_forbidden = true;
                break;
            }
        }
        if (is_forbidden) continue;
        headers[inx] = .{
            .name = signed_header,
            .value = request.getFirstHeaderValue(signed_header).?,
        };
        inx += 1;
    }
    var target_iterator = std.mem.splitSequence(u8, request.target, "?");
    var signed_request = base.Request{
        .path = target_iterator.first(),
        .headers = headers[0..inx],
        .method = @tagName(request.method),
        .content_type = request.getFirstHeaderValue("content-type").?,
    };
    signed_request.query = request.target[signed_request.path.len..]; // TODO: should this be +1? query here would include '?'
    signed_request.body = try request_body_reader.readAllAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(signed_request.body);
    signed_request = try signRequest(allocator, signed_request, config);
    defer freeSignedRequest(allocator, &signed_request, config);
    return verifySignedRequest(signed_request, signature);
}

fn verifySignedRequest(signed_request: base.Request, signature: []const u8) !bool {
    // We're not doing a lot of error checking here...we are all in control of this code
    const auth_header = blk: {
        for (signed_request.headers) |header| {
            if (std.mem.eql(u8, header.name, "Authorization"))
                break :blk header.value;
        }
        break :blk null;
    };
    var split_iterator = std.mem.splitSequence(u8, auth_header.?, " ");
    const calculated_signature = blk: {
        while (split_iterator.next()) |auth_part| {
            if (std.ascii.startsWithIgnoreCase(auth_part, "Signature=")) {
                break :blk std.mem.trim(u8, auth_part["Signature=".len..], ",");
            }
        }
        break :blk null;
    };
    log.debug(
        \\Signature Verification
        \\Request Signature: {s}
        \\Calculated Signat: {s}
    , .{ signature, calculated_signature.? });
    return std.mem.eql(u8, signature, calculated_signature.?);
}

fn getSigningKey(allocator: std.mem.Allocator, signing_date: []const u8, config: Config) ![]const u8 {
    // TODO: This is designed for lots of caching. We need to work that out
    // kSecret = your secret access key
    // kDate = HMAC("AWS4" + kSecret, Date)
    // kRegion = HMAC(kDate, Region)
    // kService = HMAC(kRegion, Service)
    // kSigning = HMAC(kService, "aws4_request")
    log.debug(
        \\signing key params:
        \\  key: (you wish)
        \\  date: {s}
        \\  region: {s}
        \\  service: {s}
    , .{ signing_date, config.region, config.service });
    const secret = try std.fmt.allocPrint(allocator, "AWS4{s}", .{config.credentials.secret_key});
    defer {
        // secureZero avoids compiler optimizations that may say
        // "WTF are you doing this thing? Looks like nothing to me. It's silly and we will remove it"
        std.crypto.utils.secureZero(u8, secret); // zero our copy of secret
        allocator.free(secret);
    }
    // log.debug("secret: {s}", .{secret});
    const k_date = try hmac(allocator, secret, signing_date);
    defer allocator.free(k_date);
    const k_region = try hmac(allocator, k_date, config.region);
    defer allocator.free(k_region);
    const k_service = try hmac(allocator, k_region, config.service);
    defer allocator.free(k_service);
    const k_signing = try hmac(allocator, k_service, "aws4_request");
    return k_signing;
}
fn validateConfig(config: Config) SigningError!void {
    if (config.signature_type != .headers or
        config.expiration_in_seconds != 0 or
        config.algorithm != .v4)
        return SigningError.NotImplemented;
}

fn hmac(allocator: std.mem.Allocator, key: []const u8, data: []const u8) ![]const u8 {
    var out: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(out[0..], data, key);
    return try allocator.dupe(u8, out[0..]);
}
const Hashed = struct {
    arr: []const u8,
    hash: []const u8,
    headers: CanonicalHeaders,
};

fn createCanonicalRequest(allocator: std.mem.Allocator, request: base.Request, payload_hash: []const u8, config: Config) !Hashed {
    // CanonicalRequest =
    // HTTPRequestMethod + '\n' +
    // CanonicalURI + '\n' +
    // CanonicalQueryString + '\n' +
    // CanonicalHeaders + '\n' +
    // SignedHeaders + '\n' +
    // HexEncode(Hash(RequestPayload))
    const fmt =
        \\{s}
        \\{s}
        \\{s}
        \\{s}
        \\{s}
        \\{s}
    ;

    // TODO: This is all better as a writer - less allocations/copying
    const canonical_method = try canonicalRequestMethod(request.method);
    // Let's not mess around here...s3 is the oddball
    const double_encode = !std.mem.eql(u8, config.service, "s3");
    const canonical_url = try canonicalUri(allocator, request.path, double_encode);
    defer allocator.free(canonical_url);
    log.debug("final uri: {s}", .{canonical_url});
    const canonical_query = try canonicalQueryString(allocator, request.query);
    defer allocator.free(canonical_query);
    log.debug("canonical query: {s}", .{canonical_query});
    const canonical_headers = try canonicalHeaders(allocator, request.headers, config.service);

    const canonical_request = try std.fmt.allocPrint(allocator, fmt, .{
        canonical_method,
        canonical_url,
        canonical_query,
        canonical_headers.str,
        canonical_headers.signed_headers,
        payload_hash,
    });
    errdefer allocator.free(canonical_request);
    log.debug("Canonical_request (just calculated):\n{s}", .{canonical_request});
    const hashed = try hash(allocator, canonical_request, .sha256);
    return Hashed{
        .arr = canonical_request,
        .hash = hashed,
        .headers = canonical_headers,
    };
}

fn canonicalRequestMethod(method: []const u8) ![]const u8 {
    return method; // We assume it's good
}

fn canonicalUri(allocator: std.mem.Allocator, path: []const u8, double_encode: bool) ![]const u8 {
    // Add the canonical URI parameter, followed by a newline character. The
    // canonical URI is the URI-encoded version of the absolute path component
    // of the URI, which is everything in the URI from the HTTP host to the
    // question mark character ("?") that begins the query string parameters (if any).
    //
    // Normalize URI paths according to RFC 3986. Remove redundant and relative
    // path components. Each path segment must be URI-encoded twice
    // (except for Amazon S3 which only gets URI-encoded once).
    //
    // Note: In exception to this, you do not normalize URI paths for requests
    // to Amazon S3. For example, if you have a bucket with an object
    // named my-object//example//photo.user, use that path. Normalizing
    // the path to my-object/example/photo.user will cause the request to
    // fail. For more information, see Task 1: Create a Canonical Request in
    // the Amazon Simple Storage Service API Reference.
    //
    // If the absolute path is empty, use a forward slash (/)
    //
    // For now, we will "Remove redundant and relative path components". This
    // doesn't apply to S3 anyway, and we'll make it the callers's problem
    if (path.len == 0 or path[0] == '?' or path[0] == '#')
        return try allocator.dupe(u8, "/");
    log.debug("encoding path: {s}", .{path});
    var encoded_once = try encodeUri(allocator, path);
    log.debug("encoded path (1): {s}", .{encoded_once});
    if (!double_encode or std.mem.indexOf(u8, path, "%") != null) { // TODO: Is the indexOf condition universally true?
        if (std.mem.lastIndexOf(u8, encoded_once, "?")) |i| {
            _ = allocator.resize(encoded_once, i);
            return encoded_once[0..i];
        }
        return encoded_once;
    }
    defer allocator.free(encoded_once);
    var encoded_twice = try encodeUri(allocator, encoded_once);
    defer allocator.free(encoded_twice);
    log.debug("encoded path (2): {s}", .{encoded_twice});
    if (std.mem.lastIndexOf(u8, encoded_twice, "?")) |i| {
        return try allocator.dupe(u8, encoded_twice[0..i]);
    }
    return try allocator.dupe(u8, encoded_twice);
}

fn encodeParamPart(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const unreserved_marks = "-_.!~*'()";
    var encoded = try std.ArrayList(u8).initCapacity(allocator, path.len);
    defer encoded.deinit();
    for (path) |c| {
        var should_encode = true;
        for (unreserved_marks) |r|
            if (r == c) {
                should_encode = false;
                break;
            };
        if (should_encode and std.ascii.isAlphanumeric(c))
            should_encode = false;

        if (!should_encode) {
            try encoded.append(c);
            continue;
        }
        // Whatever remains, encode it
        try encoded.append('%');
        const hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexUpper(&[_]u8{c})});
        defer allocator.free(hex);
        try encoded.appendSlice(hex);
    }
    return encoded.toOwnedSlice();
}

// URI encode every byte except the unreserved characters:
//   'A'-'Z', 'a'-'z', '0'-'9', '-', '.', '_', and '~'.
//
// The space character is a reserved character and must be encoded as "%20"
// (and not as "+").
//
// Each URI encoded byte is formed by a '%' and the two-digit hexadecimal value of the byte.
//
// Letters in the hexadecimal value must be uppercase, for example "%1A".
//
// Encode the forward slash character, '/', everywhere except in the object key
// name. For example, if the object key name is photos/Jan/sample.jpg, the
// forward slash in the key name is not encoded.

fn encodeUri(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const reserved_characters = ";,/?:@&=+$#";
    const unreserved_marks = "-_.!~*'()";
    var encoded = try std.ArrayList(u8).initCapacity(allocator, path.len);
    defer encoded.deinit();
    // if (std.mem.startsWith(u8, path, "/2017-03-31/tags/arn")) {
    //     try encoded.appendSlice("/2017-03-31/tags/arn%25253Aaws%25253Alambda%25253Aus-west-2%25253A550620852718%25253Afunction%25253Aawsome-lambda-LambdaStackawsomeLambda");
    //     return encoded.toOwnedSlice();
    // }
    for (path) |c| {
        var should_encode = true;
        for (reserved_characters) |r|
            if (r == c) {
                should_encode = false;
                break;
            };
        if (should_encode) {
            for (unreserved_marks) |r|
                if (r == c) {
                    should_encode = false;
                    break;
                };
        }
        if (should_encode and std.ascii.isAlphanumeric(c))
            should_encode = false;

        if (!should_encode) {
            try encoded.append(c);
            continue;
        }
        // Whatever remains, encode it
        try encoded.append('%');
        const hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexUpper(&[_]u8{c})});
        defer allocator.free(hex);
        try encoded.appendSlice(hex);
    }
    return encoded.toOwnedSlice();
}

fn canonicalQueryString(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    //     To construct the canonical query string, complete the following steps:
    //
    //     Sort the parameter names by character code point in ascending order.
    //     Parameters with duplicate names should be sorted by value. For example,
    //     a parameter name that begins with the uppercase letter F precedes a
    //     parameter name that begins with a lowercase letter b.
    //
    //     URI-encode each parameter name and value according to the following rules:
    //
    //         Do not URI-encode any of the unreserved characters that RFC 3986
    //         defines: A-Z, a-z, 0-9, hyphen ( - ), underscore ( _ ), period ( . ), and tilde ( ~ ).
    //
    //         Percent-encode all other characters with %XY, where X and Y are
    //         hexadecimal characters (0-9 and uppercase A-F). For example, the
    //         space character must be encoded as %20 (not using '+', as some
    //         encoding schemes do) and extended UTF-8 characters must be in the
    //         form %XY%ZA%BC.
    //
    //         Double-encode any equals ( = ) characters in parameter values.
    //
    //     Build the canonical query string by starting with the first parameter
    //     name in the sorted list.
    //
    //     For each parameter, append the URI-encoded parameter name, followed by
    //     the equals sign character (=), followed by the URI-encoded parameter
    //     value. Use an empty string for parameters that have no value.
    //
    //     Append the ampersand character (&) after each parameter value, except
    //     for the last value in the list.
    //
    // One option for the query API is to put all request parameters in the query
    // string. For example, you can do this for Amazon S3 to create a presigned
    // URL. In that case, the canonical query string must include not only
    // parameters for the request, but also the parameters used as part of the
    // signing process—the hashing algorithm, credential scope, date, and signed
    // headers parameters.
    //
    // The following example shows a query string that includes authentication
    // information. The example is formatted with line breaks for readability, but
    // the canonical query string must be one continuous line of text in your code.
    const first_question = std.mem.indexOf(u8, path, "?");
    if (first_question == null)
        return try allocator.dupe(u8, "");

    // We have a query string
    const query = path[first_question.? + 1 ..];

    // Split this by component
    var portions = std.mem.splitScalar(u8, query, '&');
    var sort_me = std.ArrayList([]const u8).init(allocator);
    defer sort_me.deinit();
    while (portions.next()) |item|
        try sort_me.append(item);
    std.sort.pdq([]const u8, sort_me.items, {}, lessThanBinary);

    var normalized = try std.ArrayList(u8).initCapacity(allocator, path.len);
    defer normalized.deinit();
    var first = true;
    for (sort_me.items) |i| {
        if (!first) try normalized.append('&');
        first = false;
        const first_equals = std.mem.indexOf(u8, i, "=");
        if (first_equals == null) {
            // Rare. This is "foo="
            const normed_item = try encodeUri(allocator, i);
            defer allocator.free(normed_item);
            try normalized.appendSlice(i); // This should be encoded
            try normalized.append('=');
            continue;
        }

        // normal key=value stuff
        const key = try encodeParamPart(allocator, i[0..first_equals.?]);
        defer allocator.free(key);

        const value = try encodeParamPart(allocator, i[first_equals.? + 1 ..]);
        defer allocator.free(value);
        // Double-encode any = in the value. But not anything else?
        const weird_equals_in_value_thing = try replace(allocator, value, "%3D", "%253D");
        defer allocator.free(weird_equals_in_value_thing);
        try normalized.appendSlice(key);
        try normalized.append('=');
        try normalized.appendSlice(weird_equals_in_value_thing);
    }

    return normalized.toOwnedSlice();
}

fn replace(allocator: std.mem.Allocator, haystack: []const u8, needle: []const u8, replacement_value: []const u8) ![]const u8 {
    const buffer = try allocator.alloc(u8, std.mem.replacementSize(u8, haystack, needle, replacement_value));
    _ = std.mem.replace(u8, haystack, needle, replacement_value, buffer);
    return buffer;
}

fn lessThanBinary(context: void, lhs: []const u8, rhs: []const u8) bool {
    _ = context;
    return std.mem.lessThan(u8, lhs, rhs);
}
const CanonicalHeaders = struct {
    str: []const u8,
    signed_headers: []const u8,
};
fn canonicalHeaders(allocator: std.mem.Allocator, headers: []const std.http.Header, service: []const u8) !CanonicalHeaders {
    //
    // Doc example. Original:
    //
    // Host:iam.amazonaws.com\n
    // Content-Type:application/x-www-form-urlencoded; charset=utf-8\n
    // My-header1:    a   b   c  \n
    // X-Amz-Date:20150830T123600Z\n
    // My-Header2:    "a   b   c"  \n
    //
    // Canonical form:
    // content-type:application/x-www-form-urlencoded; charset=utf-8\n
    // host:iam.amazonaws.com\n
    // my-header1:a b c\n
    // my-header2:"a b c"\n
    // x-amz-date:20150830T123600Z\n
    var dest = try std.ArrayList(std.http.Header).initCapacity(allocator, headers.len);
    defer {
        for (dest.items) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        dest.deinit();
    }
    var total_len: usize = 0;
    var total_name_len: usize = 0;
    for (headers) |h| {
        var skip = false;
        inline for (skipped_headers) |s| {
            if (std.ascii.eqlIgnoreCase(s, h.name)) {
                skip = true;
                break;
            }
        }
        // Well, this is fun (https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html):
        //
        // When you add the X-Amz-Security-Token parameter to the query string,
        // some services require that you include this parameter in the
        // canonical (signed) request. For other services, you add this
        // parameter at the end, after you calculate the signature. For
        // details, see the API reference documentation for that service.
        if (!std.mem.eql(u8, service, "s3") and std.ascii.eqlIgnoreCase(h.name, "X-Amz-Security-Token")) {
            skip = true;
        }
        if (skip) continue;

        total_len += (h.name.len + h.value.len + 2);
        total_name_len += (h.name.len + 1);
        const value = try canonicalHeaderValue(allocator, h.value);
        defer allocator.free(value);
        const n = try std.ascii.allocLowerString(allocator, h.name);
        const v = try std.fmt.allocPrint(allocator, "{s}", .{value});
        try dest.append(.{ .name = n, .value = v });
    }

    std.sort.pdq(std.http.Header, dest.items, {}, lessThan);

    var dest_str = try std.ArrayList(u8).initCapacity(allocator, total_len);
    defer dest_str.deinit();
    var signed_headers = try std.ArrayList(u8).initCapacity(allocator, total_name_len);
    defer signed_headers.deinit();
    var first = true;
    for (dest.items) |h| {
        dest_str.appendSliceAssumeCapacity(h.name);
        dest_str.appendAssumeCapacity(':');
        dest_str.appendSliceAssumeCapacity(h.value);
        dest_str.appendAssumeCapacity('\n');

        if (!first) signed_headers.appendAssumeCapacity(';');
        first = false;
        signed_headers.appendSliceAssumeCapacity(h.name);
    }
    return CanonicalHeaders{
        .str = try dest_str.toOwnedSlice(),
        .signed_headers = try signed_headers.toOwnedSlice(),
    };
}

fn canonicalHeaderValue(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    var started = false;
    const in_quote = false;
    var start: usize = 0;
    const rc = try allocator.alloc(u8, value.len);
    defer allocator.free(rc);
    var rc_inx: usize = 0;
    for (value, 0..) |c, i| {
        if (!started and !std.ascii.isWhitespace(c)) {
            started = true;
            start = i;
        }
        if (started) {
            if (!in_quote and i > 0 and std.ascii.isWhitespace(c) and std.ascii.isWhitespace(value[i - 1]))
                continue;
            // if (c == '"') in_quote = !in_quote;
            rc[rc_inx] = c;
            rc_inx += 1;
        }
    }
    // Trim end
    while (std.ascii.isWhitespace(rc[rc_inx - 1]))
        rc_inx -= 1;
    return try allocator.dupe(u8, rc[0..rc_inx]);
}
fn lessThan(context: void, lhs: std.http.Header, rhs: std.http.Header) bool {
    _ = context;
    return std.ascii.lessThanIgnoreCase(lhs.name, rhs.name);
}

fn hash(allocator: std.mem.Allocator, payload: []const u8, sig_type: SignatureType) ![]const u8 {
    if (sig_type != .sha256)
        return error.NotImplemented;
    const to_hash = blk: {
        if (payload.len > 0) {
            break :blk payload;
        }
        break :blk "";
    };
    var out: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(to_hash, &out, .{});
    return try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&out)});
}
// SignedHeaders + '\n' +
// HexEncode(Hash(RequestPayload))
test "canonical method" {
    const actual = try canonicalRequestMethod("GET");
    try std.testing.expectEqualStrings("GET", actual);
}

test "canonical uri" {
    const allocator = std.testing.allocator;
    const path = "/documents and settings/?foo=bar";
    const expected = "/documents%2520and%2520settings/";
    const actual = try canonicalUri(allocator, path, true);

    defer allocator.free(actual);
    try std.testing.expectEqualStrings(expected, actual);

    const slash = try canonicalUri(allocator, "", true);
    defer allocator.free(slash);
    try std.testing.expectEqualStrings("/", slash);
}
test "canonical query" {
    const allocator = std.testing.allocator;
    const path = "blahblahblah?foo=bar&zed=dead&qux&equals=x=y&Action=ListUsers&Version=2010-05-08";

    // {
    //     std.testing.log_level = .debug;
    //     _ = try std.io.getStdErr().write("\n");
    // }
    const expected = "Action=ListUsers&Version=2010-05-08&equals=x%253Dy&foo=bar&qux=&zed=dead";
    const actual = try canonicalQueryString(allocator, path);
    defer allocator.free(actual);
    try std.testing.expectEqualStrings(expected, actual);
}
test "canonical headers" {
    const allocator = std.testing.allocator;
    var headers = try std.ArrayList(std.http.Header).initCapacity(allocator, 5);
    defer headers.deinit();
    try headers.append(.{ .name = "Host", .value = "iam.amazonaws.com" });
    try headers.append(.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded; charset=utf-8" });
    try headers.append(.{ .name = "User-Agent", .value = "This header should be skipped" });
    try headers.append(.{ .name = "My-header1", .value = "  a  b  c  " });
    try headers.append(.{ .name = "X-Amz-Date", .value = "20150830T123600Z" });
    try headers.append(.{ .name = "My-header2", .value = "  \"a  b  c\"  " });
    const expected =
        \\content-type:application/x-www-form-urlencoded; charset=utf-8
        \\host:iam.amazonaws.com
        \\my-header1:a b c
        \\my-header2:"a b c"
        \\x-amz-date:20150830T123600Z
        \\
    ;
    const actual = try canonicalHeaders(allocator, headers.items, "dummy");
    defer allocator.free(actual.str);
    defer allocator.free(actual.signed_headers);
    try std.testing.expectEqualStrings(expected, actual.str);
    try std.testing.expectEqualStrings("content-type;host;my-header1;my-header2;x-amz-date", actual.signed_headers);
}

test "canonical request" {
    const allocator = std.testing.allocator;
    var headers = try std.ArrayList(std.http.Header).initCapacity(allocator, 5);
    defer headers.deinit();
    try headers.append(.{ .name = "User-agent", .value = "c sdk v1.0" });
    // In contrast to AWS CRT (aws-c-auth), we add the date as part of the
    // signing operation. They add it as part of the canonicalization
    try headers.append(.{ .name = "X-Amz-Date", .value = "20150830T123600Z" });
    try headers.append(.{ .name = "Host", .value = "example.amazonaws.com" });
    const req = base.Request{
        .path = "/",
        .method = "GET",
        .headers = headers.items,
    };
    const access_key = try allocator.dupe(u8, "AKIDEXAMPLE");
    const secret_key = try allocator.dupe(u8, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    const credential = Credentials.init(allocator, access_key, secret_key, null);
    defer credential.deinit();
    const request = try createCanonicalRequest(allocator, req, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", .{
        .region = "us-west-2", // us-east-1
        .service = "sts", // service
        .credentials = credential,
        .signing_time = 1440938160, // 20150830T123600Z
    });
    defer allocator.free(request.arr);
    defer allocator.free(request.hash);
    defer allocator.free(request.headers.str);
    defer allocator.free(request.headers.signed_headers);

    const expected =
        \\GET
        \\/
        \\
        \\host:example.amazonaws.com
        \\x-amz-date:20150830T123600Z
        \\
        \\host;x-amz-date
        \\e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    ;
    try std.testing.expectEqualStrings(expected, request.arr);
}
test "can sign" {
    // [debug] (aws): call: prefix sts, sigv4 sts, version 2011-06-15, action GetCallerIdentity
    // [debug] (aws): proto: AwsProtocol.query
    // [debug] (awshttp): host: sts.us-west-2.amazonaws.com, scheme: https, port: 443
    // [debug] (awshttp): Calling endpoint https://sts.us-west-2.amazonaws.com
    // [debug] (awshttp): Path: /
    // [debug] (awshttp): Query:
    // [debug] (awshttp): Method: POST
    // [debug] (awshttp): body length: 43
    // [debug] (awshttp): Body
    // ====
    // Action=GetCallerIdentity&Version=2011-06-15
    // ====
    // [debug] (awshttp): All Request Headers:
    // [debug] (awshttp):      Accept: application/json
    // [debug] (awshttp):      Host: sts.us-west-2.amazonaws.com
    // [debug] (awshttp):      User-Agent: zig-aws 1.0, Powered by the AWS Common Runtime.
    // [debug] (awshttp):      Content-Type: application/x-www-form-urlencoded
    // [debug] (awshttp):      Content-Length: 43

    const allocator = std.testing.allocator;
    var headers = try std.ArrayList(std.http.Header).initCapacity(allocator, 5);
    defer headers.deinit();
    try headers.append(.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded; charset=utf-8" });
    try headers.append(.{ .name = "Content-Length", .value = "13" });
    try headers.append(.{ .name = "Host", .value = "example.amazonaws.com" });
    const req = base.Request{
        .path = "/",
        .query = "",
        .body = "Param1=value1",
        .method = "POST",
        .content_type = "application/json",
        .headers = headers.items,
    };
    // {
    //     std.testing.log_level = .debug;
    //     _ = try std.io.getStdErr().write("\n");
    // }

    const access_key = try allocator.dupe(u8, "AKIDEXAMPLE");
    const secret_key = try allocator.dupe(u8, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    const credential = Credentials.init(allocator, access_key, secret_key, null);
    defer credential.deinit();
    // we could look at sigv4 signing tests at:
    // https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/tests/sigv4_signing_tests.c#L1478
    const config = Config{
        .region = "us-east-1",
        .service = "service",
        .credentials = credential,
        .signing_time = 1440938160, // 20150830T123600Z
    };
    // TODO: There is an x-amz-content-sha256. Investigate
    var signed_req = try signRequest(allocator, req, config);

    defer freeSignedRequest(allocator, &signed_req, config);
    try std.testing.expectEqualStrings("X-Amz-Date", signed_req.headers[signed_req.headers.len - 3].name);
    try std.testing.expectEqualStrings("20150830T123600Z", signed_req.headers[signed_req.headers.len - 3].value);

    try std.testing.expectEqualStrings("x-amz-content-sha256", signed_req.headers[signed_req.headers.len - 2].name);
    try std.testing.expectEqualStrings("9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e", signed_req.headers[signed_req.headers.len - 2].value);

    // c_aws_auth tests don't seem to have valid data. Live endpoint is
    // accepting what we're doing
    const expected_auth = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-content-sha256;x-amz-date, Signature=328d1b9eaadca9f5818ef05e8392801e091653bafec24fcab71e7344e7f51422";

    try std.testing.expectEqualStrings("Authorization", signed_req.headers[signed_req.headers.len - 1].name);
    try std.testing.expectEqualStrings(expected_auth, signed_req.headers[signed_req.headers.len - 1].value);
}

var test_credential: ?Credentials = null;
test "can verify server request" {
    const allocator = std.testing.allocator;

    const access_key = try allocator.dupe(u8, "ACCESS");
    const secret_key = try allocator.dupe(u8, "SECRET");
    test_credential = Credentials.init(allocator, access_key, secret_key, null);
    defer test_credential.?.deinit();

    const req =
        "PUT /mysfitszj3t6webstack-hostingbucketa91a61fe-1ep3ezkgwpxr0/i/am/a/teapot/foo?x-id=PutObject HTTP/1.1\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Accept-Encoding: gzip, deflate, zstd\r\n" ++
        "TE: gzip, deflate, trailers\r\n" ++
        "Accept: application/json\r\n" ++
        "Host: 127.0.0.1\r\n" ++
        "User-Agent: zig-aws 1.0\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "x-amz-storage-class: STANDARD\r\n" ++
        "Content-Length: 3\r\n" ++
        "X-Amz-Date: 20230908T170252Z\r\n" ++
        "x-amz-content-sha256: fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9\r\n" ++
        "Authorization: AWS4-HMAC-SHA256 Credential=ACCESS/20230908/us-west-2/s3/aws4_request, SignedHeaders=accept;content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, Signature=fcc43ce73a34c9bd1ddf17e8a435f46a859812822f944f9eeb2aabcd64b03523\r\n\r\nbar";
    var read_buffer: [1024]u8 = undefined;
    @memcpy(read_buffer[0..req.len], req);
    var server: std.http.Server = .{
        .connection = undefined,
        .state = .ready,
        .read_buffer = &read_buffer,
        .read_buffer_len = req.len,
        .next_request_start = 0,
    };
    var request: std.http.Server.Request = .{
        .server = &server,
        .head_end = req.len - 3,
        .head = try std.http.Server.Request.Head.parse(read_buffer[0 .. req.len - 3]),
        .reader_state = undefined,
    };

    // std.testing.log_level = .debug;
    var fbs = std.io.fixedBufferStream("bar");
    try std.testing.expect(try verifyServerRequest(allocator, &request, fbs.reader(), struct {
        cred: Credentials,

        const Self = @This();
        fn getCreds(access: []const u8) ?Credentials {
            if (std.mem.eql(u8, access, "ACCESS")) return test_credential.?;
            return null;
        }
    }.getCreds));
}
test "can verify server request without x-amz-content-sha256" {
    const allocator = std.testing.allocator;

    const access_key = try allocator.dupe(u8, "ACCESS");
    const secret_key = try allocator.dupe(u8, "SECRET");
    test_credential = Credentials.init(allocator, access_key, secret_key, null);
    defer test_credential.?.deinit();

    const head =
        "POST / HTTP/1.1\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Accept-Encoding: gzip, deflate, zstd\r\n" ++
        "TE: gzip, deflate, trailers\r\n" ++
        "Accept: application/json\r\n" ++
        "X-Amz-Target: DynamoDB_20120810.CreateTable\r\n" ++
        "Host: dynamodb.us-west-2.amazonaws.com\r\n" ++
        "User-Agent: zig-aws 1.0\r\n" ++
        "Content-Type: application/x-amz-json-1.0\r\n" ++
        "Content-Length: 403\r\n" ++
        "X-Amz-Date: 20240224T154944Z\r\n" ++
        "x-amz-content-sha256: fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9\r\n" ++
        "Authorization: AWS4-HMAC-SHA256 Credential=ACCESS/20240224/us-west-2/dynamodb/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=8fd23dc7dbcb36c4aa54207a7118f8b9fcd680da73a0590b498e9577ff68ec33\r\n\r\n";
    const body =
        \\{"AttributeDefinitions": [{"AttributeName": "Artist", "AttributeType": "S"}, {"AttributeName": "SongTitle", "AttributeType": "S"}], "TableName": "MusicCollection", "KeySchema": [{"AttributeName": "Artist", "KeyType": "HASH"}, {"AttributeName": "SongTitle", "KeyType": "RANGE"}], "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}, "Tags": [{"Key": "Owner", "Value": "blueTeam"}]}
    ;
    const req_data = head ++ body;
    var read_buffer: [2048]u8 = undefined;
    @memcpy(read_buffer[0..req_data.len], req_data);
    var server: std.http.Server = .{
        .connection = undefined,
        .state = .ready,
        .read_buffer = &read_buffer,
        .read_buffer_len = req_data.len,
        .next_request_start = 0,
    };
    var request: std.http.Server.Request = .{
        .server = &server,
        .head_end = head.len,
        .head = try std.http.Server.Request.Head.parse(read_buffer[0..head.len]),
        .reader_state = undefined,
    };
    {
        var h = std.ArrayList(std.http.Header).init(allocator);
        defer h.deinit();
        const signed_headers = &[_][]const u8{ "content-type", "host", "x-amz-date", "x-amz-target" };
        var it = request.iterateHeaders();
        while (it.next()) |source| {
            var match = false;
            for (signed_headers) |s| {
                match = std.ascii.eqlIgnoreCase(s, source.name);
                if (match) break;
            }
            if (match) try h.append(.{ .name = source.name, .value = source.value });
        }
        const req = base.Request{
            .path = "/",
            .method = "POST",
            .headers = h.items,
        };
        const body_hash = try hash(allocator, body, .sha256);
        defer allocator.free(body_hash);
        try std.testing.expectEqualStrings("ebc5118b053c75178df0aa1f10d0443f5efb527a5589df943635834016c9b3bc", body_hash);
        const canonical_request = try createCanonicalRequest(allocator, req, body_hash, .{
            .region = "us-west-2",
            .service = "dynamodb", // service
            .credentials = test_credential.?,
            .signing_time = 1708789784, // 20240224T154944Z (https://www.unixtimestamp.com)
        });
        defer allocator.free(canonical_request.arr);
        defer allocator.free(canonical_request.hash);
        defer allocator.free(canonical_request.headers.str);
        defer allocator.free(canonical_request.headers.signed_headers);
        // Canonical request:
        const expected =
            \\POST
            \\/
            \\
            \\content-type:application/x-amz-json-1.0
            \\host:dynamodb.us-west-2.amazonaws.com
            \\x-amz-date:20240224T154944Z
            \\x-amz-target:DynamoDB_20120810.CreateTable
            \\
            \\content-type;host;x-amz-date;x-amz-target
            \\ebc5118b053c75178df0aa1f10d0443f5efb527a5589df943635834016c9b3bc
        ;
        try std.testing.expectEqualStrings(expected, canonical_request.arr);
    }

    { // verification
        var fis = std.io.fixedBufferStream(body[0..]);

        try std.testing.expect(try verifyServerRequest(allocator, &request, fis.reader(), struct {
            cred: Credentials,

            const Self = @This();
            fn getCreds(access: []const u8) ?Credentials {
                if (std.mem.eql(u8, access, "ACCESS")) return test_credential.?;
                return null;
            }
        }.getCreds));
    }
}

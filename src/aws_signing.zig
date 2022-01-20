const std = @import("std");
const base = @import("aws_http_base.zig");
const auth = @import("aws_authentication.zig");
const date = @import("date.zig");

const log = std.log.scoped(.aws_signing);

// see https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L186-L207
pub const ConfigFlags = packed struct {
    // We assume the uri will be encoded once in preparation for transmission.  Certain services
    // do not decode before checking signature, requiring us to actually double-encode the uri in the canonical
    // request in order to pass a signature check.

    use_double_uri_encode: bool = true,

    // Controls whether or not the uri paths should be normalized when building the canonical request
    should_normalize_uri_path: bool = true,

    // Controls whether "X-Amz-Security-Token" is omitted from the canonical request.
    // "X-Amz-Security-Token" is added during signing, as a header or
    // query param, when credentials have a session token.
    // If false (the default), this parameter is included in the canonical request.
    // If true, this parameter is still added, but omitted from the canonical request.
    omit_session_token: bool = true,
};

pub const Config = struct {
    // These two should be all you need to set most of the time
    service: []const u8,
    credentials: auth.Credentials,

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

    flags: ConfigFlags = .{},
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
pub fn signRequest(allocator: std.mem.Allocator, request: *base.Request, config: Config) SigningError!void {
    try validateConfig(config);
    for (request.headers) |h| {
        inline for (forbidden_headers) |f| {
            if (std.ascii.eqlIgnoreCase(h.name, f.name))
                return f.err;
        }
    }

    const signing_time = config.signing_time orelse std.time.timestamp();

    const signed_date = date.timestampToDateTime(signing_time);

    const signing_iso8601 = try std.fmt.allocPrint(
        allocator,
        "{:0>4}{:0>2}{:0>2}T{:0>2}{:0>2}{:0<2}Z",
        .{
            signed_date.year,
            signed_date.month,
            signed_date.day,
            signed_date.hour,
            signed_date.minute,
            signed_date.second,
        },
    );
    errdefer freeSignedRequest(allocator, request, config);

    const newheaders = try allocator.alloc(base.Header, request.headers.len + 2);
    errdefer allocator.free(newheaders);
    const oldheaders = request.headers;
    errdefer {
        freeSignedRequest(allocator, request, config);
        request.headers = oldheaders;
    }
    std.mem.copy(base.Header, newheaders, oldheaders);
    newheaders[newheaders.len - 2] = base.Header{
        .name = "X-Amz-Date",
        .value = signing_iso8601,
    };
    std.log.debug("oldheaders len: {d}, newheaders len: {d}, request.headers len: {d}", .{ oldheaders.len, newheaders.len, request.headers.len });
    // for (newheaders) |h, i|
    //     std.log.debug("{d}: {d}/{d}", .{ i, h.name.len, h.value.len });
    request.headers = newheaders[0 .. newheaders.len - 1];
    for (request.headers) |h|
        std.log.debug("{d}/{d}", .{ h.name.len, h.value.len });
    log.debug("Signing with access key: {s}", .{config.credentials.access_key});
    const canonical_request = try createCanonicalRequest(allocator, request.*, config);
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
    log.debug("key:{s}", .{std.fmt.fmtSliceHexLower(signing_key)});

    const signature = try hmac(allocator, signing_key, string_to_sign);
    defer allocator.free(signature);
    newheaders[newheaders.len - 1] = base.Header{
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
    request.headers = newheaders;
    //return SigningError.NotImplemented;
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

    var remove_len: u2 = 0;
    for (request.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "X-Amz-Date") or std.ascii.eqlIgnoreCase(h.name, "Authorization")) {
            allocator.free(h.value);
            remove_len += 1;
        }
    }
    if (remove_len > 0)
        request.headers = allocator.resize(request.headers, request.headers.len - remove_len).?;

    allocator.free(request.headers);
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
    var secret = try std.fmt.allocPrint(allocator, "AWS4{s}", .{config.credentials.secret_key});
    defer {
        for (secret) |_, i| secret[i] = 0; // zero our copy of secret
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
        config.signed_body_header != .sha256 or
        config.expiration_in_seconds != 0 or
        config.algorithm != .v4 or
        !config.flags.omit_session_token or
        !config.flags.should_normalize_uri_path or
        !config.flags.use_double_uri_encode)
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

fn createCanonicalRequest(allocator: std.mem.Allocator, request: base.Request, config: Config) !Hashed {
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
    const canonical_method = canonicalRequestMethod(request.method);
    const canonical_url = try canonicalUri(allocator, request.path, config.flags.use_double_uri_encode);
    defer allocator.free(canonical_url);
    log.debug("final uri: {s}", .{canonical_url});
    const canonical_query = try canonicalQueryString(allocator, request.path);
    defer allocator.free(canonical_query);
    const canonical_headers = try canonicalHeaders(allocator, request.headers);
    const payload_hash = try hash(allocator, request.body, config.signed_body_header);
    defer allocator.free(payload_hash);

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
    const hashed = try hash(allocator, canonical_request, config.signed_body_header);
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
    if (!double_encode)
        return SigningError.S3NotImplemented;
    if (path.len == 0 or path[0] == '?' or path[0] == '#')
        return try allocator.dupe(u8, "/");
    log.debug("encoding path: {s}", .{path});
    const encoded_once = try encodeUri(allocator, path);
    log.debug("encoded path (1): {s}", .{encoded_once});
    if (!double_encode)
        return encoded_once[0 .. std.mem.lastIndexOf(u8, encoded_once, "?") orelse encoded_once.len];
    defer allocator.free(encoded_once);
    const encoded_twice = try encodeUri(allocator, encoded_once);
    log.debug("encoded path (2): {s}", .{encoded_twice});
    return encoded_twice[0 .. std.mem.lastIndexOf(u8, encoded_twice, "?") orelse encoded_twice.len];
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
        if (should_encode and std.ascii.isAlNum(c))
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
fn encodeUri(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const reserved_characters = ";,/?:@&=+$#";
    const unreserved_marks = "-_.!~*'()";
    var encoded = try std.ArrayList(u8).initCapacity(allocator, path.len);
    defer encoded.deinit();
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
        if (should_encode and std.ascii.isAlNum(c))
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
    var portions = std.mem.split(u8, query, "&");
    var sort_me = std.ArrayList([]const u8).init(allocator);
    defer sort_me.deinit();
    while (portions.next()) |item|
        try sort_me.append(item);
    std.sort.sort([]const u8, sort_me.items, {}, lessThanBinary);

    var normalized = try std.ArrayList(u8).initCapacity(allocator, path.len);
    defer normalized.deinit();
    var first = true;
    for (sort_me.items) |i| {
        if (!first) try normalized.append('&');
        first = false;
        var first_equals = std.mem.indexOf(u8, i, "=");
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
    var buffer = try allocator.alloc(u8, std.mem.replacementSize(u8, haystack, needle, replacement_value));
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
fn canonicalHeaders(allocator: std.mem.Allocator, headers: []base.Header) !CanonicalHeaders {
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
    var dest = try std.ArrayList(base.Header).initCapacity(allocator, headers.len);
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
        if (skip) continue;

        total_len += (h.name.len + h.value.len + 2);
        total_name_len += (h.name.len + 1);
        const value = try canonicalHeaderValue(allocator, h.value);
        defer allocator.free(value);
        const n = try std.ascii.allocLowerString(allocator, h.name);
        const v = try std.fmt.allocPrint(allocator, "{s}", .{value});
        try dest.append(.{ .name = n, .value = v });
    }

    std.sort.sort(base.Header, dest.items, {}, lessThan);

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
        .str = dest_str.toOwnedSlice(),
        .signed_headers = signed_headers.toOwnedSlice(),
    };
}

fn canonicalHeaderValue(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    var started = false;
    var in_quote = false;
    var start: usize = 0;
    const rc = try allocator.alloc(u8, value.len);
    var rc_inx: usize = 0;
    for (value) |c, i| {
        if (!started and !std.ascii.isSpace(c)) {
            started = true;
            start = i;
        }
        if (started) {
            if (!in_quote and i > 0 and std.ascii.isSpace(c) and std.ascii.isSpace(value[i - 1]))
                continue;
            // if (c == '"') in_quote = !in_quote;
            rc[rc_inx] = c;
            rc_inx += 1;
        }
    }
    // Trim end
    while (std.ascii.isSpace(rc[rc_inx - 1]))
        rc_inx -= 1;
    return rc[0..rc_inx];
}
fn lessThan(context: void, lhs: base.Header, rhs: base.Header) bool {
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
    //     // TODO: Remove block
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
    var headers = try std.ArrayList(base.Header).initCapacity(allocator, 5);
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
    const actual = try canonicalHeaders(allocator, headers.items);
    defer allocator.free(actual.str);
    defer allocator.free(actual.signed_headers);
    try std.testing.expectEqualStrings(expected, actual.str);
    try std.testing.expectEqualStrings("content-type;host;my-header1;my-header2;x-amz-date", actual.signed_headers);
}

test "canonical request" {
    const allocator = std.testing.allocator;
    var headers = try std.ArrayList(base.Header).initCapacity(allocator, 5);
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
    const request = try createCanonicalRequest(allocator, req, .{
        .region = "us-west-2", // us-east-1
        .service = "sts", // service
        .credentials = .{
            .access_key = "AKIDEXAMPLE",
            .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            .session_token = null,
        },
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
    var headers = try std.ArrayList(base.Header).initCapacity(allocator, 5);
    defer headers.deinit();
    try headers.append(.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded; charset=utf-8" });
    try headers.append(.{ .name = "Content-Length", .value = "13" });
    try headers.append(.{ .name = "Host", .value = "example.amazonaws.com" });
    var req = base.Request{
        .path = "/",
        .query = "",
        .body = "Param1=value1",
        .method = "POST",
        .content_type = "application/json",
        .headers = headers.items,
    };
    {
        // TODO: Remove block
        std.testing.log_level = .debug;
        _ = try std.io.getStdErr().write("\n");
    }

    // we could look at sigv4 signing tests at:
    // https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/tests/sigv4_signing_tests.c#L1478
    //
    // for valid signatures. TODO: Get literally anything working first
    const config = Config{
        .region = "us-east-1",
        .service = "service",
        .credentials = .{
            .access_key = "AKIDEXAMPLE",
            .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            .session_token = null, // TODO: add session token. I think we need X-Amz-Security-Token for that. Also, x-amz-region-set looks like part of v4a that will need to be dealt with eventually
        },
        .signing_time = 1440938160, // 20150830T123600Z
    };
    // TODO: There is an x-amz-content-sha256. Investigate
    //
    try signRequest(allocator, &req, config);

    defer freeSignedRequest(allocator, &req, config);
    try std.testing.expectEqualStrings("X-Amz-Date", req.headers[req.headers.len - 2].name);
    try std.testing.expectEqualStrings("20150830T123600Z", req.headers[req.headers.len - 2].value);

    const expected_auth = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date, Signature=1a72ec8f64bd914b0e42e42607c7fbce7fb2c7465f63e3092b3b0d39fa77a6fe";

    try std.testing.expectEqualStrings("Authorization", req.headers[req.headers.len - 1].name);
    try std.testing.expectEqualStrings(expected_auth, req.headers[req.headers.len - 1].value);
}

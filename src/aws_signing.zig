const std = @import("std");
const base = @import("aws_http_base.zig");
const auth = @import("aws_authentication.zig");

const log = std.log.scoped(.aws_signing);

// see https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L186-L207
const ConfigFlags = packed struct {
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
    signing_time: ?i64 = null, // Used for testing. If null, will use current time

    // In the CRT, should_sign_header is a function to allow header filtering.
    // The _ud would be a anyopaque user defined data for the function to use
    //     .should_sign_header = null,
    //     .should_sign_header_ud = null,

    // In the CRT, this is only used if the body has been precalculated. We don't have
    // this use case, and we'll ignore
    //     .signed_body_value = c.aws_byte_cursor_from_c_str(""),
    signed_body_header: enum { sha256, none } = .sha256, // https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L131

    // This is more complex in the CRT. We'll just take the creds. Someone
    // else can use a provider and get them in advance
    // https://github.com/awslabs/aws-c-auth/blob/ace1311f8ef6ea890b26dd376031bed2721648eb/include/aws/auth/signing_config.h#L225-L251
    // If non-zero and the signing transform is query param, then signing will add X-Amz-Expires to the query
    // string, equal to the value specified here.  If this value is zero or if header signing is being used then
    // this parameter has no effect.
    expiration_in_seconds: u64 = 0,
};

pub const SigningError = error{
    NotImplemented,
};

pub fn signRequest(allocator: std.mem.Allocator, http_request: base.Request, config: Config) SigningError!void {
    _ = allocator;
    _ = http_request;
    try validateConfig(config);
    log.debug("Signing with access key: {s}", .{config.credentials.access_key});
}

fn validateConfig(config: Config) SigningError!void {
    _ = config;
    return SigningError.NotImplemented;
}

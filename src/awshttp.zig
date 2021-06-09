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
const c = @cImport({
    @cInclude("bitfield-workaround.h");
    @cInclude("aws/common/allocator.h");
    @cInclude("aws/common/error.h");
    @cInclude("aws/common/string.h");
    @cInclude("aws/auth/auth.h");
    @cInclude("aws/auth/credentials.h");
    @cInclude("aws/auth/signable.h");
    @cInclude("aws/auth/signing_config.h");
    @cInclude("aws/auth/signing_result.h");
    @cInclude("aws/auth/signing.h");
    @cInclude("aws/http/connection.h");
    @cInclude("aws/http/request_response.h");
    @cInclude("aws/io/channel_bootstrap.h");
    @cInclude("aws/io/tls_channel_handler.h");
    @cInclude("aws/io/event_loop.h");
    @cInclude("aws/io/socket.h");
    @cInclude("aws/io/stream.h");
});
const std_atomic_bool = @import("bool.zig"); // This is in std in 0.8.0

const CN_NORTH_1_HASH = std.hash_map.hashString("cn-north-1");
const CN_NORTHWEST_1_HASH = std.hash_map.hashString("cn-northwest-1");
const US_ISO_EAST_1_HASH = std.hash_map.hashString("us-iso-east-1");
const US_ISOB_EAST_1_HASH = std.hash_map.hashString("us-isob-east-1");

const httplog = std.log.scoped(.awshttp);

// Variables that can be re-used globally
var reference_count: u32 = 0;
var c_allocator: ?*c.aws_allocator = null;
var c_logger: c.aws_logger = .{
    .vtable = null,
    .allocator = null,
    .p_impl = null,
};
// tls stuff initialized on demand, then destroyed in cDeinit
var tls_ctx_options: ?*c.aws_tls_ctx_options = null;
var tls_ctx: ?*c.aws_tls_ctx = null;

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

const HttpResult = struct {
    response_code: u16, // actually 3 digits can fit in u10
    body: []const u8,
    pub fn deinit(self: HttpResult) void {
        httplog.debug("http result deinit complete", .{});
        return;
    }
};

const Header = struct {
    name: []const u8,
    value: []const u8,
};

const EndPoint = struct {
    uri: []const u8,
    host: []const u8,
    scheme: []const u8,
    port: u16,
    allocator: *std.mem.Allocator,

    fn deinit(self: EndPoint) void {
        self.allocator.free(self.uri);
    }
};

fn cInit(allocator: *std.mem.Allocator) void {
    // TODO: what happens if we actually get an allocator?
    httplog.debug("auth init", .{});
    c_allocator = c.aws_default_allocator();
    // TODO: Grab logging level from environment
    // See levels here:
    // https://github.com/awslabs/aws-c-common/blob/ce964ca459759e685547e8aa95cada50fd078eeb/include/aws/common/logging.h#L13-L19
    // We set this to FATAL mostly because we're handling errors for the most
    // part here in zig-land. We would therefore set up for something like
    // AWS_LL_WARN, but the auth library is bubbling up an AWS_LL_ERROR
    // level message about not being able to open an aws config file. This
    // could be an error, but we don't need to panic people if configuration
    // is done via environment variables
    var logger_options = c.aws_logger_standard_options{
        // .level = .AWS_LL_WARN,
        // .level = .AWS_LL_INFO,
        // .level = .AWS_LL_DEBUG,
        // .level = .AWS_LL_TRACE,
        .level = .AWS_LL_FATAL,
        .file = c.get_std_err(),
        .filename = null,
    };
    const rc = c.aws_logger_init_standard(&c_logger, c_allocator, &logger_options);
    if (rc != c.AWS_OP_SUCCESS) {
        std.debug.panic("Could not configure logging: {s}", .{c.aws_error_debug_str(c.aws_last_error())});
    }

    c.aws_logger_set(&c_logger);
    // auth could use http library, so we'll init http, then auth
    // TODO: determine deallocation of ca_path
    c.aws_http_library_init(c_allocator);
    c.aws_auth_library_init(c_allocator);
}

fn cDeinit() void { // probably the wrong name
    if (tls_ctx) |ctx| {
        httplog.debug("tls_ctx deinit start", .{});
        c.aws_tls_ctx_release(ctx);
        httplog.debug("tls_ctx deinit end", .{});
    }
    if (tls_ctx_options) |opts| {
        // See:
        // https://github.com/awslabs/aws-c-io/blob/6c7bae503961545c5e99c6c836c4b37749cfc4ad/source/tls_channel_handler.c#L25
        //
        // The way this structure is constructed (setupTls/makeRequest), the only
        // thing we need to clean up here is the alpn_list, which is set by
        // aws_tls_ctx_options_set_alpn_list to a constant value. My guess here
        // is that memory is not allocated - the pointer is looking at the program data.
        // So the pointer is non-zero, but cannot be deallocated, and we segfault
        httplog.debug("tls_ctx_options deinit unnecessary - skipping", .{});
        // log.debug("tls_ctx_options deinit start. alpn_list: {*}", .{opts.alpn_list});
        // c.aws_string_destroy(opts.alpn_list);
        // c.aws_tls_ctx_options_clean_up(opts);
        // log.debug("tls_ctx_options deinit end", .{});
    }
    c.aws_http_library_clean_up();
    httplog.debug("auth clean up start", .{});
    c.aws_auth_library_clean_up();
    httplog.debug("auth clean up complete", .{});
}

pub const AwsHttp = struct {
    allocator: *std.mem.Allocator,
    bootstrap: *c.aws_client_bootstrap,
    resolver: *c.aws_host_resolver,
    eventLoopGroup: *c.aws_event_loop_group,
    credentialsProvider: *c.aws_credentials_provider,

    const Self = @This();

    pub fn init(allocator: *std.mem.Allocator) Self {
        if (reference_count == 0) cInit(allocator);
        reference_count += 1;
        httplog.debug("auth ref count: {}", .{reference_count});
        // TODO; determine appropriate lifetime for the bootstrap and credentials'
        //       provider
        // Mostly stolen from aws_c_auth/credentials_tests.c
        const el_group = c.aws_event_loop_group_new_default(c_allocator, 1, null);

        var resolver_options = c.aws_host_resolver_default_options{
            .el_group = el_group,
            .max_entries = 8,
            .shutdown_options = null, // not set in test
            .system_clock_override_fn = null, // not set in test
        };

        const resolver = c.aws_host_resolver_new_default(c_allocator, &resolver_options);

        const bootstrap_options = c.aws_client_bootstrap_options{
            .host_resolver = resolver,
            .on_shutdown_complete = null, // was set in test
            .host_resolution_config = null,
            .user_data = null,
            .event_loop_group = el_group,
        };

        const bootstrap = c.aws_client_bootstrap_new(c_allocator, &bootstrap_options);
        const provider_chain_options = c.aws_credentials_provider_chain_default_options{
            .bootstrap = bootstrap,
            .shutdown_options = c.aws_credentials_provider_shutdown_options{
                .shutdown_callback = null, // was set on test
                .shutdown_user_data = null,
            },
        };
        return .{
            .allocator = allocator,
            .bootstrap = bootstrap,
            .resolver = resolver,
            .eventLoopGroup = el_group,
            .credentialsProvider = c.aws_credentials_provider_new_chain_default(c_allocator, &provider_chain_options),
        };
    }

    pub fn deinit(self: *AwsHttp) void {
        if (reference_count > 0)
            reference_count -= 1;
        httplog.debug("deinit: auth ref count: {}", .{reference_count});
        c.aws_credentials_provider_release(self.credentialsProvider);
        // TODO: Wait for provider shutdown? https://github.com/awslabs/aws-c-auth/blob/c394e30808816a8edaab712e77f79f480c911d3a/tests/credentials_tests.c#L197
        c.aws_client_bootstrap_release(self.bootstrap);
        c.aws_host_resolver_release(self.resolver);
        c.aws_event_loop_group_release(self.eventLoopGroup);
        if (reference_count == 0) {
            cDeinit();
            httplog.debug("Deinit complete", .{});
        }
    }

    /// callApi allows the calling of AWS APIs through a higher-level interface.
    /// It will calculate the appropriate endpoint and action parameters for the
    /// service called, and will set up the signing options. The return
    /// value is simply a raw HttpResult
    pub fn callApi(self: Self, service: []const u8, version: []const u8, action: []const u8, options: Options) !HttpResult {
        const endpoint = try regionSubDomain(self.allocator, service, options.region, options.dualstack);
        defer endpoint.deinit();
        const body = try std.fmt.allocPrint(self.allocator, "Action={s}&Version={s}\n", .{ action, version });
        defer self.allocator.free(body);
        httplog.debug("Calling {s}.{s}, endpoint {s}", .{ service, action, endpoint.uri });
        const signing_options: SigningOptions = .{
            .region = options.region,
            .service = if (options.sigv4_service_name) |name| name else service,
        };
        return try self.makeRequest(endpoint, "POST", "/", body, signing_options);
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
    pub fn makeRequest(self: Self, endpoint: EndPoint, method: []const u8, path: []const u8, body: []const u8, signing_options: ?SigningOptions) !HttpResult {
        // TODO: Try to re-encapsulate this
        // var http_request = try createRequest(method, path, body);

        // TODO: Likely this should be encapsulated more
        var http_request = c.aws_http_message_new_request(c_allocator);
        defer c.aws_http_message_release(http_request);

        if (c.aws_http_message_set_request_method(http_request, c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, method))) != c.AWS_OP_SUCCESS)
            return AwsError.SetRequestMethodError;

        if (c.aws_http_message_set_request_path(http_request, c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, path))) != c.AWS_OP_SUCCESS)
            return AwsError.SetRequestPathError;

        httplog.debug("body length: {d}", .{body.len});
        const body_cursor = c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, body));
        const request_body = c.aws_input_stream_new_from_cursor(c_allocator, &body_cursor);
        defer c.aws_input_stream_destroy(request_body);
        if (body.len > 0) {
            c.aws_http_message_set_body_stream(http_request, request_body);
        }

        // End CreateRequest. This should return a struct with a deinit function that can do
        // destroys, etc

        var context = RequestContext{
            .allocator = self.allocator,
        };
        var tls_connection_options: ?*c.aws_tls_connection_options = null;
        const host = try std.fmt.allocPrint(self.allocator, "{s}", .{endpoint.host});
        defer self.allocator.free(host);
        try self.addHeaders(http_request.?, host, body);
        if (std.mem.eql(u8, endpoint.scheme, "https")) {
            // TODO: Figure out why this needs to be inline vs function call
            // tls_connection_options = try self.setupTls(host);
            if (tls_ctx_options == null) {
                httplog.debug("Setting up tls options", .{});
                var opts: c.aws_tls_ctx_options = .{
                    .allocator = c_allocator,
                    .minimum_tls_version = @intToEnum(c.aws_tls_versions, c.AWS_IO_TLS_VER_SYS_DEFAULTS),
                    .cipher_pref = @intToEnum(c.aws_tls_cipher_pref, c.AWS_IO_TLS_CIPHER_PREF_SYSTEM_DEFAULT),
                    .ca_file = c.aws_byte_buf_from_c_str(""),
                    .ca_path = c.aws_string_new_from_c_str(c_allocator, ""),
                    .alpn_list = null,
                    .certificate = c.aws_byte_buf_from_c_str(""),
                    .private_key = c.aws_byte_buf_from_c_str(""),
                    .max_fragment_size = 0,
                    .verify_peer = true,
                };
                tls_ctx_options = &opts;

                c.aws_tls_ctx_options_init_default_client(tls_ctx_options.?, c_allocator);
                // h2;http/1.1
                if (c.aws_tls_ctx_options_set_alpn_list(tls_ctx_options, "http/1.1") != c.AWS_OP_SUCCESS) {
                    httplog.alert("Failed to load alpn list with error {s}.", .{c.aws_error_debug_str(c.aws_last_error())});
                    return AwsError.AlpnError;
                }

                tls_ctx = c.aws_tls_client_ctx_new(c_allocator, tls_ctx_options.?);

                if (tls_ctx == null) {
                    std.debug.panic("Failed to initialize TLS context with error {s}.", .{c.aws_error_debug_str(c.aws_last_error())});
                }
                httplog.debug("tls options setup applied", .{});
            }
            var conn_opts = c.aws_tls_connection_options{
                .alpn_list = null,
                .server_name = null,
                .on_negotiation_result = null,
                .on_data_read = null,
                .on_error = null,
                .user_data = null,
                .ctx = null,
                .advertise_alpn_message = false,
                .timeout_ms = 0,
            };
            tls_connection_options = &conn_opts;
            c.aws_tls_connection_options_init_from_ctx(tls_connection_options, tls_ctx);
            var host_var = host;
            var host_cur = c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, host_var));
            if (c.aws_tls_connection_options_set_server_name(tls_connection_options, c_allocator, &host_cur) != c.AWS_OP_SUCCESS) {
                httplog.alert("Failed to set servername with error {s}.", .{c.aws_error_debug_str(c.aws_last_error())});
                return AwsError.TlsError;
            }
        }
        if (signing_options) |opts| try self.signRequest(http_request.?, opts);
        const socket_options = c.aws_socket_options{
            .type = @intToEnum(c.aws_socket_type, c.AWS_SOCKET_STREAM),
            .domain = @intToEnum(c.aws_socket_domain, c.AWS_SOCKET_IPV4),
            .connect_timeout_ms = 3000, // TODO: change hardcoded 3s value
            .keep_alive_timeout_sec = 0,
            .keepalive = false,
            .keep_alive_interval_sec = 0,
            // If set, sets the number of keep alive probes allowed to fail before the connection is considered
            // lost. If zero OS defaults are used. On Windows, this option is meaningless until Windows 10 1703.
            .keep_alive_max_failed_probes = 0,
        };
        const http_client_options = c.aws_http_client_connection_options{
            .self_size = @sizeOf(c.aws_http_client_connection_options),
            .socket_options = &socket_options,
            .allocator = c_allocator,
            .port = endpoint.port,
            .host_name = c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, host)),
            .bootstrap = self.bootstrap,
            .initial_window_size = c.SIZE_MAX,
            .tls_options = tls_connection_options,
            .user_data = &context,
            .proxy_options = null,
            .monitoring_options = null,
            .http1_options = null,
            .http2_options = null,
            .manual_window_management = false,
            .on_setup = connectionSetupCallback,
            .on_shutdown = connectionShutdownCallback,
        };
        if (c.aws_http_client_connect(&http_client_options) != c.AWS_OP_SUCCESS) {
            httplog.alert("HTTP client connect failed with {s}.", .{c.aws_error_debug_str(c.aws_last_error())});
            return AwsError.HttpClientConnectError;
        }
        // TODO: Timeout
        // Wait for connection to setup
        while (!context.connection_complete.load(.SeqCst)) {
            std.time.sleep(1 * std.time.ns_per_ms);
        }
        if (context.return_error) |e| return e;

        const request_options = c.aws_http_make_request_options{
            .self_size = @sizeOf(c.aws_http_make_request_options),
            .on_response_headers = incomingHeadersCallback,
            .on_response_header_block_done = null,
            .on_response_body = incomingBodyCallback,
            .on_complete = requestCompleteCallback,
            .user_data = @ptrCast(*c_void, &context),
            .request = http_request,
        };

        const stream = c.aws_http_connection_make_request(context.connection, &request_options);
        if (stream == null) {
            httplog.alert("failed to create request.", .{});
            return AwsError.RequestCreateError;
        }
        if (c.aws_http_stream_activate(stream) != c.AWS_OP_SUCCESS) {
            httplog.alert("HTTP request failed with {s}.", .{c.aws_error_debug_str(c.aws_last_error())});
            return AwsError.HttpRequestError;
        }
        // TODO: Timeout
        while (!context.request_complete.load(.SeqCst)) {
            std.time.sleep(1 * std.time.ns_per_ms);
        }
        httplog.debug("request_complete. Response code {d}", .{context.response_code.?});
        httplog.debug("headers:", .{});
        for (context.headers.?.items) |h| {
            httplog.debug("    {s}: {s}", .{ h.name, h.value });
        }
        httplog.debug("raw response body:\n{s}", .{context.body});
        // Connection will stay alive until stream completes
        c.aws_http_connection_release(context.connection);
        context.connection = null;
        if (tls_connection_options) |opts| {
            c.aws_tls_connection_options_clean_up(opts);
        }
        var final_body: []const u8 = "";
        if (context.body) |b| {
            final_body = b;
        }

        // Headers would need to be allocated/copied into HttpResult similar
        // to RequestContext, so we'll leave this as a later excercise
        // if it becomes necessary
        const rc = HttpResult{
            .response_code = context.response_code.?,
            .body = final_body,
        };
        return rc;
    }

    // TODO: Re-encapsulate or delete this function. It is not currently
    // used and will not be touched by the compiler
    fn createRequest(method: []const u8, path: []const u8, body: []const u8) !*c.aws_http_message {
        // TODO: Likely this should be encapsulated more
        var http_request = c.aws_http_message_new_request(c_allocator);

        if (c.aws_http_message_set_request_method(http_request, c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, method))) != c.AWS_OP_SUCCESS)
            return AwsError.SetRequestMethodError;

        if (c.aws_http_message_set_request_path(http_request, c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, path))) != c.AWS_OP_SUCCESS)
            return AwsError.SetRequestPathError;

        const body_cursor = c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, body));
        const request_body = c.aws_input_stream_new_from_cursor(c_allocator, &body_cursor);
        defer c.aws_input_stream_destroy(request_body);
        c.aws_http_message_set_body_stream(http_request, request_body);
        return http_request.?;
    }

    // TODO: Re-encapsulate or delete this function. It is not currently
    // used and will not be touched by the compiler
    fn setupTls(self: Self, host: []const u8) !*c.aws_tls_connection_options {
        if (tls_ctx_options == null) {
            httplog.debug("Setting up tls options", .{});
            var opts: c.aws_tls_ctx_options = .{
                .allocator = c_allocator,
                .minimum_tls_version = @intToEnum(c.aws_tls_versions, c.AWS_IO_TLS_VER_SYS_DEFAULTS),
                .cipher_pref = @intToEnum(c.aws_tls_cipher_pref, c.AWS_IO_TLS_CIPHER_PREF_SYSTEM_DEFAULT),
                .ca_file = c.aws_byte_buf_from_c_str(""),
                .ca_path = c.aws_string_new_from_c_str(c_allocator, ""),
                .alpn_list = null,
                .certificate = c.aws_byte_buf_from_c_str(""),
                .private_key = c.aws_byte_buf_from_c_str(""),
                .max_fragment_size = 0,
                .verify_peer = true,
            };
            tls_ctx_options = &opts;

            c.aws_tls_ctx_options_init_default_client(tls_ctx_options.?, c_allocator);
            // h2;http/1.1
            if (c.aws_tls_ctx_options_set_alpn_list(tls_ctx_options, "http/1.1") != c.AWS_OP_SUCCESS) {
                httplog.alert("Failed to load alpn list with error {s}.", .{c.aws_error_debug_str(c.aws_last_error())});
                return AwsError.AlpnError;
            }

            tls_ctx = c.aws_tls_client_ctx_new(c_allocator, tls_ctx_options.?);

            if (tls_ctx == null) {
                std.debug.panic("Failed to initialize TLS context with error {s}.", .{c.aws_error_debug_str(c.aws_last_error())});
            }
            httplog.debug("tls options setup applied", .{});
        }

        var tls_connection_options = c.aws_tls_connection_options{
            .alpn_list = null,
            .server_name = null,
            .on_negotiation_result = null,
            .on_data_read = null,
            .on_error = null,
            .user_data = null,
            .ctx = null,
            .advertise_alpn_message = false,
            .timeout_ms = 0,
        };
        c.aws_tls_connection_options_init_from_ctx(&tls_connection_options, tls_ctx);
        var host_var = host;
        var host_cur = c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, host_var));
        if (c.aws_tls_connection_options_set_server_name(&tls_connection_options, c_allocator, &host_cur) != c.AWS_OP_SUCCESS) {
            httplog.alert("Failed to set servername with error {s}.", .{c.aws_error_debug_str(c.aws_last_error())});
            return AwsError.TlsError;
        }
        return &tls_connection_options;

        // if (app_ctx.uri.port) {
        //     port = app_ctx.uri.port;
        // }
    }

    fn signRequest(self: Self, http_request: *c.aws_http_message, options: SigningOptions) !void {
        const creds = try self.getCredentials();
        defer c.aws_credentials_release(creds);
        // print the access key. Creds are an opaque C type, so we
        // use aws_credentials_get_access_key_id. That gets us an aws_byte_cursor,
        // from which we create a new aws_string with the contents. We need
        // to convert to c_str with aws_string_c_str
        const access_key = c.aws_string_new_from_cursor(c_allocator, &c.aws_credentials_get_access_key_id(creds));
        defer c.aws_mem_release(c_allocator, access_key);
        // defer c_allocator.*.mem_release.?(c_allocator, access_key);
        httplog.debug("Signing with access key: {s}", .{c.aws_string_c_str(access_key)});

        const signable = c.aws_signable_new_http_request(c_allocator, http_request);
        if (signable == null) {
            httplog.warn("Could not create signable request", .{});
            return AwsError.SignableError;
        }
        defer c.aws_signable_destroy(signable);

        const signing_region = try std.fmt.allocPrint(self.allocator, "{s}", .{options.region});
        defer self.allocator.free(signing_region);
        const signing_service = try std.fmt.allocPrint(self.allocator, "{s}", .{options.service});
        defer self.allocator.free(signing_service);
        const temp_signing_config = c.bitfield_workaround_aws_signing_config_aws{
            .algorithm = .AWS_SIGNING_ALGORITHM_V4,
            .config_type = .AWS_SIGNING_CONFIG_AWS,
            .signature_type = .AWS_ST_HTTP_REQUEST_HEADERS,
            .region = c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, signing_region)),
            .service = c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, signing_service)),
            .should_sign_header = null,
            .should_sign_header_ud = null,
            .flags = c.bitfield_workaround_aws_signing_config_aws_flags{
                .use_double_uri_encode = 0,
                .should_normalize_uri_path = 0,
                .omit_session_token = 1,
            },
            .signed_body_value = c.aws_byte_cursor_from_c_str(""),
            .signed_body_header = .AWS_SBHT_X_AMZ_CONTENT_SHA256, //or AWS_SBHT_NONE
            .credentials = creds,
            .credentials_provider = self.credentialsProvider,
            .expiration_in_seconds = 0,
        };
        var signing_config = c.new_aws_signing_config(c_allocator, &temp_signing_config);
        defer c.aws_mem_release(c_allocator, signing_config);
        var signing_result = AwsAsyncCallbackResult(c.aws_http_message){ .result = http_request };
        var sign_result_request = AsyncResult(AwsAsyncCallbackResult(c.aws_http_message)){ .result = &signing_result };
        if (c.aws_sign_request_aws(c_allocator, signable, fullCast([*c]const c.aws_signing_config_base, signing_config), signComplete, &sign_result_request) != c.AWS_OP_SUCCESS) {
            const error_code = c.aws_last_error();
            httplog.alert("Could not initiate signing request: {s}:{s}", .{ c.aws_error_name(error_code), c.aws_error_str(error_code) });
            return AwsError.SigningInitiationError;
        }

        // Wait for callback. Note that execution, including real work of signing
        // the http request, will continue in signComplete (below),
        // then continue beyond this line
        waitOnCallback(c.aws_http_message, &sign_result_request);
        if (sign_result_request.result.error_code != c.AWS_ERROR_SUCCESS) {
            return AwsError.SignableError;
        }
    }

    /// It's my theory that the aws event loop has a trigger to corrupt the
    /// signing result after this call completes. So the technique of assigning
    /// now, using later will not work
    fn signComplete(result: ?*c.aws_signing_result, error_code: c_int, user_data: ?*c_void) callconv(.C) void {
        var async_result = userDataTo(AsyncResult(AwsAsyncCallbackResult(c.aws_http_message)), user_data);
        var http_request = async_result.result.result;
        async_result.sync.store(true, .SeqCst);

        async_result.count += 1;
        async_result.result.error_code = error_code;

        if (result) |res| {
            if (c.aws_apply_signing_result_to_http_request(http_request, c_allocator, result) != c.AWS_OP_SUCCESS) {
                httplog.alert("Could not apply signing request to http request: {s}", .{c.aws_error_debug_str(c.aws_last_error())});
            }
            httplog.debug("signing result applied", .{});
        } else {
            httplog.alert("Did not receive signing result: {s}", .{c.aws_error_debug_str(c.aws_last_error())});
        }
        async_result.sync.store(false, .SeqCst);
    }

    fn addHeaders(self: Self, request: *c.aws_http_message, host: []const u8, body: []const u8) !void {
        const accept_header = c.aws_http_header{
            .name = c.aws_byte_cursor_from_c_str("Accept"),
            .value = c.aws_byte_cursor_from_c_str("application/json"),
            .compression = .AWS_HTTP_HEADER_COMPRESSION_USE_CACHE,
        };
        if (c.aws_http_message_add_header(request, accept_header) != c.AWS_OP_SUCCESS)
            return AwsError.AddHeaderError;

        const host_header = c.aws_http_header{
            .name = c.aws_byte_cursor_from_c_str("Host"),
            .value = c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, host)),
            .compression = .AWS_HTTP_HEADER_COMPRESSION_USE_CACHE,
        };
        if (c.aws_http_message_add_header(request, host_header) != c.AWS_OP_SUCCESS)
            return AwsError.AddHeaderError;

        const user_agent_header = c.aws_http_header{
            .name = c.aws_byte_cursor_from_c_str("User-Agent"),
            .value = c.aws_byte_cursor_from_c_str("zig-aws 1.0, Powered by the AWS Common Runtime."),
            .compression = .AWS_HTTP_HEADER_COMPRESSION_USE_CACHE,
        };
        if (c.aws_http_message_add_header(request, user_agent_header) != c.AWS_OP_SUCCESS)
            return AwsError.AddHeaderError;

        // AWS does not seem to care about Accept-Encoding
        // Accept-Encoding: identity
        // Content-Type: application/x-www-form-urlencoded
        // const accept_encoding_header = c.aws_http_header{
        //     .name = c.aws_byte_cursor_from_c_str("Accept-Encoding"),
        //     .value = c.aws_byte_cursor_from_c_str("identity"),
        //     .compression = .AWS_HTTP_HEADER_COMPRESSION_USE_CACHE,
        // };
        // if (c.aws_http_message_add_header(request, accept_encoding_header) != c.AWS_OP_SUCCESS)
        //     return AwsError.AddHeaderError;

        // AWS *does* seem to care about Content-Type. I don't think this header
        // will hold for all APIs
        // TODO: Work out Content-type
        const content_type_header = c.aws_http_header{
            .name = c.aws_byte_cursor_from_c_str("Content-Type"),
            .value = c.aws_byte_cursor_from_c_str("application/x-www-form-urlencoded"),
            .compression = .AWS_HTTP_HEADER_COMPRESSION_USE_CACHE,
        };
        if (c.aws_http_message_add_header(request, content_type_header) != c.AWS_OP_SUCCESS)
            return AwsError.AddHeaderError;

        if (body.len > 0) {
            const len = try std.fmt.allocPrint(self.allocator, "{d}", .{body.len});
            // This defer seems to work ok, but I'm a bit concerned about why
            defer self.allocator.free(len);
            const content_length_header = c.aws_http_header{
                .name = c.aws_byte_cursor_from_c_str("Content-Length"),
                .value = c.aws_byte_cursor_from_c_str(@ptrCast([*c]const u8, len)),
                .compression = .AWS_HTTP_HEADER_COMPRESSION_USE_CACHE,
            };
            if (c.aws_http_message_add_header(request, content_length_header) != c.AWS_OP_SUCCESS)
                return AwsError.AddHeaderError;
        }
    }

    fn connectionSetupCallback(connection: ?*c.aws_http_connection, error_code: c_int, user_data: ?*c_void) callconv(.C) void {
        httplog.debug("connection setup callback start", .{});
        var context = userDataTo(RequestContext, user_data);
        if (error_code != c.AWS_OP_SUCCESS) {
            httplog.alert("Failed to setup connection: {s}.", .{c.aws_error_debug_str(c.aws_last_error())});
            context.return_error = AwsError.SetupConnectionError;
        }
        context.connection = connection;
        context.connection_complete.store(true, .SeqCst);
        httplog.debug("connection setup callback end", .{});
    }

    fn connectionShutdownCallback(connection: ?*c.aws_http_connection, error_code: c_int, user_data: ?*c_void) callconv(.C) void {
        httplog.debug("connection shutdown callback start", .{});
        httplog.debug("connection shutdown callback end", .{});
    }

    fn incomingHeadersCallback(stream: ?*c.aws_http_stream, header_block: c.aws_http_header_block, headers: [*c]const c.aws_http_header, num_headers: usize, user_data: ?*c_void) callconv(.C) c_int {
        var context = userDataTo(RequestContext, user_data);

        if (context.response_code == null) {
            var status: c_int = 0;
            if (c.aws_http_stream_get_incoming_response_status(stream, &status) == c.AWS_OP_SUCCESS) {
                context.response_code = @intCast(u16, status); // RFC says this is a 3 digit number, so c_int is silly
                httplog.debug("response status code from callback: {d}", .{status});
            } else {
                httplog.alert("could not get status code", .{});
                context.return_error = AwsError.StatusCodeError;
            }
        }
        for (headers[0..num_headers]) |header| {
            const name = header.name.ptr[0..header.name.len];
            const value = header.value.ptr[0..header.value.len];
            httplog.debug("header from callback: {s}: {s}", .{ name, value });
            context.addHeader(name, value) catch
                httplog.alert("could not append header to request context", .{});
        }
        return c.AWS_OP_SUCCESS;
    }
    fn incomingBodyCallback(stream: ?*c.aws_http_stream, data: [*c]const c.aws_byte_cursor, user_data: ?*c_void) callconv(.C) c_int {
        var context = userDataTo(RequestContext, user_data);

        httplog.debug("inbound body, len {d}", .{data.*.len});
        const array = @ptrCast(*const []u8, &data.*.ptr).*;
        // Need this to be a slice because it does not necessarily have a \0 sentinal
        const body_chunk = array[0..data.*.len];
        context.appendToBody(body_chunk) catch
            httplog.alert("could not append to body!", .{});
        return c.AWS_OP_SUCCESS;
    }
    fn requestCompleteCallback(stream: ?*c.aws_http_stream, error_code: c_int, user_data: ?*c_void) callconv(.C) void {
        var context = userDataTo(RequestContext, user_data);
        context.request_complete.store(true, .SeqCst);
        c.aws_http_stream_release(stream);
        httplog.debug("request complete", .{});
    }

    fn getCredentials(self: Self) !*c.aws_credentials {
        var credential_result = AwsAsyncCallbackResult(c.aws_credentials){};
        var callback_results = AsyncResult(AwsAsyncCallbackResult(c.aws_credentials)){ .result = &credential_result };

        const callback = awsAsyncCallbackResult(c.aws_credentials, "got credentials", assignCredentialsOnCallback);
        const get_async_result =
            c.aws_credentials_provider_get_credentials(self.credentialsProvider, callback, &callback_results);

        waitOnCallback(c.aws_credentials, &callback_results);
        if (credential_result.error_code != c.AWS_ERROR_SUCCESS) {
            httplog.alert("Could not acquire credentials: {s}:{s}", .{ c.aws_error_name(credential_result.error_code), c.aws_error_str(credential_result.error_code) });
            return AwsError.CredentialsError;
        }
        return credential_result.result orelse unreachable;
    }

    // Generic wait on callback function
    fn waitOnCallback(comptime T: type, results: *AsyncResult(AwsAsyncCallbackResult(T))) void {
        var done = false;
        while (!done) {
            // TODO: Timeout
            // More context: https://github.com/ziglang/zig/blob/119fc318a753f57b55809e9256e823accba6b56a/lib/std/crypto/benchmark.zig#L45-L54
            //     var timer = try std.time.Timer.start();
            // const start = timer.lap();
            // while (offset < bytes) : (offset += block.len) {
            //     do work
            //
            //     h.update(block[0..]);
            // }
            // mem.doNotOptimizeAway(&h);
            // const end = timer.read();
            //
            // const elapsed_s = @intToFloat(f64, end - start) / time.ns_per_s;
            while (results.sync.load(.SeqCst)) {
                std.time.sleep(1 * std.time.ns_per_ms);
            }
            done = results.count >= results.requiredCount;
            // TODO: Timeout
            std.time.sleep(1 * std.time.ns_per_ms);
        }
    }

    // Generic function that generates a type-specific funtion for callback use
    fn awsAsyncCallback(comptime T: type, comptime message: []const u8) (fn (result: ?*T, error_code: c_int, user_data: ?*c_void) callconv(.C) void) {
        const inner = struct {
            fn func(userData: *AsyncResult(AwsAsyncCallbackResult(T)), apiData: ?*T) void {
                userData.result.result = apiData;
            }
        };
        return awsAsyncCallbackResult(T, message, inner.func);
    }

    // used by awsAsyncCallbackResult to cast our generic userdata void *
    // into a type known to zig
    fn userDataTo(comptime T: type, userData: ?*c_void) *T {
        return @ptrCast(*T, @alignCast(@alignOf(T), userData));
    }

    // generic callback ability. Takes a function for the actual assignment
    // If you need a standard assignment, use awsAsyncCallback instead
    fn awsAsyncCallbackResult(comptime T: type, comptime message: []const u8, comptime resultAssignment: (fn (user: *AsyncResult(AwsAsyncCallbackResult(T)), apiData: ?*T) void)) (fn (result: ?*T, error_code: c_int, user_data: ?*c_void) callconv(.C) void) {
        const inner = struct {
            fn innerfunc(result: ?*T, error_code: c_int, user_data: ?*c_void) callconv(.C) void {
                httplog.debug(message, .{});
                var asyncResult = userDataTo(AsyncResult(AwsAsyncCallbackResult(T)), user_data);

                asyncResult.sync.store(true, .SeqCst);

                asyncResult.count += 1;
                asyncResult.result.error_code = error_code;

                resultAssignment(asyncResult, result);
                // asyncResult.result.result = result;

                asyncResult.sync.store(false, .SeqCst);
            }
        };
        return inner.innerfunc;
    }

    fn assignCredentialsOnCallback(asyncResult: *AsyncResult(AwsAsyncCallbackResult(c.aws_credentials)), credentials: ?*c.aws_credentials) void {
        if (asyncResult.result.result) |result| {
            c.aws_credentials_release(result);
        }

        asyncResult.result.result = credentials;

        if (credentials) |cred| {
            c.aws_credentials_acquire(cred);
        }
    }
};

fn AsyncResult(comptime T: type) type {
    return struct {
        result: *T,
        requiredCount: u32 = 1,
        sync: std_atomic_bool.Bool = std_atomic_bool.Bool.init(false), // This is a 0.8.0 feature... :(
        count: u8 = 0,
    };
}

fn AwsAsyncCallbackResult(comptime T: type) type {
    return struct {
        result: ?*T = null,
        error_code: i32 = c.AWS_ERROR_SUCCESS,
    };
}

fn fullCast(comptime T: type, val: anytype) T {
    return @ptrCast(T, @alignCast(@alignOf(T), val));
}

fn regionSubDomain(allocator: *std.mem.Allocator, service: []const u8, region: []const u8, useDualStack: bool) !EndPoint {
    const environment_override = std.os.getenv("AWS_ENDPOINT_URL");
    if (environment_override) |override| {
        const uri = try std.fmt.allocPrint(allocator, "{s}", .{override});
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

    const uri = try std.fmt.allocPrint(allocator, "https://{s}{s}.{s}.{s}", .{ service, dualstack, realregion, domain });
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
fn endPointFromUri(allocator: *std.mem.Allocator, uri: []const u8) !EndPoint {
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
    connection_complete: std_atomic_bool.Bool = std_atomic_bool.Bool.init(false), // This is a 0.8.0 feature... :(
    request_complete: std_atomic_bool.Bool = std_atomic_bool.Bool.init(false), // This is a 0.8.0 feature... :(
    return_error: ?AwsError = null,
    allocator: *std.mem.Allocator,
    body: ?[]const u8 = null,
    response_code: ?u16 = null,
    headers: ?std.ArrayList(Header) = null,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.allocator.free(self.body);
        if (self.headers) |hs| {
            for (hs) |h| {
                // deallocate the copied values
                self.allocator.free(h.name);
                self.allocator.free(h.value);
            }
            // deallocate the structure itself
            h.deinit();
        }
    }

    pub fn appendToBody(self: *Self, fragment: []const u8) !void {
        var orig_body: []const u8 = "";
        if (self.body) |b| {
            orig_body = try self.allocator.dupeZ(u8, b);
            self.allocator.free(self.body.?);
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

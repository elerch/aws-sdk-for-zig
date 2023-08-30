const std = @import("../std.zig");
const Uri = std.http.Uri;

pub const StartError = std.http.Connection.WriteError || error{ InvalidContentLength, UnsupportedTransferEncoding };

///////////////////////////////////////////////////////////////////////////
/// This function imported from:
/// https://github.com/ziglang/zig/blob/0.11.0/lib/std/http/Client.zig#L538-L636
///
/// The first commit of this file will be unchanged from 0.11.0 to more
/// clearly indicate changes moving forward. The plan is to change
/// only the two w.print lines for req.uri 16 and 18 lines down from this comment
///////////////////////////////////////////////////////////////////////////
/// Send the request to the server.
pub fn start(req: *std.http.Client.Request) StartError!void {
    var buffered = std.io.bufferedWriter(req.connection.?.data.writer());
    const w = buffered.writer();

    try w.writeAll(@tagName(req.method));
    try w.writeByte(' ');

    if (req.method == .CONNECT) {
        try w.writeAll(req.uri.host.?);
        try w.writeByte(':');
        try w.print("{}", .{req.uri.port.?});
    } else if (req.connection.?.data.proxied) {
        // proxied connections require the full uri
        try w.print("{+/}", .{req.uri});
    } else {
        try w.print("{/}", .{req.uri});
    }

    try w.writeByte(' ');
    try w.writeAll(@tagName(req.version));
    try w.writeAll("\r\n");

    if (!req.headers.contains("host")) {
        try w.writeAll("Host: ");
        try w.writeAll(req.uri.host.?);
        try w.writeAll("\r\n");
    }

    if (!req.headers.contains("user-agent")) {
        try w.writeAll("User-Agent: zig/");
        try w.writeAll(@import("builtin").zig_version_string);
        try w.writeAll(" (std.http)\r\n");
    }

    if (!req.headers.contains("connection")) {
        try w.writeAll("Connection: keep-alive\r\n");
    }

    if (!req.headers.contains("accept-encoding")) {
        try w.writeAll("Accept-Encoding: gzip, deflate, zstd\r\n");
    }

    if (!req.headers.contains("te")) {
        try w.writeAll("TE: gzip, deflate, trailers\r\n");
    }

    const has_transfer_encoding = req.headers.contains("transfer-encoding");
    const has_content_length = req.headers.contains("content-length");

    if (!has_transfer_encoding and !has_content_length) {
        switch (req.transfer_encoding) {
            .chunked => try w.writeAll("Transfer-Encoding: chunked\r\n"),
            .content_length => |content_length| try w.print("Content-Length: {d}\r\n", .{content_length}),
            .none => {},
        }
    } else {
        if (has_content_length) {
            const content_length = std.fmt.parseInt(u64, req.headers.getFirstValue("content-length").?, 10) catch return error.InvalidContentLength;

            req.transfer_encoding = .{ .content_length = content_length };
        } else if (has_transfer_encoding) {
            const transfer_encoding = req.headers.getFirstValue("transfer-encoding").?;
            if (std.mem.eql(u8, transfer_encoding, "chunked")) {
                req.transfer_encoding = .chunked;
            } else {
                return error.UnsupportedTransferEncoding;
            }
        } else {
            req.transfer_encoding = .none;
        }
    }

    try w.print("{}", .{req.headers});

    try w.writeAll("\r\n");

    try buffered.flush();
}

///////////////////////////////////////////////////////////////////////////
/// This function imported from:
/// https://github.com/ziglang/zig/blob/0.11.0/lib/std/Uri.zig#L209-L264
///
/// The first commit of this file will be unchanged from 0.11.0 to more
/// clearly indicate changes moving forward. The plan is to change
/// only the writeEscapedPath call 42 lines down from this comment
///////////////////////////////////////////////////////////////////////////
pub fn format(
    uri: Uri,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    _ = options;

    const needs_absolute = comptime std.mem.indexOf(u8, fmt, "+") != null;
    const needs_path = comptime std.mem.indexOf(u8, fmt, "/") != null or fmt.len == 0;
    const needs_fragment = comptime std.mem.indexOf(u8, fmt, "#") != null;

    if (needs_absolute) {
        try writer.writeAll(uri.scheme);
        try writer.writeAll(":");
        if (uri.host) |host| {
            try writer.writeAll("//");

            if (uri.user) |user| {
                try writer.writeAll(user);
                if (uri.password) |password| {
                    try writer.writeAll(":");
                    try writer.writeAll(password);
                }
                try writer.writeAll("@");
            }

            try writer.writeAll(host);

            if (uri.port) |port| {
                try writer.writeAll(":");
                try std.fmt.formatInt(port, 10, .lower, .{}, writer);
            }
        }
    }

    if (needs_path) {
        if (uri.path.len == 0) {
            try writer.writeAll("/");
        } else {
            try Uri.writeEscapedPath(writer, uri.path);
        }

        if (uri.query) |q| {
            try writer.writeAll("?");
            try Uri.writeEscapedQuery(writer, q);
        }

        if (needs_fragment) {
            if (uri.fragment) |f| {
                try writer.writeAll("#");
                try Uri.writeEscapedQuery(writer, f);
            }
        }
    }
}

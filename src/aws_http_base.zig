//! This module provides base data structures for aws http requests
const std = @import("std");
pub const Request = struct {
    path: []const u8 = "/",
    query: []const u8 = "",
    body: []const u8 = "",
    method: []const u8 = "POST",
    content_type: []const u8 = "application/json", // Can we get away with this?
    headers: []const std.http.Header = &.{},
};
pub const Result = struct {
    response_code: std.http.Status,
    body: []const u8,
    headers: []const std.http.Header,
    allocator: std.mem.Allocator,

    pub fn deinit(self: Result) void {
        self.allocator.free(self.body);
        for (self.headers) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        }
        self.allocator.free(self.headers);
        //log.debug("http result deinit complete", .{});
        return;
    }
};

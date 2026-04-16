const builtin = @import("builtin");
const std = @import("std");
const Hash = std.crypto.hash.sha2.Sha256;

pub const HashedFile = struct {
    fs_path: []const u8,
    normalized_path: []const u8,
    hash: [Hash.digest_length]u8,
    failure: Error!void,

    const Error = std.Io.File.OpenError || std.Io.File.ReadStreamingError || std.Io.File.StatError;

    fn lessThan(context: void, lhs: *const HashedFile, rhs: *const HashedFile) bool {
        _ = context;
        return std.mem.lessThan(u8, lhs.normalized_path, rhs.normalized_path);
    }
};

const multihash_len = 1 + 1 + Hash.digest_length;
pub const hex_multihash_len = 2 * multihash_len;
pub const digest_len = Hash.digest_length;

const MultihashFunction = enum(u16) {
    identity = 0x00,
    sha1 = 0x11,
    @"sha2-256" = 0x12,
    @"sha2-512" = 0x13,
    @"sha3-512" = 0x14,
    @"sha3-384" = 0x15,
    @"sha3-256" = 0x16,
    @"sha3-224" = 0x17,
    @"sha2-384" = 0x20,
    @"sha2-256-trunc254-padded" = 0x1012,
    @"sha2-224" = 0x1013,
    @"sha2-512-224" = 0x1014,
    @"sha2-512-256" = 0x1015,
    @"blake2b-256" = 0xb220,
    _,
};

const multihash_function: MultihashFunction = switch (Hash) {
    std.crypto.hash.sha2.Sha256 => .@"sha2-256",
    else => @compileError("unreachable"),
};
comptime {
    // We avoid unnecessary uleb128 code in hexDigest by asserting here the
    // values are small enough to be contained in the one-byte encoding.
    std.debug.assert(@intFromEnum(multihash_function) < 127);
    std.debug.assert(Hash.digest_length < 127);
}
const hex_charset = "0123456789abcdef";

pub fn hexDigest(digest: [Hash.digest_length]u8) [multihash_len * 2]u8 {
    var result: [multihash_len * 2]u8 = undefined;

    result[0] = hex_charset[@intFromEnum(multihash_function) >> 4];
    result[1] = hex_charset[@intFromEnum(multihash_function) & 15];

    result[2] = hex_charset[Hash.digest_length >> 4];
    result[3] = hex_charset[Hash.digest_length & 15];

    for (digest, 0..) |byte, i| {
        result[4 + i * 2] = hex_charset[byte >> 4];
        result[5 + i * 2] = hex_charset[byte & 15];
    }
    return result;
}
pub fn hex64(x: u64) [16]u8 {
    var result: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const byte: u8 = @truncate(x >> @as(u6, @intCast(8 * i)));
        result[i * 2 + 0] = hex_charset[byte >> 4];
        result[i * 2 + 1] = hex_charset[byte & 15];
    }
    return result;
}

pub const walkerFn = *const fn (std.Io.Dir.Walker.Entry) bool;

fn included(entry: std.Io.Dir.Walker.Entry) bool {
    _ = entry;
    return true;
}
fn excluded(entry: std.Io.Dir.Walker.Entry) bool {
    _ = entry;
    return false;
}
pub const ComputeDirectoryOptions = struct {
    isIncluded: walkerFn = included,
    isExcluded: walkerFn = excluded,
    fileHashes: []*HashedFile = undefined,
    needFileHashes: bool = false,
};

pub fn computeDirectoryHash(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    options: *ComputeDirectoryOptions,
) ![Hash.digest_length]u8 {

    // We'll use an arena allocator for the path name strings since they all
    // need to be in memory for sorting.
    var arena_instance = std.heap.ArenaAllocator.init(allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    // Collect all files, recursively, then sort.
    // Normally we're looking at around 300 model files
    var all_files = try std.ArrayList(*HashedFile).initCapacity(allocator, 300);
    defer all_files.deinit(allocator);

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    {
        // The final hash will be a hash of each file hashed independently. This
        // allows hashing in parallel.
        var g: std.Io.Group = .init;
        errdefer g.cancel(io);

        while (try walker.next(io)) |entry| {
            switch (entry.kind) {
                .directory => continue,
                .file => {},
                else => return error.IllegalFileTypeInPackage,
            }
            if (options.isExcluded(entry) or !options.isIncluded(entry))
                continue;
            const alloc = if (options.needFileHashes) allocator else arena;
            const hashed_file = try alloc.create(HashedFile);
            const fs_path = try alloc.dupe(u8, entry.path);
            hashed_file.* = .{
                .fs_path = fs_path,
                .normalized_path = try normalizePath(alloc, fs_path),
                .hash = undefined, // to be populated by the worker
                .failure = undefined, // to be populated by the worker
            };
            g.async(io, workerHashFile, .{ io, dir, hashed_file, &g });

            try all_files.append(allocator, hashed_file);
        }
        try g.await(io);
    }

    std.mem.sort(*HashedFile, all_files.items, {}, HashedFile.lessThan);

    var hasher = Hash.init(.{});
    var any_failures = false;
    for (all_files.items) |hashed_file| {
        hashed_file.failure catch |err| {
            any_failures = true;
            std.log.err("unable to hash '{s}': {s}", .{ hashed_file.fs_path, @errorName(err) });
        };
        hasher.update(&hashed_file.hash);
    }
    if (any_failures) return error.DirectoryHashUnavailable;
    if (options.needFileHashes) options.fileHashes = try all_files.toOwnedSlice(allocator);
    return hasher.finalResult();
}
fn workerHashFile(io: std.Io, dir: std.Io.Dir, hashed_file: *HashedFile, wg: *std.Io.Group) void {
    _ = wg; // assume here that 0.16.0 Io.Group no longer needs to be notified at the time of completion
    hashed_file.failure = hashFileFallible(io, dir, hashed_file);
}

fn hashFileFallible(io: std.Io, dir: std.Io.Dir, hashed_file: *HashedFile) HashedFile.Error!void {
    var buf: [8000]u8 = undefined;
    var file = try dir.openFile(io, hashed_file.fs_path, .{});
    defer file.close(io);
    var hasher = Hash.init(.{});
    hasher.update(hashed_file.normalized_path);
    hasher.update(&.{ 0, @intFromBool(try isExecutable(io, file)) });
    while (true) {
        const bytes_read = file.readStreaming(io, &.{&buf}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (bytes_read == 0) break;
        hasher.update(buf[0..bytes_read]);
    }
    hasher.final(&hashed_file.hash);
}

/// Make a file system path identical independently of operating system path inconsistencies.
/// This converts backslashes into forward slashes.
fn normalizePath(arena: std.mem.Allocator, fs_path: []const u8) ![]const u8 {
    const canonical_sep = '/';

    if (std.fs.path.sep == canonical_sep)
        return fs_path;

    const normalized = try arena.dupe(u8, fs_path);
    for (normalized) |*byte| {
        switch (byte.*) {
            std.fs.path.sep => byte.* = canonical_sep,
            else => continue,
        }
    }
    return normalized;
}

fn isExecutable(io: std.Io, file: std.Io.File) !bool {
    if (builtin.os.tag == .windows) {
        // TODO check the ACL on Windows.
        // Until this is implemented, this could be a false negative on
        // Windows, which is why we do not yet set executable_bit_only above
        // when unpacking the tarball.
        return false;
    } else {
        const stat = try file.stat(io);
        return stat.kind == .file and (stat.permissions.toMode() & std.posix.S.IXUSR != 0);
    }
}

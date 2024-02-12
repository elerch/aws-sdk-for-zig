const builtin = @import("builtin");
const std = @import("std");
const Hash = std.crypto.hash.sha2.Sha256;

pub const HashedFile = struct {
    fs_path: []const u8,
    normalized_path: []const u8,
    hash: [Hash.digest_length]u8,
    failure: Error!void,

    const Error = std.fs.File.OpenError || std.fs.File.ReadError || std.fs.File.StatError;

    fn lessThan(context: void, lhs: *const HashedFile, rhs: *const HashedFile) bool {
        _ = context;
        return std.mem.lessThan(u8, lhs.normalized_path, rhs.normalized_path);
    }
};

const multihash_len = 1 + 1 + Hash.digest_length;
pub const hex_multihash_len = 2 * multihash_len;
pub const digest_len = Hash.digest_length;

const MultiHashHexDigest = [hex_multihash_len]u8;
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
        const byte = @as(u8, @truncate(x >> @as(u6, @intCast(8 * i))));
        result[i * 2 + 0] = hex_charset[byte >> 4];
        result[i * 2 + 1] = hex_charset[byte & 15];
    }
    return result;
}

pub const walkerFn = *const fn (std.fs.Dir.Walker.WalkerEntry) bool;

fn included(entry: std.fs.Dir.Walker.WalkerEntry) bool {
    _ = entry;
    return true;
}
fn excluded(entry: std.fs.Dir.Walker.WalkerEntry) bool {
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
    thread_pool: *std.Thread.Pool,
    dir: std.fs.Dir,
    options: *ComputeDirectoryOptions,
) ![Hash.digest_length]u8 {
    const gpa = thread_pool.allocator;

    // We'll use an arena allocator for the path name strings since they all
    // need to be in memory for sorting.
    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    // Collect all files, recursively, then sort.
    var all_files = std.ArrayList(*HashedFile).init(gpa);
    defer all_files.deinit();

    var walker = try dir.walk(gpa);
    defer walker.deinit();

    {
        // The final hash will be a hash of each file hashed independently. This
        // allows hashing in parallel.
        var wait_group: std.Thread.WaitGroup = .{};
        defer wait_group.wait();

        while (try walker.next()) |entry| {
            switch (entry.kind) {
                .directory => continue,
                .file => {},
                else => return error.IllegalFileTypeInPackage,
            }
            if (options.isExcluded(entry) or !options.isIncluded(entry))
                continue;
            const alloc = if (options.needFileHashes) gpa else arena;
            const hashed_file = try alloc.create(HashedFile);
            const fs_path = try alloc.dupe(u8, entry.path);
            hashed_file.* = .{
                .fs_path = fs_path,
                .normalized_path = try normalizePath(alloc, fs_path),
                .hash = undefined, // to be populated by the worker
                .failure = undefined, // to be populated by the worker
            };
            wait_group.start();
            try thread_pool.spawn(workerHashFile, .{ dir, hashed_file, &wait_group });

            try all_files.append(hashed_file);
        }
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
    if (options.needFileHashes) options.fileHashes = try all_files.toOwnedSlice();
    return hasher.finalResult();
}
fn workerHashFile(dir: std.fs.Dir, hashed_file: *HashedFile, wg: *std.Thread.WaitGroup) void {
    defer wg.finish();
    hashed_file.failure = hashFileFallible(dir, hashed_file);
}

fn hashFileFallible(dir: std.fs.Dir, hashed_file: *HashedFile) HashedFile.Error!void {
    var buf: [8000]u8 = undefined;
    var file = try dir.openFile(hashed_file.fs_path, .{});
    defer file.close();
    var hasher = Hash.init(.{});
    hasher.update(hashed_file.normalized_path);
    hasher.update(&.{ 0, @intFromBool(try isExecutable(file)) });
    while (true) {
        const bytes_read = try file.read(&buf);
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

fn isExecutable(file: std.fs.File) !bool {
    if (builtin.os.tag == .windows) {
        // TODO check the ACL on Windows.
        // Until this is implemented, this could be a false negative on
        // Windows, which is why we do not yet set executable_bit_only above
        // when unpacking the tarball.
        return false;
    } else {
        const stat = try file.stat();
        return (stat.mode & std.os.S.IXUSR) != 0;
    }
}

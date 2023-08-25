const builtin = @import("builtin");
const std = @import("std");
const testing = std.testing;

/// This is 128 bits - Even with 2^54 cache entries, the probably of a collision would be under 10^-6
const bin_digest_len = 16;
const hex_digest_len = bin_digest_len * 2;
const hex_multihash_len = 2 * multihash_len;
const MultiHashHexDigest = [hex_multihash_len]u8;
const hex_charset = "0123456789abcdef";
const Hash = std.crypto.hash.sha2.Sha256;
const multihash_len = 1 + 1 + Hash.digest_length;
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
const HashedFile = struct {
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

const Package = @This();

root_src_directory: std.Build.Cache.Directory,

/// Whether to free `root_src_directory` on `destroy`.
root_src_directory_owned: bool = false,
allocator: std.mem.Allocator,

pub const Dependency = struct {
    url: []const u8,
    hash: ?[]const u8,
};

pub fn deinit(self: *Package) void {
    if (self.root_src_directory_owned)
        self.root_src_directory.closeAndFree(self.allocator);
}

pub fn fetchOneAndUnpack(
    allocator: std.mem.Allocator,
    cache_directory: []const u8, // directory to store things
    dep: Dependency, // thing to download
) !*Package {
    var http_client: std.http.Client = .{ .allocator = allocator };
    defer http_client.deinit();

    var global_cache_directory: std.Build.Cache.Directory = .{
        .handle = try std.fs.cwd().makeOpenPath(cache_directory, .{}),
        .path = cache_directory,
    };
    var thread_pool: std.Thread.Pool = undefined;
    try thread_pool.init(.{ .allocator = allocator });
    defer thread_pool.deinit();
    var progress: std.Progress = .{ .dont_print_on_dumb = true };
    const root_prog_node = progress.start("Fetch Packages", 0);
    defer root_prog_node.end();
    return try fetchAndUnpack(
        &thread_pool,
        &http_client,
        global_cache_directory,
        dep,
        dep.url,
        root_prog_node,
    );
}

pub fn fetchAndUnpack(
    thread_pool: *std.Thread.Pool, // thread pool for hashing things in parallel
    http_client: *std.http.Client, // client to download stuff
    global_cache_directory: std.Build.Cache.Directory, // directory to store things
    dep: Dependency, // thing to download
    fqn: []const u8, // used as name for thing downloaded
    root_prog_node: *std.Progress.Node, // used for outputting to terminal
) !*Package {
    const gpa = http_client.allocator;
    const s = std.fs.path.sep_str;

    // Check if the expected_hash is already present in the global package
    // cache, and thereby avoid both fetching and unpacking.
    if (dep.hash) |h| cached: {
        const hex_digest = h[0..hex_multihash_len];
        const pkg_dir_sub_path = "p" ++ s ++ hex_digest;

        const build_root = try global_cache_directory.join(gpa, &.{pkg_dir_sub_path});
        errdefer gpa.free(build_root);

        var pkg_dir = global_cache_directory.handle.openDir(pkg_dir_sub_path, .{}) catch |err| switch (err) {
            error.FileNotFound => break :cached,
            else => |e| return e,
        };
        errdefer pkg_dir.close();

        root_prog_node.completeOne();

        const ptr = try gpa.create(Package);
        errdefer gpa.destroy(ptr);

        ptr.* = .{
            .root_src_directory = .{
                .path = build_root,
                .handle = pkg_dir,
            },
            .root_src_directory_owned = true,
            .allocator = gpa,
        };

        return ptr;
    }

    var pkg_prog_node = root_prog_node.start(fqn, 0);
    defer pkg_prog_node.end();
    pkg_prog_node.activate();
    pkg_prog_node.context.refresh();

    const uri = try std.Uri.parse(dep.url);

    const rand_int = std.crypto.random.int(u64);
    const tmp_dir_sub_path = "tmp" ++ s ++ hex64(rand_int);

    const actual_hash = a: {
        var tmp_directory: std.Build.Cache.Directory = d: {
            const path = try global_cache_directory.join(gpa, &.{tmp_dir_sub_path});
            errdefer gpa.free(path);

            const iterable_dir = try global_cache_directory.handle.makeOpenPathIterable(tmp_dir_sub_path, .{});
            errdefer iterable_dir.close();

            break :d .{
                .path = path,
                .handle = iterable_dir.dir,
            };
        };
        defer tmp_directory.closeAndFree(gpa);

        var h = std.http.Headers{ .allocator = gpa };
        defer h.deinit();

        var req = try http_client.request(.GET, uri, h, .{});
        defer req.deinit();

        try req.start();
        try req.wait();

        if (req.response.status != .ok) {
            std.log.err("Expected response status '200 OK' got '{} {s}'", .{
                @intFromEnum(req.response.status),
                req.response.status.phrase() orelse "",
            });
            return error.UnexpectedResponseStatus;
        }

        const content_type = req.response.headers.getFirstValue("Content-Type") orelse
            return error.MissingContentTypeHeader;

        var prog_reader: ProgressReader(std.http.Client.Request.Reader) = .{
            .child_reader = req.reader(),
            .prog_node = &pkg_prog_node,
            .unit = if (req.response.content_length) |content_length| unit: {
                const kib = content_length / 1024;
                const mib = kib / 1024;
                if (mib > 0) {
                    pkg_prog_node.setEstimatedTotalItems(@intCast(mib));
                    pkg_prog_node.setUnit("MiB");
                    break :unit .mib;
                } else {
                    pkg_prog_node.setEstimatedTotalItems(@intCast(@max(1, kib)));
                    pkg_prog_node.setUnit("KiB");
                    break :unit .kib;
                }
            } else .any,
        };
        pkg_prog_node.context.refresh();

        if (std.ascii.eqlIgnoreCase(content_type, "application/gzip") or
            std.ascii.eqlIgnoreCase(content_type, "application/x-gzip") or
            std.ascii.eqlIgnoreCase(content_type, "application/tar+gzip"))
        {
            // I observed the gzip stream to read 1 byte at a time, so I am using a
            // buffered reader on the front of it.
            try unpackTarball(gpa, prog_reader.reader(), tmp_directory.handle, std.compress.gzip);
        } else if (std.ascii.eqlIgnoreCase(content_type, "application/x-xz")) {
            // I have not checked what buffer sizes the xz decompression implementation uses
            // by default, so the same logic applies for buffering the reader as for gzip.
            try unpackTarball(gpa, prog_reader.reader(), tmp_directory.handle, std.compress.xz);
        } else if (std.ascii.eqlIgnoreCase(content_type, "application/octet-stream")) {
            // support gitlab tarball urls such as https://gitlab.com/<namespace>/<project>/-/archive/<sha>/<project>-<sha>.tar.gz
            // whose content-disposition header is: 'attachment; filename="<project>-<sha>.tar.gz"'
            const content_disposition = req.response.headers.getFirstValue("Content-Disposition") orelse
                return error.@"Missing 'Content-Disposition' header for Content-Type=application/octet-stream";
            if (isTarAttachment(content_disposition)) {
                try unpackTarball(gpa, prog_reader.reader(), tmp_directory.handle, std.compress.gzip);
            } else {
                std.log.err("Unsupported 'Content-Disposition' header value: '{s}' for Content-Type=application/octet-stream", .{content_disposition});
                return error.UnsupportedContentDispositionHeader;
            }
        } else {
            std.log.err("Unsupported 'Content-Type' header value: '{s}'", .{content_type});
            return error.UnsupportedContentTypeHeader;
        }

        // Download completed - stop showing downloaded amount as progress
        pkg_prog_node.setEstimatedTotalItems(0);
        pkg_prog_node.setCompletedItems(0);
        pkg_prog_node.context.refresh();

        // TODO: delete files not included in the package prior to computing the package hash.
        // for example, if the ini file has directives to include/not include certain files,
        // apply those rules directly to the filesystem right here. This ensures that files
        // not protected by the hash are not present on the file system.

        // TODO: raise an error for files that have illegal paths on some operating systems.
        // For example, on Linux a path with a backslash should raise an error here.
        // Of course, if the ignore rules above omit the file from the package, then everything
        // is fine and no error should be raised.

        break :a try computePackageHash(thread_pool, .{ .dir = tmp_directory.handle });
    };

    const pkg_dir_sub_path = "p" ++ s ++ hexDigest(actual_hash);
    try renameTmpIntoCache(global_cache_directory.handle, tmp_dir_sub_path, pkg_dir_sub_path);

    const actual_hex = hexDigest(actual_hash);
    if (dep.hash) |h| {
        if (!std.mem.eql(u8, h, &actual_hex)) {
            std.log.err("hash mismatch: expected: {s}, found: {s}", .{
                h, actual_hex,
            });
            return error.HashMismatch;
        }
    } else {
        std.log.err("No hash supplied. Expecting hash \"{s}\"", .{actual_hex});
        return error.NoHashSupplied;
    }

    const build_root = try global_cache_directory.join(gpa, &.{pkg_dir_sub_path});
    defer gpa.free(build_root);

    const mod = try createWithDir(gpa, global_cache_directory, pkg_dir_sub_path);
    return mod;
}
fn hex64(x: u64) [16]u8 {
    var result: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const byte = @as(u8, @truncate(x >> @as(u6, @intCast(8 * i))));
        result[i * 2 + 0] = hex_charset[byte >> 4];
        result[i * 2 + 1] = hex_charset[byte & 15];
    }
    return result;
}
fn ProgressReader(comptime ReaderType: type) type {
    return struct {
        child_reader: ReaderType,
        bytes_read: u64 = 0,
        prog_node: *std.Progress.Node,
        unit: enum {
            kib,
            mib,
            any,
        },

        pub const Error = ReaderType.Error;
        pub const Reader = std.io.Reader(*@This(), Error, read);

        pub fn read(self: *@This(), buf: []u8) Error!usize {
            const amt = try self.child_reader.read(buf);
            self.bytes_read += amt;
            const kib = self.bytes_read / 1024;
            const mib = kib / 1024;
            switch (self.unit) {
                .kib => self.prog_node.setCompletedItems(@intCast(kib)),
                .mib => self.prog_node.setCompletedItems(@intCast(mib)),
                .any => {
                    if (mib > 0) {
                        self.prog_node.setUnit("MiB");
                        self.prog_node.setCompletedItems(@intCast(mib));
                    } else {
                        self.prog_node.setUnit("KiB");
                        self.prog_node.setCompletedItems(@intCast(kib));
                    }
                },
            }
            self.prog_node.context.maybeRefresh();
            return amt;
        }

        pub fn reader(self: *@This()) Reader {
            return .{ .context = self };
        }
    };
}
fn isTarAttachment(content_disposition: []const u8) bool {
    const disposition_type_end = std.ascii.indexOfIgnoreCase(content_disposition, "attachment;") orelse return false;

    var value_start = std.ascii.indexOfIgnoreCasePos(content_disposition, disposition_type_end + 1, "filename") orelse return false;
    value_start += "filename".len;
    if (content_disposition[value_start] == '*') {
        value_start += 1;
    }
    if (content_disposition[value_start] != '=') return false;
    value_start += 1;

    var value_end = std.mem.indexOfPos(u8, content_disposition, value_start, ";") orelse content_disposition.len;
    if (content_disposition[value_end - 1] == '\"') {
        value_end -= 1;
    }
    return std.ascii.endsWithIgnoreCase(content_disposition[value_start..value_end], ".tar.gz");
}
fn computePackageHash(
    thread_pool: *std.Thread.Pool,
    pkg_dir: std.fs.IterableDir,
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

    var walker = try pkg_dir.walk(gpa);
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
            const hashed_file = try arena.create(HashedFile);
            const fs_path = try arena.dupe(u8, entry.path);
            hashed_file.* = .{
                .fs_path = fs_path,
                .normalized_path = try normalizePath(arena, fs_path),
                .hash = undefined, // to be populated by the worker
                .failure = undefined, // to be populated by the worker
            };
            wait_group.start();
            try thread_pool.spawn(workerHashFile, .{ pkg_dir.dir, hashed_file, &wait_group });

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
    if (any_failures) return error.PackageHashUnavailable;
    return hasher.finalResult();
}
fn hexDigest(digest: [Hash.digest_length]u8) [multihash_len * 2]u8 {
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
fn renameTmpIntoCache(
    cache_dir: std.fs.Dir,
    tmp_dir_sub_path: []const u8,
    dest_dir_sub_path: []const u8,
) !void {
    std.debug.assert(dest_dir_sub_path[1] == std.fs.path.sep);
    var handled_missing_dir = false;
    while (true) {
        cache_dir.rename(tmp_dir_sub_path, dest_dir_sub_path) catch |err| switch (err) {
            error.FileNotFound => {
                if (handled_missing_dir) return err;
                cache_dir.makeDir(dest_dir_sub_path[0..1]) catch |mkd_err| switch (mkd_err) {
                    error.PathAlreadyExists => handled_missing_dir = true,
                    else => |e| return e,
                };
                continue;
            },
            error.PathAlreadyExists, error.AccessDenied => {
                // Package has been already downloaded and may already be in use on the system.
                cache_dir.deleteTree(tmp_dir_sub_path) catch |del_err| {
                    std.log.warn("unable to delete temp directory: {s}", .{@errorName(del_err)});
                };
            },
            else => |e| return e,
        };
        break;
    }
}

fn createWithDir(
    gpa: std.mem.Allocator,
    directory: std.Build.Cache.Directory,
    /// Relative to `directory`. If null, means `directory` is the root src dir
    /// and is owned externally.
    root_src_dir_path: ?[]const u8,
) !*Package {
    const ptr = try gpa.create(Package);
    errdefer gpa.destroy(ptr);

    if (root_src_dir_path) |p| {
        const owned_dir_path = try directory.join(gpa, &[1][]const u8{p});
        errdefer gpa.free(owned_dir_path);

        ptr.* = .{
            .root_src_directory = .{
                .path = owned_dir_path,
                .handle = try directory.handle.openDir(p, .{}),
            },
            .root_src_directory_owned = true,
            .allocator = gpa,
        };
    } else {
        ptr.* = .{
            .root_src_directory = directory,
            .root_src_directory_owned = false,
            .allocator = gpa,
        };
    }
    return ptr;
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

// Create/Write a file, close it, then grab its stat.mtime timestamp.
fn testGetCurrentFileTimestamp(dir: std.fs.Dir) !i128 {
    const test_out_file = "test-filetimestamp.tmp";

    var file = try dir.createFile(test_out_file, .{
        .read = true,
        .truncate = true,
    });
    defer {
        file.close();
        dir.deleteFile(test_out_file) catch {};
    }

    return (try file.stat()).mtime;
}

// These functions come from src/Package.zig, src/Manifest.zig in the compiler,
// not the standard library
fn unpackTarball(
    gpa: std.mem.Allocator,
    req_reader: anytype,
    out_dir: std.fs.Dir,
    comptime compression: type,
) !void {
    var br = std.io.bufferedReaderSize(std.crypto.tls.max_ciphertext_record_len, req_reader);

    var decompress = try compression.decompress(gpa, br.reader());
    defer decompress.deinit();

    try std.tar.pipeToFileSystem(out_dir, decompress.reader(), .{
        .strip_components = 1,
        // TODO: we would like to set this to executable_bit_only, but two
        // things need to happen before that:
        // 1. the tar implementation needs to support it
        // 2. the hashing algorithm here needs to support detecting the is_executable
        //    bit on Windows from the ACLs (see the isExecutable function).
        .mode_mode = .ignore,
    });
}

test {
    std.testing.refAllDecls(@This());
}
test "cache a file and recall it" {
    if (builtin.os.tag == .wasi) {
        // https://github.com/ziglang/zig/issues/5437

        return error.SkipZigTest;
    }

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const temp_file = "test.txt";
    const temp_file2 = "test2.txt";
    const temp_manifest_dir = "temp_manifest_dir";

    try tmp.dir.writeFile(temp_file, "Hello, world!\n");
    try tmp.dir.writeFile(temp_file2, "yo mamma\n");

    // Wait for file timestamps to tick

    const initial_time = try testGetCurrentFileTimestamp(tmp.dir);
    while ((try testGetCurrentFileTimestamp(tmp.dir)) == initial_time) {
        std.time.sleep(1);
    }

    var digest1: [hex_digest_len]u8 = undefined;
    var digest2: [hex_digest_len]u8 = undefined;

    {
        var cache = std.build.Cache{
            .gpa = testing.allocator,
            .manifest_dir = try tmp.dir.makeOpenPath(temp_manifest_dir, .{}),
        };
        cache.addPrefix(.{ .path = null, .handle = tmp.dir });
        defer cache.manifest_dir.close();

        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.add(true);
            ch.hash.add(@as(u16, 1234));
            ch.hash.addBytes("1234");
            _ = try ch.addFile(temp_file, null);

            // There should be nothing in the cache

            try testing.expectEqual(false, try ch.hit());

            digest1 = ch.final();
            try ch.writeManifest();
        }
        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.add(true);
            ch.hash.add(@as(u16, 1234));
            ch.hash.addBytes("1234");
            _ = try ch.addFile(temp_file, null);

            // Cache hit! We just "built" the same file

            try testing.expect(try ch.hit());
            digest2 = ch.final();

            try testing.expectEqual(false, ch.have_exclusive_lock);
        }

        try testing.expectEqual(digest1, digest2);
    }
}
test "fetch and unpack" {
    const alloc = std.testing.allocator;
    var http_client: std.http.Client = .{ .allocator = alloc };
    defer http_client.deinit();

    var global_cache_directory: std.Build.Cache.Directory = .{
        .handle = try std.fs.cwd().makeOpenPath("test-pkg", .{}),
        .path = "test-pkg",
    };
    var thread_pool: std.Thread.Pool = undefined;
    try thread_pool.init(.{ .allocator = alloc });
    defer thread_pool.deinit();
    var progress: std.Progress = .{ .dont_print_on_dumb = true };
    const root_prog_node = progress.start("Fetch Packages", 0);
    defer root_prog_node.end();
    const pkg = try fetchAndUnpack(
        &thread_pool,
        &http_client,
        global_cache_directory,
        .{
            .url = "https://github.com/aws/aws-sdk-go-v2/archive/7502ff360b1c3b79cbe117437327f6ff5fb89f65.tar.gz",
            .hash = "1220a414719bff14c9362fb1c695e3346fa12ec2e728bae5757a57aae7738916ffd2",
        },
        "https://github.com/aws/aws-sdk-go-v2/archive/7502ff360b1c3b79cbe117437327f6ff5fb89f65.tar.gz",
        root_prog_node,
    );
    defer alloc.destroy(pkg);
    defer pkg.deinit();
}
test "fetch one and unpack" {
    const pkg = try fetchOneAndUnpack(
        std.testing.allocator,
        "test-pkg",
        .{
            .url = "https://github.com/aws/aws-sdk-go-v2/archive/7502ff360b1c3b79cbe117437327f6ff5fb89f65.tar.gz",
            .hash = "1220a414719bff14c9362fb1c695e3346fa12ec2e728bae5757a57aae7738916ffd2",
        },
    );
    defer std.testing.allocator.destroy(pkg);
    defer pkg.deinit();
    try std.testing.expectEqualStrings(
        "test-pkg/p/1220a414719bff14c9362fb1c695e3346fa12ec2e728bae5757a57aae7738916ffd2",
        pkg.root_src_directory.path.?,
    );
}
test "isTarAttachment" {
    try std.testing.expect(isTarAttachment("attaChment; FILENAME=\"stuff.tar.gz\"; size=42"));
    try std.testing.expect(isTarAttachment("attachment; filename*=\"stuff.tar.gz\""));
    try std.testing.expect(isTarAttachment("ATTACHMENT; filename=\"stuff.tar.gz\""));
    try std.testing.expect(isTarAttachment("attachment; FileName=\"stuff.tar.gz\""));
    try std.testing.expect(isTarAttachment("attachment; FileName*=UTF-8\'\'xyz%2Fstuff.tar.gz"));

    try std.testing.expect(!isTarAttachment("attachment FileName=\"stuff.tar.gz\""));
    try std.testing.expect(!isTarAttachment("attachment; FileName=\"stuff.tar\""));
    try std.testing.expect(!isTarAttachment("attachment; FileName\"stuff.gz\""));
    try std.testing.expect(!isTarAttachment("attachment; size=42"));
    try std.testing.expect(!isTarAttachment("inline; size=42"));
    try std.testing.expect(!isTarAttachment("FileName=\"stuff.tar.gz\"; attachment;"));
    try std.testing.expect(!isTarAttachment("FileName=\"stuff.tar.gz\";"));
}

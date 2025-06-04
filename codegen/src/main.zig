const std = @import("std");
const smithy = @import("smithy");
const Hasher = @import("Hasher.zig");
const case = @import("case");

var verbose = false;

const Shape = @FieldType(smithy.ShapeInfo, "shape");
const ServiceShape = @TypeOf((Shape{ .service = undefined }).service);
const ListShape = @TypeOf((Shape{ .list = undefined }).list);
const MapShape = @TypeOf((Shape{ .map = undefined }).map);

pub fn main() anyerror!void {
    const root_progress_node = std.Progress.start(.{});
    defer root_progress_node.end();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const stdout = std.io.getStdOut().writer();

    var output_dir = std.fs.cwd();
    defer if (output_dir.fd > 0) output_dir.close();
    var models_dir: ?std.fs.Dir = null;
    defer if (models_dir) |*m| m.close();
    for (args, 0..) |arg, i| {
        if (std.mem.eql(u8, "--help", arg) or
            std.mem.eql(u8, "-h", arg))
        {
            try stdout.print("usage: {s} [--verbose] [--models dir] [--output dir] [file...]\n\n", .{args[0]});
            try stdout.print(" --models specifies a directory with all model files (do not specify files if --models is used)\n", .{});
            try stdout.print(" --output specifies an output directory, otherwise the current working directory will be used\n", .{});
            std.process.exit(0);
        }
        if (std.mem.eql(u8, "--output", arg))
            output_dir = try output_dir.makeOpenPath(args[i + 1], .{});
        if (std.mem.eql(u8, "--models", arg))
            models_dir = try std.fs.cwd().openDir(args[i + 1], .{ .iterate = true });
    }

    // TODO: We need a different way to handle this file...
    const manifest_file_started = false;
    var manifest_file: std.fs.File = undefined;
    defer if (manifest_file_started) manifest_file.close();
    var manifest: std.fs.File.Writer = undefined;
    var files_processed: usize = 0;
    var skip_next = true;
    for (args) |arg| {
        if (skip_next) {
            skip_next = false;
            continue;
        }
        if (std.mem.eql(u8, "--verbose", arg)) {
            verbose = true;
            continue;
        }

        if (std.mem.eql(u8, "--models", arg) or
            std.mem.eql(u8, "--output", arg))
        {
            skip_next = true;
            continue;
        }
        if (!manifest_file_started) {
            manifest_file = try output_dir.createFile("service_manifest.zig", .{});
            manifest = manifest_file.writer();
        }
        try processFile(arg, output_dir, manifest);
        files_processed += 1;
    }
    if (files_processed == 0) {
        // no files specified, look for json files in models directory or cwd
        // this is our normal mode of operation and where initial optimizations
        // can be made

        if (models_dir) |m| {
            var cwd = try std.fs.cwd().openDir(".", .{});
            defer cwd.close();
            defer cwd.setAsCwd() catch unreachable;

            try m.setAsCwd();
            try processDirectories(m, output_dir, &root_progress_node);
        }
    }

    if (args.len == 0)
        _ = try generateServices(allocator, ";", std.io.getStdIn(), stdout);

    if (verbose) {
        const output_path = try output_dir.realpathAlloc(allocator, ".");
        std.debug.print("Output path: {s}\n", .{output_path});
    }
}

const OutputManifest = struct {
    model_dir_hash_digest: [Hasher.hex_multihash_len]u8,
    output_dir_hash_digest: [Hasher.hex_multihash_len]u8,
};
fn processDirectories(models_dir: std.fs.Dir, output_dir: std.fs.Dir, parent_progress: *const std.Progress.Node) !void {
    // Let's get ready to hash!!
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var thread_pool: std.Thread.Pool = undefined;
    try thread_pool.init(.{ .allocator = allocator });
    defer thread_pool.deinit();

    const count, var calculated_manifest = try calculateDigests(models_dir, output_dir, &thread_pool);
    const output_stored_manifest = output_dir.readFileAlloc(allocator, "output_manifest.json", std.math.maxInt(usize)) catch null;
    if (output_stored_manifest) |o| {
        // we have a stored manifest. Parse it and compare to our calculations
        // we can leak as we're using an arena allocator
        const stored_manifest = try std.json.parseFromSliceLeaky(OutputManifest, allocator, o, .{});
        if (std.mem.eql(u8, &stored_manifest.model_dir_hash_digest, &calculated_manifest.model_dir_hash_digest) and
            std.mem.eql(u8, &stored_manifest.output_dir_hash_digest, &calculated_manifest.output_dir_hash_digest))
        {
            // hashes all match, we can end now
            if (verbose)
                std.log.info("calculated hashes match output_manifest.json. Nothing to do", .{});
            return;
        }
    }
    // Do this in a brain dead fashion from here, no optimization
    const manifest_file = try output_dir.createFile("service_manifest.zig", .{});
    defer manifest_file.close();
    const manifest = manifest_file.writer();
    var mi = models_dir.iterate();

    const generating_models_progress = parent_progress.start("generating models", count);
    defer generating_models_progress.end();

    while (try mi.next()) |e| {
        if ((e.kind == .file or e.kind == .sym_link) and std.mem.endsWith(u8, e.name, ".json")) {
            try processFile(e.name, output_dir, manifest);
            generating_models_progress.completeOne();
        }
    }
    // re-calculate so we can store the manifest
    model_digest = calculated_manifest.model_dir_hash_digest;
    _, calculated_manifest = try calculateDigests(models_dir, output_dir, &thread_pool);
    try output_dir.writeFile(.{ .sub_path = "output_manifest.json", .data = try std.json.stringifyAlloc(
        allocator,
        calculated_manifest,
        .{ .whitespace = .indent_2 },
    ) });
}

var model_digest: ?[Hasher.hex_multihash_len]u8 = null;
fn calculateDigests(models_dir: std.fs.Dir, output_dir: std.fs.Dir, thread_pool: *std.Thread.Pool) !struct { usize, OutputManifest } {
    const Include = struct {
        threadlocal var count: usize = 0;
        pub fn include(entry: std.fs.Dir.Walker.Entry) bool {
            const included = std.mem.endsWith(u8, entry.basename, ".json");
            if (included) count += 1;
            return included;
        }
    };

    const model_hash = if (model_digest) |m| m[0..Hasher.digest_len].* else try Hasher.computeDirectoryHash(thread_pool, models_dir, @constCast(&Hasher.ComputeDirectoryOptions{
        .isIncluded = Include.include,
        .isExcluded = struct {
            pub fn exclude(entry: std.fs.Dir.Walker.Entry) bool {
                _ = entry;
                return false;
            }
        }.exclude,
        .needFileHashes = false,
    }));
    if (verbose) std.log.info("Model directory hash: {s}", .{model_digest orelse Hasher.hexDigest(model_hash)});

    const output_hash = try Hasher.computeDirectoryHash(thread_pool, try output_dir.openDir(".", .{ .iterate = true }), @constCast(&Hasher.ComputeDirectoryOptions{
        .isIncluded = struct {
            pub fn include(entry: std.fs.Dir.Walker.Entry) bool {
                return std.mem.endsWith(u8, entry.basename, ".zig");
            }
        }.include,
        .isExcluded = struct {
            pub fn exclude(entry: std.fs.Dir.Walker.Entry) bool {
                _ = entry;
                return false;
            }
        }.exclude,
        .needFileHashes = false,
    }));
    if (verbose) std.log.info("Output directory hash: {s}", .{Hasher.hexDigest(output_hash)});
    return .{
        Include.count, .{
            .model_dir_hash_digest = model_digest orelse Hasher.hexDigest(model_hash),
            .output_dir_hash_digest = Hasher.hexDigest(output_hash),
        },
    };
}
fn processFile(file_name: []const u8, output_dir: std.fs.Dir, manifest: anytype) !void {
    // It's probably best to create our own allocator here so we can deint at the end and
    // toss all allocations related to the services in this file
    // I can't guarantee we're not leaking something, and at the end of the
    // day I'm not sure we want to track down leaks
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var output = try std.ArrayListUnmanaged(u8).initCapacity(allocator, 1024 * 1024 * 2);
    defer output.deinit(allocator);

    var counting_writer = std.io.countingWriter(output.writer(allocator));
    var writer = counting_writer.writer();

    _ = try writer.write("const std = @import(\"std\");\n");
    _ = try writer.write("const smithy = @import(\"smithy\");\n");
    _ = try writer.write("const json = @import(\"json\");\n");
    _ = try writer.write("const date = @import(\"date\");\n");
    _ = try writer.write("const zeit = @import(\"zeit\");\n");
    _ = try writer.write("\n");
    _ = try writer.write("const serializeMap = json.serializeMap;\n");
    _ = try writer.write("\n");

    if (verbose) std.log.info("Processing file: {s}", .{file_name});

    const service_names = generateServicesForFilePath(allocator, ";", file_name, writer) catch |err| {
        std.log.err("Error processing file: {s}", .{file_name});
        return err;
    };

    var output_file_name: []const u8 = try std.mem.join(allocator, "-", service_names);

    if (output_file_name.len == 0) {
        const ext = std.fs.path.extension(file_name);
        output_file_name = file_name[0 .. file_name.len - ext.len];
    }

    {
        // append .zig on to the file name
        const new_output_file_name = try std.fmt.allocPrint(
            allocator,
            "{s}.zig",
            .{output_file_name},
        );
        allocator.free(output_file_name);
        output_file_name = new_output_file_name;
    }

    const unformatted: [:0]const u8 = try output.toOwnedSliceSentinel(allocator, 0);
    const formatted = try zigFmt(allocator, unformatted);

    // Dump our buffer out to disk
    var file = try output_dir.createFile(output_file_name, .{ .truncate = true });
    defer file.close();
    try file.writeAll(formatted);

    for (service_names) |name| {
        try manifest.print("pub const {s} = @import(\"{s}\");\n", .{ name, std.fs.path.basename(output_file_name) });
    }
}

fn zigFmt(allocator: std.mem.Allocator, buffer: [:0]const u8) ![]const u8 {
    var tree = try std.zig.Ast.parse(allocator, buffer, .zig);
    defer tree.deinit(allocator);

    return try tree.render(allocator);
}

fn generateServicesForFilePath(
    allocator: std.mem.Allocator,
    comptime terminator: []const u8,
    path: []const u8,
    writer: anytype,
) ![][]const u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try generateServices(allocator, terminator, file, writer);
}

fn addReference(id: []const u8, map: *std.StringHashMap(u64)) !void {
    const res = try map.getOrPut(id);
    if (res.found_existing) {
        res.value_ptr.* += 1;
    } else {
        res.value_ptr.* = 1;
    }
}
fn countAllReferences(shape_ids: [][]const u8, shapes: std.StringHashMap(smithy.ShapeInfo), shape_references: *std.StringHashMap(u64), stack: *std.ArrayList([]const u8)) anyerror!void {
    for (shape_ids) |id| {
        const shape = shapes.get(id);
        if (shape == null) {
            std.log.err("Error - could not find shape with id {s}", .{id});
            return error.ShapeNotFound;
        }
        try countReferences(shape.?, shapes, shape_references, stack);
    }
}
fn countTypeMembersReferences(type_members: []smithy.TypeMember, shapes: std.StringHashMap(smithy.ShapeInfo), shape_references: *std.StringHashMap(u64), stack: *std.ArrayList([]const u8)) anyerror!void {
    for (type_members) |m| {
        const target = shapes.get(m.target);
        if (target == null) {
            std.log.err("Error - could not find target {s}", .{m.target});
            return error.TargetNotFound;
        }
        try countReferences(target.?, shapes, shape_references, stack);
    }
}

fn countReferences(shape: smithy.ShapeInfo, shapes: std.StringHashMap(smithy.ShapeInfo), shape_references: *std.StringHashMap(u64), stack: *std.ArrayList([]const u8)) anyerror!void {
    // Add ourselves as a reference, then we will continue down the tree
    try addReference(shape.id, shape_references);
    // Put ourselves on the stack. If we come back to ourselves, we want to end.
    for (stack.items) |i| {
        if (std.mem.eql(u8, shape.id, i))
            return;
    }
    try stack.append(shape.id);
    defer _ = stack.pop();
    // Well, this is a fun read: https://awslabs.github.io/smithy/1.0/spec/core/model.html#recursive-shape-definitions
    // Looks like recursion has special rules in the spec to accomodate Java.
    // This is silly and we will ignore
    switch (shape.shape) {
        // We don't care about these primitives - they don't have children
        .blob,
        .boolean,
        .string,
        .byte,
        .short,
        .integer,
        .long,
        .float,
        .double,
        .bigInteger,
        .bigDecimal,
        .timestamp,
        .unit,
        => {},
        .document, .member, .resource => {}, // less sure about these?
        .list => |i| try countReferences(shapes.get(i.member_target).?, shapes, shape_references, stack),
        .set => |i| try countReferences(shapes.get(i.member_target).?, shapes, shape_references, stack),
        .map => |i| {
            try countReferences(shapes.get(i.key).?, shapes, shape_references, stack);
            try countReferences(shapes.get(i.value).?, shapes, shape_references, stack);
        },
        .structure => |m| try countTypeMembersReferences(m.members, shapes, shape_references, stack),
        .uniontype => |m| try countTypeMembersReferences(m.members, shapes, shape_references, stack),
        .service => |i| try countAllReferences(i.operations, shapes, shape_references, stack),
        .operation => |op| {
            if (op.input) |i| {
                const val = shapes.get(i);
                if (val == null) {
                    std.log.err("Error processing shape with id \"{s}\". Input shape \"{s}\" was not found", .{ shape.id, i });
                    return error.ShapeNotFound;
                }
                try countReferences(val.?, shapes, shape_references, stack);
            }
            if (op.output) |i| {
                const val = shapes.get(i);
                if (val == null) {
                    std.log.err("Error processing shape with id \"{s}\". Output shape \"{s}\" was not found", .{ shape.id, i });
                    return error.ShapeNotFound;
                }
                try countReferences(val.?, shapes, shape_references, stack);
            }
            if (op.errors) |i| try countAllReferences(i, shapes, shape_references, stack);
        },
        .@"enum" => |m| try countTypeMembersReferences(m.members, shapes, shape_references, stack),
    }
}

fn generateServices(allocator: std.mem.Allocator, comptime _: []const u8, file: std.fs.File, writer: anytype) ![][]const u8 {
    const json = try file.readToEndAlloc(allocator, 1024 * 1024 * 1024);
    defer allocator.free(json);
    const model = try smithy.parse(allocator, json);
    defer model.deinit();
    var shapes = std.StringHashMap(smithy.ShapeInfo).init(allocator);
    defer shapes.deinit();
    var services = std.ArrayList(smithy.ShapeInfo).init(allocator);
    defer services.deinit();
    for (model.shapes) |shape| {
        try shapes.put(shape.id, shape);
        switch (shape.shape) {
            .service => try services.append(shape),
            else => {},
        }
    }
    // At this point we want to generate a graph of shapes, starting
    // services -> operations -> other shapes. This will allow us to get
    // a reference count in case there are recursive data structures
    var shape_references = std.StringHashMap(u64).init(allocator);
    defer shape_references.deinit();
    var stack = std.ArrayList([]const u8).init(allocator);
    defer stack.deinit();
    for (services.items) |service|
        try countReferences(service, shapes, &shape_references, &stack);

    var constant_names = std.ArrayList([]const u8).init(allocator);
    defer constant_names.deinit();
    var unresolved = std.ArrayList(smithy.ShapeInfo).init(allocator);
    defer unresolved.deinit();
    var generated = std.StringHashMap(void).init(allocator);
    defer generated.deinit();

    var state = FileGenerationState{
        .protocol = undefined,
        .shape_references = shape_references,
        .additional_types_to_generate = &unresolved,
        .additional_types_generated = &generated,
        .shapes = shapes,
    };
    for (services.items) |service| {
        var sdk_id: []const u8 = undefined;
        const version: ?[]const u8 = service.shape.service.version;
        const name: []const u8 = service.name;
        var arn_namespace: ?[]const u8 = undefined;
        var sigv4_name: ?[]const u8 = null;
        var endpoint_prefix: []const u8 = undefined;
        var aws_protocol: smithy.AwsProtocol = undefined;
        for (service.shape.service.traits) |trait| {
            // need the info/get the info
            switch (trait) {
                .aws_api_service => {
                    arn_namespace = trait.aws_api_service.arn_namespace;
                    sdk_id = trait.aws_api_service.sdk_id;
                    endpoint_prefix = trait.aws_api_service.endpoint_prefix;
                },
                .aws_auth_sigv4 => sigv4_name = trait.aws_auth_sigv4.name,
                .aws_protocol => {
                    aws_protocol = trait.aws_protocol;
                    state.protocol = aws_protocol;
                },
                else => {},
            }
        }
        if (sigv4_name == null) {
            // This is true for CodeCatalyst, that operates a bit differently
            std.log.debug("No sigv4 name found. Service '{s}' cannot be accessed via standard methods. Skipping", .{name});
            continue;
        }

        // Service struct
        // name of the field will be snake_case of whatever comes in from
        // sdk_id. Not sure this will simple...
        const constant_name = try constantName(allocator, sdk_id, .snake);
        try constant_names.append(constant_name);
        try writer.print("const Self = @This();\n", .{});
        if (version) |v|
            try writer.print("pub const version: ?[]const u8 = \"{s}\";\n", .{v})
        else
            try writer.print("pub const version: ?[]const u8 = null;\n", .{});
        try writer.print("pub const sdk_id: []const u8 = \"{s}\";\n", .{sdk_id});
        if (arn_namespace) |a| {
            try writer.print("pub const arn_namespace: ?[]const u8 = \"{s}\";\n", .{a});
        } else try writer.print("pub const arn_namespace: ?[]const u8 = null;\n", .{});
        try writer.print("pub const endpoint_prefix: []const u8 = \"{s}\";\n", .{endpoint_prefix});
        try writer.print("pub const sigv4_name: []const u8 = \"{s}\";\n", .{sigv4_name.?});
        try writer.print("pub const name: []const u8 = \"{s}\";\n", .{name});
        // TODO: This really should just be ".whatevs". We're fully qualifying here, which isn't typical
        try writer.print("pub const aws_protocol: smithy.AwsProtocol = {};\n\n", .{aws_protocol});
        _ = try writer.write("pub const service_metadata: struct {\n");
        if (version) |v|
            try writer.print("    version: ?[]const u8 = \"{s}\",\n", .{v})
        else
            try writer.print("    version: ?[]const u8 = null,\n", .{});
        try writer.print("    sdk_id: []const u8 = \"{s}\",\n", .{sdk_id});
        if (arn_namespace) |a| {
            try writer.print("    arn_namespace: ?[]const u8 = \"{s}\",\n", .{a});
        } else try writer.print("    arn_namespace: ?[]const u8 = null,\n", .{});
        try writer.print("    endpoint_prefix: []const u8 = \"{s}\",\n", .{endpoint_prefix});
        try writer.print("    sigv4_name: []const u8 = \"{s}\",\n", .{sigv4_name.?});
        try writer.print("    name: []const u8 = \"{s}\",\n", .{name});
        // TODO: This really should just be ".whatevs". We're fully qualifying here, which isn't typical
        try writer.print("    aws_protocol: smithy.AwsProtocol = {},\n", .{aws_protocol});
        _ = try writer.write("} = .{};\n");

        // Operations
        for (service.shape.service.operations) |op|
            try generateOperation(allocator, shapes.get(op).?, state, writer);
    }
    try generateAdditionalTypes(allocator, state, writer);
    return constant_names.toOwnedSlice();
}

fn generateAdditionalTypes(allocator: std.mem.Allocator, file_state: FileGenerationState, writer: anytype) !void {
    // More types may be added during processing
    while (file_state.additional_types_to_generate.pop()) |t| {
        if (file_state.additional_types_generated.getEntry(t.name) != null) continue;
        // std.log.info("\t\t{s}", .{t.name});
        var type_stack = std.ArrayList(*const smithy.ShapeInfo).init(allocator);
        defer type_stack.deinit();
        const state = GenerationState{
            .type_stack = &type_stack,
            .file_state = file_state,
            .allocator = allocator,
            .indent_level = 0,
        };
        const type_name = try getTypeName(allocator, t);
        defer allocator.free(type_name);

        try writer.print("\npub const {s} = ", .{type_name});
        try file_state.additional_types_generated.putNoClobber(t.name, {});
        _ = try generateTypeFor(t.id, writer, state, .{
            .key_case = .snake,
            .end_structure = true,
        });
        _ = try writer.write(";\n");
    }
}

fn constantName(allocator: std.mem.Allocator, id: []const u8, comptime to_case: case.Case) ![]const u8 {
    // There are some ids that don't follow consistent rules, so we'll
    // look for the exceptions and, if not found, revert to the snake case
    // algorithm

    var buf = std.mem.zeroes([256]u8);
    @memcpy(buf[0..id.len], id);

    var name = try allocator.dupe(u8, id);

    const simple_replacements = &.{
        &.{ "DevOps", "Devops" },
        &.{ "IoT", "Iot" },
        &.{ "FSx", "Fsx" },
        &.{ "CloudFront", "Cloudfront" },
    };

    inline for (simple_replacements) |rep| {
        if (std.mem.indexOf(u8, name, rep[0])) |idx| @memcpy(name[idx .. idx + rep[0].len], rep[1]);
    }

    if (to_case == .snake) {
        if (std.mem.eql(u8, id, "SESv2")) return try std.fmt.allocPrint(allocator, "ses_v2", .{});
        if (std.mem.eql(u8, id, "ETag")) return try std.fmt.allocPrint(allocator, "e_tag", .{});
    }

    return try case.allocTo(allocator, to_case, name);
}

const FileGenerationState = struct {
    protocol: smithy.AwsProtocol,
    shapes: std.StringHashMap(smithy.ShapeInfo),
    shape_references: std.StringHashMap(u64),
    additional_types_to_generate: *std.ArrayList(smithy.ShapeInfo),
    additional_types_generated: *std.StringHashMap(void),
};

const GenerationState = struct {
    type_stack: *std.ArrayList(*const smithy.ShapeInfo),
    file_state: FileGenerationState,
    // we will need some sort of "type decls needed" for recursive structures
    allocator: std.mem.Allocator,
    indent_level: u64,

    fn appendToTypeStack(self: @This(), shape_info: *const smithy.ShapeInfo) !void {
        try self.type_stack.append(shape_info);
    }

    fn popFromTypeStack(self: @This()) void {
        _ = self.type_stack.pop();
    }

    fn getTypeRecurrenceCount(self: @This(), id: []const u8) u8 {
        var self_occurences: u8 = 0;

        for (self.type_stack.items) |i| {
            if (std.mem.eql(u8, i.id, id)) {
                self_occurences += 1;
            }
        }

        return self_occurences;
    }

    fn indent(self: @This()) GenerationState {
        var new_state = self.clone();
        new_state.indent_level += 1;
        return new_state;
    }

    fn deindent(self: @This()) GenerationState {
        var new_state = self.clone();
        new_state.indent_level = @max(0, new_state.indent_level - 1);
        return new_state;
    }

    fn clone(self: @This()) GenerationState {
        return GenerationState{
            .type_stack = self.type_stack,
            .file_state = self.file_state,
            .allocator = self.allocator,
            .indent_level = self.indent_level,
        };
    }
};

fn outputIndent(state: GenerationState, writer: anytype) !void {
    const n_chars = 4 * state.indent_level;
    try writer.writeByteNTimes(' ', n_chars);
}

const StructType = enum {
    request,
    response,
    apiRequest,
    apiResponse,
};

const OperationSubTypeInfo = struct {
    type: StructType,
    key_case: case.Case,
};

const operation_sub_types = [_]OperationSubTypeInfo{
    OperationSubTypeInfo{
        .key_case = .snake,
        .type = .request,
    },
    OperationSubTypeInfo{
        .key_case = .snake,
        .type = .response,
    },
    // OperationSubTypeInfo{
    //     .key_case = .pascal,
    //     .type = .apiRequest,
    // },
    // OperationSubTypeInfo{
    //     .key_case = .pascal,
    //     .type = .apiResponse,
    // },
};

fn generateOperation(allocator: std.mem.Allocator, operation: smithy.ShapeInfo, file_state: FileGenerationState, writer: anytype) !void {
    const snake_case_name = try constantName(allocator, operation.name, .snake);
    defer allocator.free(snake_case_name);

    var type_stack = std.ArrayList(*const smithy.ShapeInfo).init(allocator);
    defer type_stack.deinit();
    const state = GenerationState{
        .type_stack = &type_stack,
        .file_state = file_state,
        .allocator = allocator,
        .indent_level = 1,
    };
    var child_state = state;
    child_state.indent_level += 1;
    // indent should start at 4 spaces here
    const operation_name = avoidReserved(snake_case_name);

    inline for (operation_sub_types) |type_info| {
        _ = try writer.print("pub const {s}", .{operation.name});
        switch (type_info.type) {
            .request => try writer.writeAll("Request"),
            .response => try writer.writeAll("Response"),
            .apiRequest => try writer.writeAll("ApiRequest"),
            .apiResponse => try writer.writeAll("ApiResponse"),
        }
        try writer.writeAll(" = ");

        const operation_field_name = switch (type_info.type) {
            .request, .apiRequest => "input",
            .response, .apiResponse => "output",
        };
        const maybe_shape_id = @field(operation.shape.operation, operation_field_name);

        const generate_type_options = GenerateTypeOptions{
            .key_case = type_info.key_case,
            .end_structure = false,
        };

        if (maybe_shape_id == null or
            (try shapeInfoForId(maybe_shape_id.?, state.file_state.shapes)).shape == .unit)
        {
            _ = try writer.write("struct {\n");
        } else if (maybe_shape_id) |shape_id| {
            if (try generateTypeFor(shape_id, writer, state, generate_type_options)) unreachable; // we expect only structs here
            _ = try writer.write("\n");

            switch (type_info.type) {
                .request => {
                    var new_state = state.clone();
                    new_state.indent_level = 0;
                    std.debug.assert(new_state.type_stack.items.len == 0);

                    try generateToJsonFunction(shape_id, writer.any(), new_state, generate_type_options.keyCase(.pascal));

                    try writer.writeAll("\n");
                },
                else => {},
            }
        }

        try generateMetadataFunction(operation_name, state, writer, generate_type_options);

        _ = try writer.write("};\n\n");
    }

    try writer.print("pub const {s}: struct ", .{operation_name});
    _ = try writer.write("{\n");
    for (operation.shape.operation.traits) |trait| {
        if (trait == .http) {
            try outputIndent(state, writer);
            _ = try writer.write("pub const http_config = .{\n");
            try outputIndent(child_state, writer);
            try writer.print(".method = \"{s}\",\n", .{trait.http.method});
            try outputIndent(child_state, writer);
            try writer.print(".uri = \"{s}\",\n", .{trait.http.uri});
            try outputIndent(child_state, writer);
            try writer.print(".success_code = {d},\n", .{trait.http.code});
            try outputIndent(state, writer);
            _ = try writer.write("};\n\n");
        }
    }

    try outputIndent(state, writer);
    try writer.print("action_name: []const u8 = \"{s}\",\n", .{operation.name});
    try outputIndent(state, writer);
    _ = try writer.print("Request: type = {s}Request,\n", .{operation.name});

    try outputIndent(state, writer);
    _ = try writer.print("Response: type = {s}Response,\n", .{operation.name});

    if (operation.shape.operation.errors) |errors| {
        try outputIndent(state, writer);
        _ = try writer.write("ServiceError: type = error{\n");
        for (errors) |err| {
            const err_name = getErrorName(file_state.shapes.get(err).?.name); // need to remove "exception"
            try outputIndent(child_state, writer);
            try writer.print("{s},\n", .{err_name});
        }
        try outputIndent(state, writer);
        _ = try writer.write("},\n");
    }
    _ = try writer.write("} = .{};\n");
}

fn generateMetadataFunction(operation_name: []const u8, state: GenerationState, writer: anytype, options: GenerateTypeOptions) !void {
    // TODO: Shove these lines in here, and also the else portion
    // pub fn metaInfo(self: @This()) struct { service: @TypeOf(sts), action: @TypeOf(sts.get_caller_identity) } {
    //     return .{ .service = sts, .action = sts.get_caller_identity };
    // }
    // We want to add a short "get my parents" function into the response
    var child_state = state;
    child_state.indent_level += 1;
    try outputIndent(child_state, writer);
    _ = try writer.write("pub fn metaInfo() struct { ");
    try writer.print("service_metadata: @TypeOf(service_metadata), action: @TypeOf({s})", .{operation_name});
    _ = try writer.write(" } {\n");
    child_state.indent_level += 1;
    try outputIndent(child_state, writer);
    _ = try writer.write("return .{ .service_metadata = service_metadata, ");
    try writer.print(".action = {s}", .{operation_name});
    _ = try writer.write(" };\n");
    child_state.indent_level -= 1;
    try outputIndent(child_state, writer);
    _ = try writer.write("}\n");
    try outputIndent(state, writer);

    if (options.end_structure) {
        try writer.writeByte('}');
    }
}

fn findTrait(trait_type: smithy.TraitType, traits: []smithy.Trait) ?smithy.Trait {
    for (traits) |trait| {
        if (trait == trait_type) {
            return trait;
        }
    }

    return null;
}

fn hasTrait(trait_type: smithy.TraitType, traits: []smithy.Trait) bool {
    return findTrait(trait_type, traits) != null;
}

const JsonMember = struct {
    field_name: []const u8,
    json_key: []const u8,
    target: []const u8,
    type_member: smithy.TypeMember,
    shape_info: smithy.ShapeInfo,
};

fn getJsonMembers(allocator: std.mem.Allocator, shape: Shape, state: GenerationState) !?std.ArrayListUnmanaged(JsonMember) {
    const is_json_shape = switch (state.file_state.protocol) {
        .json_1_0, .json_1_1, .rest_json_1 => true,
        else => false,
    };

    if (!is_json_shape) {
        return null;
    }

    var hash_map = std.StringHashMapUnmanaged(smithy.TypeMember){};

    const shape_members = getShapeMembers(shape);
    for (shape_members) |member| {
        try hash_map.putNoClobber(state.allocator, member.name, member);
    }

    for (shape_members) |member| {
        for (member.traits) |trait| {
            switch (trait) {
                .http_header, .http_query => {
                    std.debug.assert(hash_map.remove(member.name));
                    break;
                },
                else => continue,
            }
        }
    }

    if (hash_map.count() == 0) {
        return null;
    }

    var json_members = std.ArrayListUnmanaged(JsonMember){};

    var iter = hash_map.iterator();
    while (iter.next()) |kvp| {
        const member = kvp.value_ptr.*;

        const key = blk: {
            if (findTrait(.json_name, member.traits)) |trait| {
                break :blk trait.json_name;
            }

            break :blk member.name;
        };

        try json_members.append(allocator, .{
            .field_name = try constantName(allocator, member.name, .snake),
            .json_key = key,
            .target = member.target,
            .type_member = member,
            .shape_info = try shapeInfoForId(member.target, state.file_state.shapes),
        });
    }

    return json_members;
}

fn generateToJsonFunction(shape_id: []const u8, writer: std.io.AnyWriter, state: GenerationState, comptime options: GenerateTypeOptions) !void {
    _ = options;
    const allocator = state.allocator;

    const shape_info = try shapeInfoForId(shape_id, state.file_state.shapes);
    const shape = shape_info.shape;

    if (try getJsonMembers(allocator, shape, state)) |json_members| {
        if (json_members.items.len > 0) {
            try writer.writeAll("/// Allocator should be from an Arena\n");
            try writer.writeAll("pub fn toJson(self: @This(), allocator: std.mem.Allocator) !std.json.Value {\n");
            try writer.writeAll("var object_map = std.json.ObjectMap.init(allocator);\n");

            for (json_members.items) |member| {
                const member_value = try getMemberValueJson(allocator, "self", member);
                defer allocator.free(member_value);

                try writer.print("try object_map.put(\"{s}\", ", .{member.json_key});
                try writeMemberJson(
                    .{
                        .shape_id = member.target,
                        .field_name = member.field_name,
                        .field_value = member_value,
                        .state = state.indent(),
                        .member = member.type_member,
                    },
                    writer,
                );
                try writer.writeAll(");\n");
            }

            try writer.writeAll("return .{ .object = object_map, };\n");
            try writer.writeAll("}\n\n");

            // json stringify function
            try writer.writeAll("pub fn jsonStringify(self: @This(), jw: anytype) !void {\n");
            try writer.writeAll("var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);\n");
            try writer.writeAll("defer arena.deinit();\n");
            try writer.writeAll("const json_value = try self.toJson(arena.allocator());\n");
            try writer.writeAll("try jw.write(json_value);\n");
            try writer.writeAll("}\n");
        }
    }
}

fn getShapeTraits(shape: Shape) []smithy.Trait {
    return switch (shape) {
        .@"enum" => |s| s.traits,
        .bigDecimal,
        .bigInteger,
        .blob,
        .boolean,
        .byte,
        .document,
        .double,
        .float,
        .integer,
        .long,
        .member,
        .short,
        .string,
        .timestamp,
        .unit,
        => |s| s.traits,
        .list => |s| s.traits,
        .map => |s| s.traits,
        .set => |s| s.traits,
        .structure => |s| s.traits,
        .uniontype => |s| s.traits,
        else => std.debug.panic("Unexpected shape type: {}", .{shape}),
    };
}

fn getShapeMembers(shape: Shape) []smithy.TypeMember {
    return switch (shape) {
        .structure => |s| s.members,
        .uniontype => |s| s.members,
        else => std.debug.panic("Unexpected shape type: {}", .{shape}),
    };
}

fn shapeIsLeaf(shape: Shape) bool {
    return switch (shape) {
        .@"enum",
        .bigDecimal,
        .bigInteger,
        .blob,
        .boolean,
        .byte,
        .document,
        .double,
        .float,
        .integer,
        .long,
        .short,
        .string,
        .timestamp,
        => true,
        else => false,
    };
}

fn shapeIsOptional(traits: []smithy.Trait) bool {
    return !hasTrait(.required, traits);
}

fn getShapeJsonValueType(shape: Shape) []const u8 {
    return switch (shape) {
        .string, .@"enum", .blob, .document, .timestamp => ".string",
        .boolean => ".bool",
        .integer, .bigInteger, .short, .long => ".integer",
        .float, .double, .bigDecimal => ".float",
        else => std.debug.panic("Unexpected shape: {}", .{shape}),
    };
}

fn writeMemberValue(
    allocator: std.mem.Allocator,
    writer: anytype,
    member_value: []const u8,
    shape_info: smithy.ShapeInfo,
    traits: []smithy.Trait,
) !void {
    if (shapeIsLeaf(shape_info.shape)) {
        const json_value_type = getShapeJsonValueType(shape_info.shape);

        if (shapeIsOptional(traits)) {
            const member_value_capture = try case.allocTo(allocator, .snake, member_value);
            defer allocator.free(member_value_capture);

            try writer.print("if ({s}) |{s}|", .{ member_value, member_value_capture });
            try writer.writeAll("std.json.Value{");
            try writer.writeAll(json_value_type);
            try writer.print(" = {s}", .{member_value_capture});
            try writer.writeAll("} else .{ .null = undefined }");
        } else {
            try writer.writeAll("std.json.Value{");
            try writer.writeAll(json_value_type);
            try writer.print(" = {s}", .{member_value});
            try writer.writeAll("}");
        }
    } else {
        try writer.writeAll(member_value);
    }
}

fn getMemberValueJson(allocator: std.mem.Allocator, source: []const u8, member: JsonMember) ![]const u8 {
    const member_value = try std.fmt.allocPrint(allocator, "@field({s}, \"{s}\")", .{ source, member.field_name });
    defer allocator.free(member_value);

    var output_block = std.ArrayListUnmanaged(u8){};
    const writer = output_block.writer(allocator);

    try writeMemberValue(
        allocator,
        writer,
        member_value,
        member.shape_info,
        member.type_member.traits,
    );

    return output_block.toOwnedSlice(allocator);
}

const WriteMemberJsonParams = struct {
    shape_id: []const u8,
    field_name: []const u8,
    field_value: []const u8,
    state: GenerationState,
    member: smithy.TypeMember,
};

fn writeStructureMemberJson(params: WriteMemberJsonParams, writer: std.io.AnyWriter) !void {
    const shape_type = "structure";
    const allocator = params.state.allocator;
    const state = params.state;

    const shape_info = try shapeInfoForId(params.shape_id, state.file_state.shapes);
    const shape = shape_info.shape;

    const structure_name = try std.fmt.allocPrint(params.state.allocator, "{s}_{s}_{d}", .{ params.field_name, shape_type, state.indent_level });
    defer params.state.allocator.free(structure_name);

    try writer.print("\n// start {s}: {s}\n", .{ shape_type, structure_name });
    defer writer.print("// end {s}: {s}\n", .{ shape_type, structure_name }) catch std.debug.panic("Unreachable", .{});

    const blk_name = try std.fmt.allocPrint(allocator, "{s}_blk", .{structure_name});
    defer allocator.free(blk_name);

    if (try getJsonMembers(allocator, shape, state)) |json_members| {
        try writer.writeAll(blk_name);
        try writer.writeAll(": {\n");

        if (json_members.items.len > 0) {
            try writer.print("var {s} = std.json.ObjectMap.init(allocator);\n", .{structure_name});

            for (json_members.items) |member| {
                const member_value = try getMemberValueJson(allocator, params.field_value, member);
                defer allocator.free(member_value);

                try writer.print("try {s}.put(\"{s}\", ", .{ structure_name, member.json_key });
                try writeMemberJson(
                    .{
                        .shape_id = member.target,
                        .field_name = member.field_name,
                        .field_value = member_value,
                        .state = state.indent(),
                        .member = member.type_member,
                    },
                    writer,
                );
                try writer.writeAll(");\n");
            }

            try writer.print("break :{s} ", .{blk_name});
            try writer.writeAll(".{ .object = ");
            try writer.writeAll(structure_name);
            try writer.writeAll("};");
        } else {
            try writer.print("break :{s} ", .{blk_name});
            try writer.writeAll(".null;");
        }

        try writer.writeAll("}\n");
    }
}

fn writeTimestampJson(params: WriteMemberJsonParams, writer: std.io.AnyWriter) anyerror!void {
    try writer.writeAll("try std.json.Value.jsonParse(allocator, ");
    try writer.writeAll(params.field_value);
    try writer.writeAll(", .{})");
}

fn writeListJson(list: ListShape, params: WriteMemberJsonParams, writer: std.io.AnyWriter) anyerror!void {
    const state = params.state;
    const allocator = state.allocator;

    const list_name = try std.fmt.allocPrint(allocator, "{s}_list_{d}", .{ params.field_name, state.indent_level });
    defer state.allocator.free(list_name);

    try writer.print("\n// start list: {s}\n", .{list_name});
    defer writer.print("// end list: {s}\n", .{list_name}) catch std.debug.panic("Unreachable", .{});

    const list_each_value = try std.fmt.allocPrint(allocator, "{s}_value", .{list_name});
    defer allocator.free(list_each_value);

    const list_value_name_local = try std.fmt.allocPrint(allocator, "{s}_local", .{list_each_value});
    defer allocator.free(list_value_name_local);

    const blk_name = try std.fmt.allocPrint(state.allocator, "{s}_blk", .{list_name});
    defer state.allocator.free(blk_name);

    const list_capture = try std.fmt.allocPrint(state.allocator, "{s}_capture", .{list_name});
    defer state.allocator.free(list_capture);

    try writer.writeAll(blk_name);
    try writer.writeAll(": {\n");
    {
        try writer.print("var {s} = std.json.Array.init(allocator);\n", .{list_name});
        try writer.print("const {s} = {s};\n", .{ list_value_name_local, params.field_value });

        const list_is_optional = shapeIsOptional(list.traits);

        var list_value = list_value_name_local;

        if (list_is_optional) {
            list_value = list_capture;

            try writer.print("if ({s}) |{s}| ", .{
                list_value_name_local,
                list_capture,
            });
            try writer.writeAll("{\n");
        }

        const list_target_shape_info = try shapeInfoForId(list.member_target, state.file_state.shapes);

        // start loop
        try writer.print("for ({s}) |{s}|", .{ list_value, list_each_value });
        try writer.writeAll("{\n");
        try writer.print("try {s}.append(", .{list_name});
        try writeMemberValue(
            allocator,
            writer,
            list_each_value,
            list_target_shape_info,
            @constCast(&[_]smithy.Trait{.required}),
        );
        try writer.writeAll(");");
        try writer.writeAll("}\n");
        // end loop

        if (list_is_optional) {
            try writer.writeAll("}\n");
        }

        try writer.print("break :{s} ", .{blk_name});
        try writer.writeAll(".{ .array = ");
        try writer.print(" {s} ", .{list_name});
        try writer.writeAll("};");
    }
    try writer.writeAll("}\n");
}

fn writeMapJson(map: MapShape, params: WriteMemberJsonParams, writer: std.io.AnyWriter) anyerror!void {
    const state = params.state;
    const name = params.field_name;
    const value = params.field_value;
    const allocator = state.allocator;

    const map_name = try std.fmt.allocPrint(state.allocator, "{s}_object_map_{d}", .{ name, state.indent_level });
    defer state.allocator.free(map_name);

    try writer.print("\n// start map: {s}\n", .{map_name});
    defer writer.print("// end map: {s}\n", .{map_name}) catch std.debug.panic("Unreachable", .{});

    const map_value_capture = try std.fmt.allocPrint(allocator, "{s}_kvp", .{map_name});
    defer allocator.free(map_value_capture);

    const map_value_capture_key = try std.fmt.allocPrint(allocator, "{s}.key", .{map_value_capture});
    defer allocator.free(map_value_capture_key);

    const value_name = try std.fmt.allocPrint(allocator, "{s}_value", .{map_value_capture});
    defer allocator.free(value_name);

    const value_shape_info = try shapeInfoForId(map.value, state.file_state.shapes);

    const value_member = smithy.TypeMember{
        .name = "value",
        .target = map.value,
        .traits = getShapeTraits(value_shape_info.shape),
    };

    const map_value_block = try getMemberValueJson(allocator, map_value_capture, .{
        .field_name = "value",
        .json_key = undefined,
        .shape_info = try shapeInfoForId(map.value, state.file_state.shapes),
        .target = map.value,
        .type_member = value_member,
    });
    defer allocator.free(map_value_block);

    const blk_name = try std.fmt.allocPrint(state.allocator, "{s}_blk", .{map_name});
    defer state.allocator.free(blk_name);

    const map_capture = try std.fmt.allocPrint(state.allocator, "{s}_capture", .{map_name});

    try writer.writeAll(blk_name);
    try writer.writeAll(": {\n");
    {
        const map_member = params.member;
        const key_member = smithy.TypeMember{
            .name = "key",
            .target = map.key,
            .traits = @constCast(&[_]smithy.Trait{.required}),
        };

        const map_is_optional = !hasTrait(.required, map_member.traits);

        var map_value = value;

        if (map_is_optional) {
            map_value = map_capture;

            try writer.print("if ({s}) |{s}| ", .{
                value,
                map_capture,
            });
            try writer.writeAll("{\n");
        }

        try writer.print("var {s} = std.json.ObjectMap.init(allocator);\n", .{map_name});

        // start loop
        try writer.print("for ({s}) |{s}|", .{ map_value, map_value_capture });
        try writer.writeAll("{\n");
        try writer.print("const {s}: std.json.Value = ", .{value_name});
        try writeMemberJson(.{
            .shape_id = map.value,
            .field_name = "value",
            .field_value = map_value_block,
            .state = state,
            .member = value_member,
        }, writer);
        try writer.writeAll(";\n");
        try writer.print("try {s}.put(\n", .{map_name});
        try writeMemberJson(.{
            .shape_id = map.key,
            .field_name = "key",
            .field_value = map_value_capture_key,
            .state = state.indent(),
            .member = key_member,
        }, writer);
        try writer.writeAll(", ");
        try writeMemberJson(.{
            .shape_id = map.value,
            .field_name = "value",
            .field_value = value_name,
            .state = state.indent(),
            .member = value_member,
        }, writer);
        try writer.writeAll(");\n");
        try writer.writeAll("}\n");
        // end loop

        try writer.print("break :{s}", .{blk_name});
        try writer.writeAll(".{ .object = ");
        try writer.writeAll(map_name);
        try writer.writeAll("};\n");

        if (map_is_optional) {
            try writer.writeAll("}\n");
            try writer.print("break :{s} .null;", .{blk_name});
        }
    }
    try writer.writeAll("}\n");
}

fn writeScalarJson(comment: []const u8, params: WriteMemberJsonParams, writer: std.io.AnyWriter) anyerror!void {
    try writer.print("\n// {s}\n", .{comment});
    try writer.writeAll(params.field_value);
}

fn writeMemberJson(params: WriteMemberJsonParams, writer: std.io.AnyWriter) anyerror!void {
    const shape_id = params.shape_id;
    const state = params.state;
    const value = params.field_value;

    const shape_info = try shapeInfoForId(shape_id, state.file_state.shapes);
    const shape = shape_info.shape;

    if (state.getTypeRecurrenceCount(shape_id) > 2) {
        try writer.writeAll(value);
        return;
    }

    try state.appendToTypeStack(&shape_info);
    defer state.popFromTypeStack();

    switch (shape) {
        .structure, .uniontype => try writeStructureMemberJson(params, writer),
        .timestamp => try writeTimestampJson(params, writer),
        .list => |l| try writeListJson(l, params, writer),
        .set => std.debug.panic("Set not implemented", .{}),
        .map => |m| try writeMapJson(m, params, writer),
        .string => try writeScalarJson("string", params, writer),
        .@"enum" => try writeScalarJson("enum", params, writer),
        .document => try writeScalarJson("document", params, writer),
        .blob => try writeScalarJson("blob", params, writer),
        .boolean => try writeScalarJson("bool", params, writer),
        .float => try writeScalarJson("float", params, writer),
        .integer => try writeScalarJson("integer", params, writer),
        .long => try writeScalarJson("long", params, writer),
        .double => try writeScalarJson("double", params, writer),
        .bigDecimal => try writeScalarJson("bigDecimal", params, writer),
        .bigInteger => try writeScalarJson("bigInteger", params, writer),
        .unit => try writeScalarJson("unit", params, writer),
        .byte => try writeScalarJson("byte", params, writer),
        .short => try writeScalarJson("short", params, writer),
        else => std.debug.panic("Unexpected shape type: {}", .{shape}),
    }
}

fn getErrorName(err_name: []const u8) []const u8 {
    if (endsWith("Exception", err_name))
        return err_name[0 .. err_name.len - "Exception".len];

    if (endsWith("Fault", err_name))
        return err_name[0 .. err_name.len - "Fault".len];
    return err_name;
}

fn endsWith(item: []const u8, str: []const u8) bool {
    if (str.len < item.len) return false;
    return std.mem.eql(u8, item, str[str.len - item.len ..]);
}

fn getTypeName(allocator: std.mem.Allocator, shape: smithy.ShapeInfo) ![]const u8 {
    const pascal_shape_name = try case.allocTo(allocator, .pascal, shape.name);
    const type_name = avoidReserved(pascal_shape_name);

    switch (shape.shape) {
        // maps are named like "Tags"
        // this removes the trailing s and adds "KeyValue" suffix
        .map => {
            var name_slice = pascal_shape_name;

            if (pascal_shape_name[pascal_shape_name.len - 1] == 's') {
                name_slice = pascal_shape_name[0 .. pascal_shape_name.len - 1];
            }

            return try std.fmt.allocPrint(allocator, "{s}KeyValue", .{name_slice});
        },
        else => return type_name,
    }
}

fn reuseCommonType(shape: smithy.ShapeInfo, writer: anytype, state: GenerationState) !bool {
    // We want to return if we're at the top level of the stack. There are three
    // reasons for this:
    // 1. For operations, we have a request that includes a metadata function
    //    to enable aws.zig eventually to find the action based on a request.
    //    This could be considered a hack and maybe we should remove that
    //    caller convenience ability.
    // 2. Given the state of zig compiler tooling, "intellisense" or whatever
    //    we're calling it these days, isn't real mature, so we end up looking
    //    at the models quite a bit. Leaving the top level alone here reduces
    //    the need for users to hop around too much looking at types as they
    //    can at least see the top level.
    // 3. When we come through at the end, we want to make sure we're writing
    //    something or we'll have an infinite loop!

    switch (shape.shape) {
        .structure, .uniontype, .map => {},
        else => return false,
    }

    const type_name = try getTypeName(state.allocator, shape);
    defer state.allocator.free(type_name);

    if (state.type_stack.items.len == 1) return false;
    var rc = false;
    if (state.file_state.shape_references.get(shape.id)) |r| {
        if (r > 1) {
            rc = true;
            _ = try writer.write(type_name); // This can't possibly be this easy...
            if (state.file_state.additional_types_generated.getEntry(shape.name) == null)
                try state.file_state.additional_types_to_generate.append(shape);
        }
    }
    return rc;
}

fn shapeInfoForId(id: []const u8, shapes: std.StringHashMap(smithy.ShapeInfo)) !smithy.ShapeInfo {
    return shapes.get(id) orelse {
        std.debug.print("Shape ID not found. This is most likely a bug. Shape ID: {s}\n", .{id});
        return error.InvalidType;
    };
}

const GenerateTypeOptions = struct {
    end_structure: bool,
    key_case: case.Case,

    pub fn endStructure(self: @This(), value: bool) GenerateTypeOptions {
        return .{
            .end_structure = value,
            .key_case = self.key_case,
        };
    }

    pub fn keyCase(self: @This(), value: case.Case) GenerateTypeOptions {
        return .{
            .end_structure = self.end_structure,
            .key_case = value,
        };
    }
};

/// return type is anyerror!void as this is a recursive function, so the compiler cannot properly infer error types
fn generateTypeFor(shape_id: []const u8, writer: anytype, state: GenerationState, comptime options: GenerateTypeOptions) anyerror!bool {
    const end_structure = options.end_structure;

    var rc = false;

    // We assume it must exist
    const shape_info = try shapeInfoForId(shape_id, state.file_state.shapes);
    const shape = shape_info.shape;

    // Check for ourselves up the stack
    const self_occurences: u8 = state.getTypeRecurrenceCount(shape_id);
    if (self_occurences > 2) { // TODO: What's the appropriate number here?
        // TODO: Determine if this warrants the creation of another public
        // type to properly reference. Realistically, AWS or the service
        // must be blocking deep recursion somewhere or this would be a great
        // DOS attack
        try generateSimpleTypeFor("nothing", "[]const u8", writer);

        if (verbose) {
            std.log.warn("Type cycle detected, limiting depth. Type: {s}", .{shape_id});
        }
        // if (std.mem.eql(u8, "com.amazonaws.workmail#Timestamp", shape_id)) {
        //     std.log.info("  Type stack:\n", .{});
        //     for (state.type_stack.items) |i|
        //         std.log.info("  {s}", .{i.*.id});
        // }
        return false; // not a map
    }

    try state.appendToTypeStack(&shape_info);
    defer state.popFromTypeStack();

    switch (shape) {
        .structure => {
            if (!try reuseCommonType(shape_info, writer, state)) {
                try generateComplexTypeFor(shape_id, shape.structure.members, "struct", writer, state, options);
                if (end_structure) {
                    // epilog
                    try outputIndent(state, writer);
                    _ = try writer.write("}");
                }
            }
        },
        .uniontype => {
            if (!try reuseCommonType(shape_info, writer, state)) {
                try generateComplexTypeFor(shape_id, shape.uniontype.members, "union", writer, state, options);
                // epilog
                try outputIndent(state, writer);
                _ = try writer.write("}");
            }
        },
        // Document is unstructured data, so bag of bytes it is
        // https://smithy.io/2.0/spec/simple-types.html#document
        .string, .@"enum", .document, .blob => try generateSimpleTypeFor({}, "[]const u8", writer),
        .unit => |s| try generateSimpleTypeFor(s, "struct {}", writer), // Would be better as void, but doing so creates inconsistency we don't want clients to have to deal with
        .integer => |s| try generateSimpleTypeFor(s, "i64", writer),
        .list => |s| {
            _ = try writer.write("[]");
            // The serializer will have to deal with the idea we might be an array
            return try generateTypeFor(s.member_target, writer, state, options.endStructure(true));
        },
        .set => |s| {
            _ = try writer.write("[]");
            // The serializer will have to deal with the idea we might be an array
            return try generateTypeFor(s.member_target, writer, state, options.endStructure(true));
        },
        .timestamp => |s| try generateSimpleTypeFor(s, "date.Timestamp", writer),
        .boolean => |s| try generateSimpleTypeFor(s, "bool", writer),
        .double => |s| try generateSimpleTypeFor(s, "f64", writer),
        .float => |s| try generateSimpleTypeFor(s, "f32", writer),
        .long => |s| try generateSimpleTypeFor(s, "i64", writer),
        .map => |m| {
            if (!try reuseCommonType(shape_info, std.io.null_writer, state)) {
                try generateMapTypeFor(m, writer, state, options);
                rc = true;
            } else {
                try writer.writeAll("[]");
                _ = try reuseCommonType(shape_info, writer, state);
            }
        },
        else => {
            std.log.err("encountered unimplemented shape type {s} for shape_id {s}. Generated code will not compile", .{ @tagName(shape), shape_id });
            // Not sure we want to return here - I think we want an exhaustive list
            // return error{UnimplementedShapeType}.UnimplementedShapeType;
        },
    }
    return rc;
}

fn generateMapTypeFor(map: anytype, writer: anytype, state: GenerationState, comptime options: GenerateTypeOptions) anyerror!void {
    _ = try writer.write("struct {\n");

    try writer.writeAll("pub const is_map_type = true;\n\n");

    var child_state = state;
    child_state.indent_level += 1;

    _ = try writer.write("key: ");
    _ = try generateTypeFor(map.key, writer, child_state, options.endStructure(true));
    _ = try writer.write(",\n");

    const value_shape_info = try shapeInfoForId(map.value, state.file_state.shapes);
    const value_traits = getShapeTraits(value_shape_info.shape);

    _ = try writer.write("value: ");
    try writeOptional(value_traits, writer, null);
    _ = try generateTypeFor(map.value, writer, child_state, options.endStructure(true));

    _ = try writer.write(",\n");
    _ = try writer.write("}");
}

fn generateSimpleTypeFor(_: anytype, type_name: []const u8, writer: anytype) !void {
    _ = try writer.write(type_name); // This had required stuff but the problem was elsewhere. Better to leave as function just in case
}

const Mapping = struct { snake: []const u8, original: []const u8 };
fn generateComplexTypeFor(shape_id: []const u8, members: []smithy.TypeMember, type_type_name: []const u8, writer: anytype, state: GenerationState, comptime options: GenerateTypeOptions) anyerror!void {
    _ = shape_id;

    var arena = std.heap.ArenaAllocator.init(state.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var field_name_mappings = try std.ArrayList(Mapping).initCapacity(allocator, members.len);
    defer field_name_mappings.deinit();
    // There is an httpQueryParams trait as well, but nobody is using it. API GW
    // pretends to, but it's an empty map
    //
    // Same with httpPayload
    //
    // httpLabel is interesting - right now we just assume anything can be used - do we need to track this?
    var http_query_mappings = try std.ArrayList(Mapping).initCapacity(allocator, members.len);
    defer http_query_mappings.deinit();

    var http_header_mappings = try std.ArrayList(Mapping).initCapacity(allocator, members.len);
    defer http_header_mappings.deinit();

    var map_fields = std.ArrayList([]const u8).init(allocator);
    defer map_fields.deinit();

    // prolog. We'll rely on caller to get the spacing correct here
    _ = try writer.write(type_type_name);
    _ = try writer.write(" {\n");
    var child_state = state;
    child_state.indent_level += 1;
    var payload: ?[]const u8 = null;
    for (members) |member| {
        // This is our mapping
        const snake_case_member = try constantName(allocator, member.name, .snake);
        // So it looks like some services have duplicate names?! Check out "httpMethod"
        // in API Gateway. Not sure what we're supposed to do there. Checking the go
        // sdk, they move this particular duplicate to 'http_method' - not sure yet
        // if this is a hard-coded exception`
        var found_name_trait = false;
        for (member.traits) |trait| {
            switch (trait) {
                .json_name => |n| {
                    found_name_trait = true;
                    field_name_mappings.appendAssumeCapacity(.{ .snake = try allocator.dupe(u8, snake_case_member), .original = n });
                },
                .xml_name => |n| {
                    found_name_trait = true;
                    field_name_mappings.appendAssumeCapacity(.{ .snake = try allocator.dupe(u8, snake_case_member), .original = n });
                },
                .http_query => |n| http_query_mappings.appendAssumeCapacity(.{ .snake = try allocator.dupe(u8, snake_case_member), .original = n }),
                .http_header => http_header_mappings.appendAssumeCapacity(.{ .snake = try allocator.dupe(u8, snake_case_member), .original = trait.http_header }),
                .http_payload => {
                    // Don't assert as that will be optimized for Release* builds
                    // We'll continue here and treat the above as a warning
                    if (payload) |first| {
                        std.log.warn("Found multiple httpPayloads in violation of smithy spec! Ignoring '{s}' and using '{s}'", .{ first, snake_case_member });
                    }
                    payload = try allocator.dupe(u8, snake_case_member);
                },
                else => {},
            }
        }
        if (!found_name_trait)
            field_name_mappings.appendAssumeCapacity(.{ .snake = try allocator.dupe(u8, snake_case_member), .original = member.name });

        try outputIndent(child_state, writer);

        const member_name = blk: {
            if (options.key_case == .snake) {
                break :blk avoidReserved(snake_case_member);
            }

            break :blk avoidReserved(try case.allocTo(allocator, options.key_case, snake_case_member));
        };

        try writer.print("{s}: ", .{member_name});
        try writeOptional(member.traits, writer, null);
        if (try generateTypeFor(member.target, writer, child_state, options.endStructure(true)))
            try map_fields.append(try std.fmt.allocPrint(allocator, "{s}", .{member_name}));

        if (!std.mem.eql(u8, "union", type_type_name))
            try writeOptional(member.traits, writer, " = null");
        _ = try writer.write(",\n");
    }

    // Add in http query metadata (only relevant to REST JSON APIs - do we care?
    // pub const http_query = .{
    //     .master_region = "MasterRegion",
    //     .function_version = "FunctionVersion",
    //     .marker = "Marker",
    //     .max_items = "MaxItems",
    // };
    if (http_query_mappings.items.len > 0) _ = try writer.write("\n");
    try writeMappings(child_state, "pub ", "http_query", http_query_mappings, false, writer);
    if (http_query_mappings.items.len > 0 and http_header_mappings.items.len > 0) _ = try writer.write("\n");
    try writeMappings(child_state, "pub ", "http_header", http_header_mappings, false, writer);

    // Add in json mappings. The function looks like this:
    //
    // pub fn jsonFieldNameFor(_: @This(), comptime field_name: []const u8) []const u8 {
    //     const mappings = .{
    //         .exclusive_start_table_name = "ExclusiveStartTableName",
    //         .limit = "Limit",
    //     };
    //     return @field(mappings, field_name);
    // }
    //
    if (payload) |load| {
        try writer.writeByte('\n');
        try outputIndent(child_state, writer);
        try writer.print("pub const http_payload: []const u8 = \"{s}\";\n", .{load});
    }

    try writer.writeByte('\n');
    try outputIndent(child_state, writer);
    _ = try writer.write("pub fn fieldNameFor(_: @This(), comptime field_name: []const u8) []const u8 {\n");
    var grandchild_state = child_state;
    grandchild_state.indent_level += 1;
    // We need to force output here becaseu we're referencing the field in the return statement below
    try writeMappings(grandchild_state, "", "mappings", field_name_mappings, true, writer);
    try outputIndent(grandchild_state, writer);
    _ = try writer.write("return @field(mappings, field_name);\n");
    try outputIndent(child_state, writer);
    _ = try writer.write("}\n");
}

fn writeMappings(state: GenerationState, @"pub": []const u8, mapping_name: []const u8, mappings: anytype, force_output: bool, writer: anytype) !void {
    if (mappings.items.len == 0 and !force_output) return;
    try outputIndent(state, writer);
    if (mappings.items.len == 0) {
        try writer.print("{s}const {s} = ", .{ @"pub", mapping_name });
        _ = try writer.write(".{};\n");
        return;
    }
    try writer.print("{s}const {s} = .", .{ @"pub", mapping_name });
    _ = try writer.write("{\n");
    var child_state = state;
    child_state.indent_level += 1;
    for (mappings.items) |mapping| {
        try outputIndent(child_state, writer);
        try writer.print(".{s} = \"{s}\",\n", .{ avoidReserved(mapping.snake), mapping.original });
    }
    try outputIndent(state, writer);
    _ = try writer.write("};\n");
}

fn writeOptional(traits: ?[]smithy.Trait, writer: anytype, value: ?[]const u8) !void {
    if (traits) |ts| if (hasTrait(.required, ts)) return;
    try writer.writeAll(value orelse "?");
}
fn avoidReserved(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "error")) return "@\"error\"";
    if (std.mem.eql(u8, name, "return")) return "@\"return\"";
    if (std.mem.eql(u8, name, "not")) return "@\"not\"";
    if (std.mem.eql(u8, name, "and")) return "@\"and\"";
    if (std.mem.eql(u8, name, "or")) return "@\"or\"";
    if (std.mem.eql(u8, name, "test")) return "@\"test\"";
    if (std.mem.eql(u8, name, "null")) return "@\"null\"";
    if (std.mem.eql(u8, name, "export")) return "@\"export\"";
    if (std.mem.eql(u8, name, "union")) return "@\"union\"";
    if (std.mem.eql(u8, name, "enum")) return "@\"enum\"";
    if (std.mem.eql(u8, name, "inline")) return "@\"inline\"";
    return name;
}

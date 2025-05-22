const std = @import("std");
const smithy = @import("smithy");
const Hasher = @import("Hasher.zig");
const case = @import("case");

var verbose = false;

pub fn main() anyerror!void {
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
            try processDirectories(m, output_dir);
        }
    }

    if (args.len == 0)
        _ = try generateServices(allocator, ";", std.io.getStdIn(), stdout);
}

const OutputManifest = struct {
    model_dir_hash_digest: [Hasher.hex_multihash_len]u8,
    output_dir_hash_digest: [Hasher.hex_multihash_len]u8,
};
fn processDirectories(models_dir: std.fs.Dir, output_dir: std.fs.Dir) !void {
    // Let's get ready to hash!!
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var thread_pool: std.Thread.Pool = undefined;
    try thread_pool.init(.{ .allocator = allocator });
    defer thread_pool.deinit();
    var calculated_manifest = try calculateDigests(models_dir, output_dir, &thread_pool);
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
    while (try mi.next()) |e| {
        if ((e.kind == .file or e.kind == .sym_link) and
            std.mem.endsWith(u8, e.name, ".json"))
            try processFile(e.name, output_dir, manifest);
    }
    // re-calculate so we can store the manifest
    model_digest = calculated_manifest.model_dir_hash_digest;
    calculated_manifest = try calculateDigests(models_dir, output_dir, &thread_pool);
    try output_dir.writeFile(.{ .sub_path = "output_manifest.json", .data = try std.json.stringifyAlloc(
        allocator,
        calculated_manifest,
        .{ .whitespace = .indent_2 },
    ) });
}

var model_digest: ?[Hasher.hex_multihash_len]u8 = null;
fn calculateDigests(models_dir: std.fs.Dir, output_dir: std.fs.Dir, thread_pool: *std.Thread.Pool) !OutputManifest {
    const model_hash = if (model_digest) |m| m[0..Hasher.digest_len].* else try Hasher.computeDirectoryHash(thread_pool, models_dir, @constCast(&Hasher.ComputeDirectoryOptions{
        .isIncluded = struct {
            pub fn include(entry: std.fs.Dir.Walker.Entry) bool {
                return std.mem.endsWith(u8, entry.basename, ".json");
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
        .model_dir_hash_digest = model_digest orelse Hasher.hexDigest(model_hash),
        .output_dir_hash_digest = Hasher.hexDigest(output_hash),
    };
}
fn processFile(file_name: []const u8, output_dir: std.fs.Dir, manifest: anytype) !void {
    // The fixed buffer for output will be 2MB, which is twice as large as the size of the EC2
    // (the largest) model. We'll then flush all this at one go at the end.
    var buffer = std.mem.zeroes([1024 * 1024 * 2]u8);
    var output_stream = std.io.FixedBufferStream([]u8){
        .buffer = &buffer,
        .pos = 0,
    };
    var counting_writer = std.io.countingWriter(output_stream.writer());
    var writer = counting_writer.writer();

    // It's probably best to create our own allocator here so we can deint at the end and
    // toss all allocations related to the services in this file
    // I can't guarantee we're not leaking something, and at the end of the
    // day I'm not sure we want to track down leaks
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
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

    const formatted = try zigFmt(allocator, @ptrCast(buffer[0..counting_writer.bytes_written]));

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

    const state = FileGenerationState{
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
                .aws_protocol => aws_protocol = trait.aws_protocol,
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
        const constant_name = try constantName(allocator, sdk_id);
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
        _ = try generateTypeFor(t.id, writer, state, true);
        _ = try writer.write(";\n");
    }
}

fn constantName(allocator: std.mem.Allocator, id: []const u8) ![]const u8 {
    // There are some ids that don't follow consistent rules, so we'll
    // look for the exceptions and, if not found, revert to the snake case
    // algorithm

    // This one might be a bug in snake, but it's the only example so HPDL
    if (std.mem.eql(u8, id, "SESv2")) return try std.fmt.allocPrint(allocator, "ses_v2", .{});
    if (std.mem.eql(u8, id, "CloudFront")) return try std.fmt.allocPrint(allocator, "cloudfront", .{});
    // IoT is an acryonym, but snake wouldn't know that. Interestingly not all
    // iot services are capitalizing that way.
    if (std.mem.eql(u8, id, "IoTSiteWise")) return try std.fmt.allocPrint(allocator, "iot_sitewise", .{});
    if (std.mem.eql(u8, id, "IoTFleetHub")) return try std.fmt.allocPrint(allocator, "iot_fleet_hub", .{});
    if (std.mem.eql(u8, id, "IoTSecureTunneling")) return try std.fmt.allocPrint(allocator, "iot_secure_tunneling", .{});
    if (std.mem.eql(u8, id, "IoTThingsGraph")) return try std.fmt.allocPrint(allocator, "iot_things_graph", .{});
    // snake turns this into dev_ops, which is a little weird
    if (std.mem.eql(u8, id, "DevOps Guru")) return try std.fmt.allocPrint(allocator, "devops_guru", .{});
    if (std.mem.eql(u8, id, "FSx")) return try std.fmt.allocPrint(allocator, "fsx", .{});
    if (std.mem.eql(u8, id, "ETag")) return try std.fmt.allocPrint(allocator, "e_tag", .{});

    // Not a special case - just snake it
    return try case.allocTo(allocator, .snake, id);
}

const FileGenerationState = struct {
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
};

fn outputIndent(state: GenerationState, writer: anytype) !void {
    const n_chars = 4 * state.indent_level;
    try writer.writeByteNTimes(' ', n_chars);
}
fn generateOperation(allocator: std.mem.Allocator, operation: smithy.ShapeInfo, file_state: FileGenerationState, writer: anytype) !void {
    const snake_case_name = try constantName(allocator, operation.name);
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

    // Request type
    _ = try writer.print("pub const {s}Request = ", .{operation.name});
    if (operation.shape.operation.input == null or
        (try shapeInfoForId(operation.shape.operation.input.?, state)).shape == .unit)
    {
        _ = try writer.write("struct {\n");
        try generateMetadataFunction(operation_name, state, writer);
    } else if (operation.shape.operation.input) |member| {
        if (try generateTypeFor(member, writer, state, false)) unreachable; // we expect only structs here
        _ = try writer.write("\n");
        try generateMetadataFunction(operation_name, state, writer);
    }
    _ = try writer.write(";\n\n");

    // Response type
    _ = try writer.print("pub const {s}Response = ", .{operation.name});
    if (operation.shape.operation.output == null or
        (try shapeInfoForId(operation.shape.operation.output.?, state)).shape == .unit)
    {
        _ = try writer.write("struct {\n");
        try generateMetadataFunction(operation_name, state, writer);
    } else if (operation.shape.operation.output) |member| {
        if (try generateTypeFor(member, writer, state, false)) unreachable; // we expect only structs here
        _ = try writer.write("\n");
        try generateMetadataFunction(operation_name, state, writer);
    }
    _ = try writer.write(";\n\n");

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

fn generateMetadataFunction(operation_name: []const u8, state: GenerationState, writer: anytype) !void {
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
    try writer.writeByte('}');
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
    const type_name = avoidReserved(shape.name);

    switch (shape.shape) {
        // maps are named like "Tags"
        // this removes the trailing s and adds "KeyValue" suffix
        .map => {
            const map_type_name = avoidReserved(shape.name);
            return try std.fmt.allocPrint(allocator, "{s}KeyValue", .{map_type_name[0 .. map_type_name.len - 1]});
        },
        else => return allocator.dupe(u8, type_name),
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
fn shapeInfoForId(id: []const u8, state: GenerationState) !smithy.ShapeInfo {
    return state.file_state.shapes.get(id) orelse {
        std.debug.print("Shape ID not found. This is most likely a bug. Shape ID: {s}\n", .{id});
        return error.InvalidType;
    };
}

/// return type is anyerror!void as this is a recursive function, so the compiler cannot properly infer error types
fn generateTypeFor(shape_id: []const u8, writer: anytype, state: GenerationState, end_structure: bool) anyerror!bool {
    var rc = false;

    // We assume it must exist
    const shape_info = try shapeInfoForId(shape_id, state);
    const shape = shape_info.shape;

    // Check for ourselves up the stack
    var self_occurences: u8 = 0;
    for (state.type_stack.items) |i| {
        // NOTE: shapes.get isn't providing a consistent pointer - is it allocating each time?
        // we will therefore need to compare ids
        if (std.mem.eql(u8, i.*.id, shape_info.id))
            self_occurences = self_occurences + 1;
    }
    // Debugging
    // if (std.mem.eql(u8, shape_info.name, "Expression")) {
    //     std.log.info("  Type stack len: {d}, occurences: {d}\n", .{ type_stack.items.len, self_occurences });
    //     if (type_stack.items.len > 15) {
    //         std.log.info("  Type stack:\n", .{});
    //         for (type_stack.items) |i|
    //             std.log.info("  {s}: {*}", .{ i.*.id, i });
    //         return error.BugDetected;
    //     }
    // }
    // End Debugging
    if (self_occurences > 2) { // TODO: What's the appropriate number here?
        // TODO: Determine if this warrants the creation of another public
        // type to properly reference. Realistically, AWS or the service
        // must be blocking deep recursion somewhere or this would be a great
        // DOS attack
        try generateSimpleTypeFor("nothing", "[]const u8", writer);
        std.log.warn("Type cycle detected, limiting depth. Type: {s}", .{shape_id});
        // if (std.mem.eql(u8, "com.amazonaws.workmail#Timestamp", shape_id)) {
        //     std.log.info("  Type stack:\n", .{});
        //     for (state.type_stack.items) |i|
        //         std.log.info("  {s}", .{i.*.id});
        // }
        return false; // not a map
    }
    try state.type_stack.append(&shape_info);
    defer _ = state.type_stack.pop();
    switch (shape) {
        .structure => {
            if (!try reuseCommonType(shape_info, writer, state)) {
                try generateComplexTypeFor(shape_id, shape.structure.members, "struct", writer, state);
                if (end_structure) {
                    // epilog
                    try outputIndent(state, writer);
                    _ = try writer.write("}");
                }
            }
        },
        .uniontype => {
            if (!try reuseCommonType(shape_info, writer, state)) {
                try generateComplexTypeFor(shape_id, shape.uniontype.members, "union", writer, state);
                // epilog
                try outputIndent(state, writer);
                _ = try writer.write("}");
            }
        },
        // Document is unstructured data, so bag of bytes it is
        // https://smithy.io/2.0/spec/simple-types.html#document
        .document => |s| try generateSimpleTypeFor(s, "[]const u8", writer),
        .string => |s| try generateSimpleTypeFor(s, "[]const u8", writer),
        .unit => |s| try generateSimpleTypeFor(s, "struct {}", writer), // Would be better as void, but doing so creates inconsistency we don't want clients to have to deal with
        .@"enum" => |s| try generateSimpleTypeFor(s, "[]const u8", writer), // This should be closer to uniontype, but the generated code will look ugly, and Smithy 2.0 requires that enums are open (clients accept unspecified values). So string is the best analog
        .integer => |s| try generateSimpleTypeFor(s, "i64", writer),
        .list => {
            _ = try writer.write("[]");
            // The serializer will have to deal with the idea we might be an array
            return try generateTypeFor(shape.list.member_target, writer, state, true);
        },
        .set => {
            _ = try writer.write("[]");
            // The serializer will have to deal with the idea we might be an array
            return try generateTypeFor(shape.set.member_target, writer, state, true);
        },
        .timestamp => |s| try generateSimpleTypeFor(s, "date.Timestamp", writer),
        .blob => |s| try generateSimpleTypeFor(s, "[]const u8", writer),
        .boolean => |s| try generateSimpleTypeFor(s, "bool", writer),
        .double => |s| try generateSimpleTypeFor(s, "f64", writer),
        .float => |s| try generateSimpleTypeFor(s, "f32", writer),
        .long => |s| try generateSimpleTypeFor(s, "i64", writer),
        .map => |m| {
            if (!try reuseCommonType(shape_info, std.io.null_writer, state)) {
                try generateMapTypeFor(m, writer, state);
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

fn generateMapTypeFor(map: anytype, writer: anytype, state: GenerationState) anyerror!void {
    _ = try writer.write("struct {\n");

    try writer.writeAll("pub const is_map_type = true;\n\n");

    var child_state = state;
    child_state.indent_level += 1;

    _ = try writer.write("key: ");
    try writeOptional(map.traits, writer, null);

    _ = try generateTypeFor(map.key, writer, child_state, true);

    try writeOptional(map.traits, writer, " = null");
    _ = try writer.write(",\n");

    _ = try writer.write("value: ");
    try writeOptional(map.traits, writer, null);

    _ = try generateTypeFor(map.value, writer, child_state, true);

    try writeOptional(map.traits, writer, " = null");
    _ = try writer.write(",\n");
    _ = try writer.write("}");
}

fn generateSimpleTypeFor(_: anytype, type_name: []const u8, writer: anytype) !void {
    _ = try writer.write(type_name); // This had required stuff but the problem was elsewhere. Better to leave as function just in case
}

const Mapping = struct { snake: []const u8, original: []const u8 };
fn generateComplexTypeFor(shape_id: []const u8, members: []smithy.TypeMember, type_type_name: []const u8, writer: anytype, state: GenerationState) anyerror!void {
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
        const snake_case_member = try constantName(allocator, member.name);
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
                        std.log.err("Found multiple httpPayloads in violation of smithy spec! Ignoring '{s}' and using '{s}'", .{ first, snake_case_member });
                    }
                    payload = try allocator.dupe(u8, snake_case_member);
                },
                else => {},
            }
        }
        if (!found_name_trait)
            field_name_mappings.appendAssumeCapacity(.{ .snake = try allocator.dupe(u8, snake_case_member), .original = member.name });

        try outputIndent(child_state, writer);
        const member_name = avoidReserved(snake_case_member);
        try writer.print("{s}: ", .{member_name});
        try writeOptional(member.traits, writer, null);
        if (try generateTypeFor(member.target, writer, child_state, true))
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
        try writer.print("pub const http_payload: []const u8 = \"{s}\";", .{load});
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
    try writeStringify(child_state, map_fields.items, writer);
}

fn writeStringify(state: GenerationState, fields: [][]const u8, writer: anytype) !void {
    if (fields.len > 0) {
        // pub fn jsonStringifyField(self: @This(), comptime field_name: []const u8, options: anytype, out_stream: anytype) !bool {
        //     if (std.mem.eql(u8, "tags", field_name))
        //         return try serializeMap(self.tags, self.jsonFieldNameFor("tags"), options, out_stream);
        //     return false;
        // }
        var child_state = state;
        child_state.indent_level += 1;
        try writer.writeByte('\n');
        try outputIndent(state, writer);
        _ = try writer.write("pub fn jsonStringifyField(self: @This(), comptime field_name: []const u8, options: anytype, out_stream: anytype) !bool {\n");
        var return_state = child_state;
        return_state.indent_level += 1;
        for (fields) |field| {
            try outputIndent(child_state, writer);
            try writer.print("if (std.mem.eql(u8, \"{s}\", field_name))\n", .{field});
            try outputIndent(return_state, writer);
            try writer.print("return try serializeMap(self.{s}, self.fieldNameFor(\"{s}\"), options, out_stream);\n", .{ field, field });
        }
        try outputIndent(child_state, writer);
        _ = try writer.write("return false;\n");
        try outputIndent(state, writer);
        _ = try writer.write("}\n");
    }
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
    if (traits) |ts| {
        for (ts) |t|
            if (t == .required) return;
    }

    // not required
    if (value) |v| {
        _ = try writer.write(v);
    } else _ = try writer.write("?");
}
fn camelCase(allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
    const first_letter = name[0] + ('a' - 'A');
    return try std.fmt.allocPrint(allocator, "{c}{s}", .{ first_letter, name[1..] });
}
fn avoidReserved(snake_name: []const u8) []const u8 {
    if (std.mem.eql(u8, snake_name, "error")) return "@\"error\"";
    if (std.mem.eql(u8, snake_name, "return")) return "@\"return\"";
    if (std.mem.eql(u8, snake_name, "not")) return "@\"not\"";
    if (std.mem.eql(u8, snake_name, "and")) return "@\"and\"";
    if (std.mem.eql(u8, snake_name, "or")) return "@\"or\"";
    if (std.mem.eql(u8, snake_name, "test")) return "@\"test\"";
    if (std.mem.eql(u8, snake_name, "null")) return "@\"null\"";
    if (std.mem.eql(u8, snake_name, "export")) return "@\"export\"";
    if (std.mem.eql(u8, snake_name, "union")) return "@\"union\"";
    if (std.mem.eql(u8, snake_name, "enum")) return "@\"enum\"";
    if (std.mem.eql(u8, snake_name, "inline")) return "@\"inline\"";
    return snake_name;
}

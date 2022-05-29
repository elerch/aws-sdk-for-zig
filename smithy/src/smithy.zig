const std = @import("std");
const expect = std.testing.expect;

// TODO: validate this matches the schema
pub const Smithy = struct {
    version: []const u8,
    metadata: ModelMetadata,
    shapes: []ShapeInfo,
    allocator: std.mem.Allocator,

    const Self = @This();
    pub fn init(allocator: std.mem.Allocator, version: []const u8, metadata: ModelMetadata, shapeinfo: []ShapeInfo) Smithy {
        return .{
            .version = version,
            .metadata = metadata,
            .shapes = shapeinfo,
            .allocator = allocator,
        };
    }
    pub fn deinit(self: Self) void {
        for (self.shapes) |s| {
            switch (s.shape) {
                .string,
                .byte,
                .short,
                .integer,
                .long,
                .float,
                .double,
                .bigInteger,
                .bigDecimal,
                .blob,
                .boolean,
                .timestamp,
                .document,
                .member,
                .resource,
                => |v| self.allocator.free(v.traits),
                .structure => |v| {
                    for (v.members) |m| self.allocator.free(m.traits);
                    self.allocator.free(v.members);
                    self.allocator.free(v.traits);
                },
                .uniontype => |v| {
                    for (v.members) |m| self.allocator.free(m.traits);
                    self.allocator.free(v.members);
                    self.allocator.free(v.traits);
                },
                .service => |v| {
                    self.allocator.free(v.traits);
                    self.allocator.free(v.operations);
                },
                .operation => |v| {
                    if (v.errors) |e| self.allocator.free(e);
                    self.allocator.free(v.traits);
                },
                .list => |v| {
                    self.allocator.free(v.traits);
                },
                .set => |v| {
                    self.allocator.free(v.traits);
                },
                .map => |v| {
                    self.allocator.free(v.key);
                    self.allocator.free(v.value);
                    self.allocator.free(v.traits);
                },
            }
        }
        self.allocator.free(self.shapes);
    }
};
pub const ShapeInfo = struct {
    id: []const u8,
    namespace: []const u8,
    name: []const u8,
    member: ?[]const u8,

    shape: Shape,
};

const ModelMetadata = struct {
    suppressions: []struct {
        id: []const u8,
        namespace: []const u8,
    },
};

pub const TraitType = enum {
    aws_api_service,
    aws_auth_sigv4,
    aws_protocol,
    ec2_query_name,
    http,
    http_header,
    http_label,
    http_query,
    http_payload,
    json_name,
    xml_name,
    required,
    documentation,
    pattern,
    range,
    length,
    box,
    sparse,
};
pub const Trait = union(TraitType) {
    aws_api_service: struct {
        sdk_id: []const u8,
        arn_namespace: []const u8,
        cloudformation_name: []const u8,
        cloudtrail_event_source: []const u8,
        endpoint_prefix: []const u8,
    },
    aws_auth_sigv4: struct {
        name: []const u8,
    },
    aws_protocol: AwsProtocol,
    ec2_query_name: []const u8,
    json_name: []const u8,
    xml_name: []const u8,
    http: struct {
        method: []const u8,
        uri: []const u8,
        code: i64 = 200,
    },
    http_header: []const u8,
    http_label: []const u8,
    http_query: []const u8,
    http_payload: struct {},
    required: struct {},
    documentation: []const u8,
    pattern: []const u8,
    range: struct { // most data is actually integers, but as some are floats, we'll use that here
        min: ?f64,
        max: ?f64,
    },
    length: struct {
        min: ?f64,
        max: ?f64,
    },
    box: struct {},
    sparse: struct {},
};
const ShapeType = enum {
    blob,
    boolean,
    string,
    byte,
    short,
    integer,
    long,
    float,
    double,
    bigInteger,
    bigDecimal,
    timestamp,
    document,
    member,
    list,
    set,
    map,
    structure,
    uniontype,
    service,
    operation,
    resource,
};
const TraitsOnly = struct {
    traits: []Trait,
};
pub const TypeMember = struct {
    name: []const u8,
    target: []const u8,
    traits: []Trait,
};
const Shape = union(ShapeType) {
    blob: TraitsOnly,
    boolean: TraitsOnly,
    string: TraitsOnly,
    byte: TraitsOnly,
    short: TraitsOnly,
    integer: TraitsOnly,
    long: TraitsOnly,
    float: TraitsOnly,
    double: TraitsOnly,
    bigInteger: TraitsOnly,
    bigDecimal: TraitsOnly,
    timestamp: TraitsOnly,
    document: TraitsOnly,
    member: TraitsOnly,
    list: struct {
        member_target: []const u8,
        traits: []Trait,
    },
    set: struct {
        member_target: []const u8,
        traits: []Trait,
    },
    map: struct {
        key: []const u8,
        value: []const u8,
        traits: []Trait,
    },
    structure: struct {
        members: []TypeMember,
        traits: []Trait,
    },
    uniontype: struct {
        members: []TypeMember,
        traits: []Trait,
    },
    service: struct {
        version: []const u8,
        operations: [][]const u8,
        resources: [][]const u8,
        traits: []Trait,
    },
    operation: struct {
        input: ?[]const u8,
        output: ?[]const u8,
        errors: ?[][]const u8,
        traits: []Trait,
    },
    resource: TraitsOnly,
};

// https://awslabs.github.io/smithy/1.0/spec/aws/index.html
pub const AwsProtocol = enum {
    query,
    rest_xml,
    json_1_1,
    json_1_0,
    rest_json_1,
    ec2_query,
};

pub fn parse(allocator: std.mem.Allocator, json_model: []const u8) !Smithy {
    // construct a parser. We're not copying strings here, but that may
    // be a poor decision
    var parser = std.json.Parser.init(allocator, false);
    defer parser.deinit();
    var vt = try parser.parse(json_model);
    defer vt.deinit();
    return Smithy.init(
        allocator,
        vt.root.Object.get("smithy").?.String,
        ModelMetadata{
            // TODO: implement
            .suppressions = &.{},
        },
        try shapes(allocator, vt.root.Object.get("shapes").?.Object),
    );
}

// anytype: HashMap([]const u8, std.json.Value...)
// list must be deinitialized by caller
fn shapes(allocator: std.mem.Allocator, map: anytype) ![]ShapeInfo {
    var list = try std.ArrayList(ShapeInfo).initCapacity(allocator, map.count());
    defer list.deinit();
    var iterator = map.iterator();
    while (iterator.next()) |kv| {
        const id_info = try parseId(kv.key_ptr.*);
        try list.append(.{
            .id = id_info.id,
            .namespace = id_info.namespace,
            .name = id_info.name,
            .member = id_info.member,
            .shape = try getShape(allocator, kv.value_ptr.*),
        });
    }
    // This seems to be a synonym for the simple type "string"
    // https://awslabs.github.io/smithy/1.0/spec/core/model.html#simple-types
    // But I don't see it in the spec. We might need to preload other similar
    // simple types?
    try list.append(.{
        .id = "smithy.api#String",
        .namespace = "smithy.api",
        .name = "String",
        .member = null,
        .shape = Shape{
            .string = .{
                .traits = &.{},
            },
        },
    });
    try list.append(.{
        .id = "smithy.api#Boolean",
        .namespace = "smithy.api",
        .name = "Boolean",
        .member = null,
        .shape = Shape{
            .boolean = .{
                .traits = &.{},
            },
        },
    });
    try list.append(.{
        .id = "smithy.api#Integer",
        .namespace = "smithy.api",
        .name = "Integer",
        .member = null,
        .shape = Shape{
            .integer = .{
                .traits = &.{},
            },
        },
    });
    try list.append(.{
        .id = "smithy.api#Double",
        .namespace = "smithy.api",
        .name = "Double",
        .member = null,
        .shape = Shape{
            .double = .{
                .traits = &.{},
            },
        },
    });
    try list.append(.{
        .id = "smithy.api#Timestamp",
        .namespace = "smithy.api",
        .name = "Timestamp",
        .member = null,
        .shape = Shape{
            .timestamp = .{
                .traits = &.{},
            },
        },
    });
    return list.toOwnedSlice();
}

fn getShape(allocator: std.mem.Allocator, shape: std.json.Value) SmithyParseError!Shape {
    const shape_type = shape.Object.get("type").?.String;
    if (std.mem.eql(u8, shape_type, "service"))
        return Shape{
            .service = .{
                .version = shape.Object.get("version").?.String,
                .operations = if (shape.Object.get("operations")) |ops|
                    try parseTargetList(allocator, ops.Array)
                else
                    &.{}, // this doesn't make much sense, but it's happening
                // TODO: implement. We need some sample data tho
                .resources = &.{},
                .traits = try parseTraits(allocator, shape.Object.get("traits")),
            },
        };
    if (std.mem.eql(u8, shape_type, "structure"))
        return Shape{
            .structure = .{
                .members = try parseMembers(allocator, shape.Object.get("members")),
                .traits = try parseTraits(allocator, shape.Object.get("traits")),
            },
        };
    if (std.mem.eql(u8, shape_type, "union"))
        return Shape{
            .uniontype = .{
                .members = try parseMembers(allocator, shape.Object.get("members")),
                .traits = try parseTraits(allocator, shape.Object.get("traits")),
            },
        };
    if (std.mem.eql(u8, shape_type, "operation"))
        return Shape{
            .operation = .{
                .input = if (shape.Object.get("input")) |member| member.Object.get("target").?.String else null,
                .output = if (shape.Object.get("output")) |member| member.Object.get("target").?.String else null,
                .errors = blk: {
                    if (shape.Object.get("errors")) |e| {
                        break :blk try parseTargetList(allocator, e.Array);
                    }
                    break :blk null;
                },
                .traits = try parseTraits(allocator, shape.Object.get("traits")),
            },
        };
    if (std.mem.eql(u8, shape_type, "list"))
        return Shape{
            .list = .{
                .member_target = shape.Object.get("member").?.Object.get("target").?.String,
                .traits = try parseTraits(allocator, shape.Object.get("traits")),
            },
        };
    if (std.mem.eql(u8, shape_type, "set"))
        return Shape{
            .set = .{
                .member_target = shape.Object.get("member").?.Object.get("target").?.String,
                .traits = try parseTraits(allocator, shape.Object.get("traits")),
            },
        };
    if (std.mem.eql(u8, shape_type, "map"))
        return Shape{
            .map = .{
                .key = shape.Object.get("key").?.Object.get("target").?.String,
                .value = shape.Object.get("value").?.Object.get("target").?.String,
                .traits = try parseTraits(allocator, shape.Object.get("traits")),
            },
        };
    if (std.mem.eql(u8, shape_type, "string"))
        return Shape{ .string = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "byte"))
        return Shape{ .byte = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "short"))
        return Shape{ .short = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "integer"))
        return Shape{ .integer = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "long"))
        return Shape{ .long = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "float"))
        return Shape{ .float = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "double"))
        return Shape{ .double = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "bigInteger"))
        return Shape{ .bigInteger = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "bigDecimal"))
        return Shape{ .bigDecimal = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "boolean"))
        return Shape{ .boolean = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "blob"))
        return Shape{ .blob = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "timestamp"))
        return Shape{ .timestamp = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "document"))
        return Shape{ .document = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "member"))
        return Shape{ .member = try parseTraitsOnly(allocator, shape) };
    if (std.mem.eql(u8, shape_type, "resource"))
        return Shape{ .resource = try parseTraitsOnly(allocator, shape) };

    std.debug.print("Invalid Type: {s}", .{shape_type});
    return SmithyParseError.InvalidType;
}

fn parseMembers(allocator: std.mem.Allocator, shape: ?std.json.Value) SmithyParseError![]TypeMember {
    var rc: []TypeMember = &.{};
    if (shape == null)
        return rc;

    const map = shape.?.Object;
    var list = std.ArrayList(TypeMember).initCapacity(allocator, map.count()) catch return SmithyParseError.OutOfMemory;
    defer list.deinit();
    var iterator = map.iterator();
    while (iterator.next()) |kv| {
        try list.append(TypeMember{
            .name = kv.key_ptr.*,
            .target = kv.value_ptr.*.Object.get("target").?.String,
            .traits = try parseTraits(allocator, kv.value_ptr.*.Object.get("traits")),
        });
    }
    return list.toOwnedSlice();
}

// ArrayList of std.Json.Value
fn parseTargetList(allocator: std.mem.Allocator, list: anytype) SmithyParseError![][]const u8 {
    var array_list = std.ArrayList([]const u8).initCapacity(allocator, list.items.len) catch return SmithyParseError.OutOfMemory;
    defer array_list.deinit();
    for (list.items) |i| {
        try array_list.append(i.Object.get("target").?.String);
    }
    return array_list.toOwnedSlice();
}
fn parseTraitsOnly(allocator: std.mem.Allocator, shape: std.json.Value) SmithyParseError!TraitsOnly {
    return TraitsOnly{
        .traits = try parseTraits(allocator, shape.Object.get("traits")),
    };
}

fn parseTraits(allocator: std.mem.Allocator, shape: ?std.json.Value) SmithyParseError![]Trait {
    var rc: []Trait = &.{};
    if (shape == null)
        return rc;

    const map = shape.?.Object;
    var list = std.ArrayList(Trait).initCapacity(allocator, map.count()) catch return SmithyParseError.OutOfMemory;
    defer list.deinit();
    var iterator = map.iterator();
    while (iterator.next()) |kv| {
        if (try getTrait(kv.key_ptr.*, kv.value_ptr.*)) |t|
            try list.append(t);
    }
    return list.toOwnedSlice();
}

fn getTrait(trait_type: []const u8, value: std.json.Value) SmithyParseError!?Trait {
    if (std.mem.eql(u8, trait_type, "aws.api#service"))
        return Trait{
            .aws_api_service = .{
                .sdk_id = value.Object.get("sdkId").?.String,
                .arn_namespace = value.Object.get("arnNamespace").?.String,
                .cloudformation_name = value.Object.get("cloudFormationName").?.String,
                .cloudtrail_event_source = value.Object.get("cloudTrailEventSource").?.String,
                // what good is a service without an endpoint? I don't know - ask amp
                .endpoint_prefix = if (value.Object.get("endpointPrefix")) |endpoint| endpoint.String else "",
            },
        };
    if (std.mem.eql(u8, trait_type, "aws.auth#sigv4"))
        return Trait{
            .aws_auth_sigv4 = .{
                .name = value.Object.get("name").?.String,
            },
        };
    if (std.mem.eql(u8, trait_type, "smithy.api#required"))
        return Trait{ .required = .{} };
    if (std.mem.eql(u8, trait_type, "smithy.api#sparse"))
        return Trait{ .sparse = .{} };
    if (std.mem.eql(u8, trait_type, "smithy.api#box"))
        return Trait{ .box = .{} };

    if (std.mem.eql(u8, trait_type, "smithy.api#range"))
        return Trait{
            .range = .{
                .min = getOptionalNumber(value, "min"),
                .max = getOptionalNumber(value, "max"),
            },
        };
    if (std.mem.eql(u8, trait_type, "smithy.api#length"))
        return Trait{
            .length = .{
                .min = getOptionalNumber(value, "min"),
                .max = getOptionalNumber(value, "max"),
            },
        };
    if (std.mem.eql(u8, trait_type, "aws.protocols#restJson1"))
        return Trait{
            .aws_protocol = .rest_json_1,
        };
    if (std.mem.eql(u8, trait_type, "aws.protocols#awsJson1_0"))
        return Trait{
            .aws_protocol = .json_1_0,
        };
    if (std.mem.eql(u8, trait_type, "aws.protocols#awsJson1_1"))
        return Trait{
            .aws_protocol = .json_1_1,
        };
    if (std.mem.eql(u8, trait_type, "aws.protocols#restXml"))
        return Trait{
            .aws_protocol = .rest_xml,
        };
    if (std.mem.eql(u8, trait_type, "aws.protocols#awsQuery"))
        return Trait{
            .aws_protocol = .query,
        };
    if (std.mem.eql(u8, trait_type, "aws.protocols#ec2Query"))
        return Trait{
            .aws_protocol = .ec2_query,
        };

    if (std.mem.eql(u8, trait_type, "smithy.api#documentation"))
        return Trait{ .documentation = value.String };
    if (std.mem.eql(u8, trait_type, "smithy.api#pattern"))
        return Trait{ .pattern = value.String };

    if (std.mem.eql(u8, trait_type, "aws.protocols#ec2QueryName"))
        return Trait{ .ec2_query_name = value.String };

    if (std.mem.eql(u8, trait_type, "smithy.api#http")) {
        var code: i64 = 200;
        if (value.Object.get("code")) |v| {
            if (v == .Integer)
                code = v.Integer;
        }
        return Trait{ .http = .{
            .method = value.Object.get("method").?.String,
            .uri = value.Object.get("uri").?.String,
            .code = code,
        } };
    }
    if (std.mem.eql(u8, trait_type, "smithy.api#jsonName"))
        return Trait{ .json_name = value.String };
    if (std.mem.eql(u8, trait_type, "smithy.api#xmlName"))
        return Trait{ .xml_name = value.String };
    if (std.mem.eql(u8, trait_type, "smithy.api#httpQuery"))
        return Trait{ .http_query = value.String };
    if (std.mem.eql(u8, trait_type, "smithy.api#httpHeader"))
        return Trait{ .http_header = value.String };
    if (std.mem.eql(u8, trait_type, "smithy.api#httpPayload"))
        return Trait{ .http_payload = .{} };

    // TODO: Maybe care about these traits?
    if (std.mem.eql(u8, trait_type, "smithy.api#title"))
        return null;

    if (std.mem.eql(u8, trait_type, "smithy.api#xmlNamespace"))
        return null;
    // TODO: win argument with compiler to get this comptime
    const list =
        \\aws.api#arnReference
        \\aws.api#clientDiscoveredEndpoint
        \\aws.api#clientEndpointDiscovery
        \\aws.api#arn
        \\aws.auth#unsignedPayload
        \\aws.iam#disableConditionKeyInference
        \\smithy.api#auth
        \\smithy.api#cors
        \\smithy.api#deprecated
        \\smithy.api#endpoint
        \\smithy.api#enum
        \\smithy.api#error
        \\smithy.api#eventPayload
        \\smithy.api#externalDocumentation
        \\smithy.api#hostLabel
        \\smithy.api#httpError
        \\smithy.api#httpChecksumRequired
        \\smithy.api#httpLabel
        \\smithy.api#httpPrefixHeaders
        \\smithy.api#httpQueryParams
        \\smithy.api#httpResponseCode
        \\smithy.api#idempotencyToken
        \\smithy.api#idempotent
        \\smithy.api#mediaType
        \\smithy.api#noReplace
        \\smithy.api#optionalAuth
        \\smithy.api#paginated
        \\smithy.api#readonly
        \\smithy.api#references
        \\smithy.api#requiresLength
        \\smithy.api#retryable
        \\smithy.api#sensitive
        \\smithy.api#streaming
        \\smithy.api#suppress
        \\smithy.api#tags
        \\smithy.api#timestampFormat
        \\smithy.api#xmlAttribute
        \\smithy.api#xmlFlattened
        \\smithy.waiters#waitable
    ;
    var iterator = std.mem.split(u8, list, "\n");
    while (iterator.next()) |known_but_unimplemented| {
        if (std.mem.eql(u8, trait_type, known_but_unimplemented))
            return null;
    }

    // Totally unknown type
    std.log.err("Invalid Trait Type: {s}", .{trait_type});
    return null;
}
fn getOptionalNumber(value: std.json.Value, key: []const u8) ?f64 {
    if (value.Object.get(key)) |v|
        return switch (v) {
            .Integer => @intToFloat(f64, v.Integer),
            .Float => v.Float,
            .Null, .Bool, .NumberString, .String, .Array, .Object => null,
        };
    return null;
}
const IdInfo = struct { id: []const u8, namespace: []const u8, name: []const u8, member: ?[]const u8 };
const SmithyParseError = error{
    NoHashtagFound,
    InvalidType,
    OutOfMemory,
};
fn parseId(id: []const u8) SmithyParseError!IdInfo {
    var hashtag: ?usize = null;
    var dollar: ?usize = null;
    var inx: usize = 0;
    for (id) |ch| {
        switch (ch) {
            '#' => hashtag = inx,
            '$' => dollar = inx,
            else => {},
        }
        inx = inx + 1;
    }
    if (hashtag == null) {
        std.debug.print("no hashtag found on id: {s}\n", .{id});
        return SmithyParseError.NoHashtagFound;
    }
    const namespace = id[0..hashtag.?];
    var end = id.len;
    var member: ?[]const u8 = null;
    if (dollar) |d| {
        member = id[dollar.? + 1 .. end];
        end = d;
    }
    const name = id[hashtag.? + 1 .. end];
    return IdInfo{
        .id = id,
        .namespace = namespace,
        .name = name,
        .member = member,
    };
}
fn read_file_to_string(allocator: std.mem.Allocator, file_name: []const u8, max_bytes: usize) ![]const u8 {
    const file = try std.fs.cwd().openFile(file_name, std.fs.File.OpenFlags{});
    defer file.close();
    return file.readToEndAlloc(allocator, max_bytes);
}
var test_data: ?[]const u8 = null;
const intrinsic_type_count: usize = 5; // 5 intrinsic types are added to every model

fn getTestData(_: *std.mem.Allocator) []const u8 {
    if (test_data) |d| return d;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    test_data = read_file_to_string(gpa.allocator, "test.json", 150000) catch @panic("could not read test.json");
    return test_data.?;
}
test "read file" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit()) @panic("leak");
    const allocator = gpa.allocator;
    _ = getTestData(allocator);
    // test stuff
}
test "parse string" {
    const test_string =
        \\ {
        \\     "smithy": "1.0",
        \\     "shapes": {
        \\         "com.amazonaws.sts#AWSSecurityTokenServiceV20110615": {
        \\             "type": "service",
        \\             "version": "2011-06-15",
        \\             "operations": [
        \\                 {
        \\                     "target": "op"
        \\                 }
        \\             ]
        \\         }
        \\     }
        \\ }
        \\
        \\
    ;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit()) @panic("leak");
    const allocator = gpa.allocator;
    const model = try parse(allocator, test_string);
    defer model.deinit();
    try expect(std.mem.eql(u8, model.version, "1.0"));

    try std.testing.expectEqual(intrinsic_type_count + 1, model.shapes.len);
    try std.testing.expectEqualStrings("com.amazonaws.sts#AWSSecurityTokenServiceV20110615", model.shapes[0].id);
    try std.testing.expectEqualStrings("com.amazonaws.sts", model.shapes[0].namespace);
    try std.testing.expectEqualStrings("AWSSecurityTokenServiceV20110615", model.shapes[0].name);
    try std.testing.expect(model.shapes[0].member == null);
    try std.testing.expectEqualStrings("2011-06-15", model.shapes[0].shape.service.version);
}
test "parse shape with member" {
    const test_string =
        \\ {
        \\     "smithy": "1.0",
        \\     "shapes": {
        \\         "com.amazonaws.sts#AWSSecurityTokenServiceV20110615$member": {
        \\             "type": "service",
        \\             "version": "2011-06-15",
        \\             "operations": [
        \\                 {
        \\                     "target": "op"
        \\                 }
        \\             ]
        \\         }
        \\     }
        \\ }
        \\
        \\
    ;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit()) @panic("leak");
    const allocator = gpa.allocator;
    const model = try parse(allocator, test_string);
    defer model.deinit();
    try expect(std.mem.eql(u8, model.version, "1.0"));
    try std.testing.expectEqual(intrinsic_type_count + 1, model.shapes.len);
    try std.testing.expectEqualStrings("com.amazonaws.sts#AWSSecurityTokenServiceV20110615$member", model.shapes[0].id);
    try std.testing.expectEqualStrings("com.amazonaws.sts", model.shapes[0].namespace);
    try std.testing.expectEqualStrings("AWSSecurityTokenServiceV20110615", model.shapes[0].name);
    try std.testing.expectEqualStrings("2011-06-15", model.shapes[0].shape.service.version);
    try std.testing.expectEqualStrings("member", model.shapes[0].member.?);
}
test "parse file" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit()) @panic("leak");
    const allocator = gpa.allocator;
    const test_string = getTestData(allocator);
    const model = try parse(allocator, test_string);
    defer model.deinit();
    try std.testing.expectEqualStrings(model.version, "1.0");
    // metadata expectations
    // try expect(std.mem.eql(u8, model.version, "version 1.0"));

    // shape expectations
    try std.testing.expectEqual(intrinsic_type_count + 81, model.shapes.len);
    var optsvc: ?ShapeInfo = null;
    for (model.shapes) |shape| {
        if (std.mem.eql(u8, shape.id, "com.amazonaws.sts#AWSSecurityTokenServiceV20110615")) {
            optsvc = shape;
            break;
        }
    }
    try std.testing.expect(optsvc != null);
    const svc = optsvc.?;
    try std.testing.expectEqualStrings("com.amazonaws.sts#AWSSecurityTokenServiceV20110615", svc.id);
    try std.testing.expectEqualStrings("com.amazonaws.sts", svc.namespace);
    try std.testing.expectEqualStrings("AWSSecurityTokenServiceV20110615", svc.name);
    try std.testing.expectEqualStrings("2011-06-15", svc.shape.service.version);
    // Should be 6, but we don't handle title or xml namespace
    try std.testing.expectEqual(@as(usize, 4), svc.shape.service.traits.len);
    try std.testing.expectEqual(@as(usize, 8), svc.shape.service.operations.len);
}

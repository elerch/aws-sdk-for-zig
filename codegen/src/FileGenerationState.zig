const std = @import("std");
const smithy = @import("smithy");

const FileGenerationState = @This();

protocol: smithy.AwsProtocol,
shapes: std.StringHashMap(smithy.ShapeInfo),
shape_references: std.StringHashMap(u64),
additional_types_to_generate: *std.ArrayList(smithy.ShapeInfo),
additional_types_generated: *std.StringHashMap(void),

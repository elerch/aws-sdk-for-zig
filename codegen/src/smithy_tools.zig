const std = @import("std");
const smithy = @import("smithy");

pub const Shape = @FieldType(smithy.ShapeInfo, "shape");
pub const ServiceShape = @TypeOf((Shape{ .service = undefined }).service);
pub const ListShape = @TypeOf((Shape{ .list = undefined }).list);
pub const MapShape = @TypeOf((Shape{ .map = undefined }).map);

pub fn getShapeInfo(id: []const u8, shapes: std.StringHashMap(smithy.ShapeInfo)) !smithy.ShapeInfo {
    return shapes.get(id) orelse {
        std.debug.print("Shape ID not found. This is most likely a bug. Shape ID: {s}\n", .{id});
        return error.InvalidType;
    };
}

pub fn getShapeTraits(shape: Shape) []smithy.Trait {
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

pub fn getShapeMembers(shape: Shape) []smithy.TypeMember {
    return switch (shape) {
        .structure => |s| s.members,
        .uniontype => |s| s.members,
        else => std.debug.panic("Unexpected shape type: {}", .{shape}),
    };
}

pub fn shapeIsLeaf(shape: Shape) bool {
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

pub fn shapeIsOptional(traits: []smithy.Trait) bool {
    return !hasTrait(.required, traits);
}

pub fn findTrait(trait_type: smithy.TraitType, traits: []smithy.Trait) ?smithy.Trait {
    for (traits) |trait| {
        if (trait == trait_type) {
            return trait;
        }
    }

    return null;
}

pub fn hasTrait(trait_type: smithy.TraitType, traits: []smithy.Trait) bool {
    return findTrait(trait_type, traits) != null;
}

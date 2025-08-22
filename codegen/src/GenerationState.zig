const std = @import("std");
const smithy = @import("smithy");

const FileGenerationState = @import("FileGenerationState.zig");

const GenerationState = @This();

type_stack: *std.ArrayList(*const smithy.ShapeInfo),
file_state: FileGenerationState,
// we will need some sort of "type decls needed" for recursive structures
allocator: std.mem.Allocator,
indent_level: u64,

pub fn appendToTypeStack(self: @This(), shape_info: *const smithy.ShapeInfo) !void {
    try self.type_stack.append(self.allocator, shape_info);
}

pub fn popFromTypeStack(self: @This()) void {
    _ = self.type_stack.pop();
}

pub fn getTypeRecurrenceCount(self: @This(), id: []const u8) u8 {
    var self_occurences: u8 = 0;

    for (self.type_stack.items) |i| {
        if (std.mem.eql(u8, i.id, id)) {
            self_occurences += 1;
        }
    }

    return self_occurences;
}

pub fn indent(self: @This()) GenerationState {
    var new_state = self.clone();
    new_state.indent_level += 1;
    return new_state;
}

pub fn deindent(self: @This()) GenerationState {
    var new_state = self.clone();
    new_state.indent_level = @max(0, new_state.indent_level - 1);
    return new_state;
}

pub fn clone(self: @This()) GenerationState {
    return GenerationState{
        .type_stack = self.type_stack,
        .file_state = self.file_state,
        .allocator = self.allocator,
        .indent_level = self.indent_level,
    };
}

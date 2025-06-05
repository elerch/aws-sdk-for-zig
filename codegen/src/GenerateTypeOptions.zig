const std = @import("std");
const case = @import("case");

const GenerateTypeOptions = @This();

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

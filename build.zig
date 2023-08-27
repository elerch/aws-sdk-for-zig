const std = @import("std");
const builtin = @import("builtin");
const Builder = @import("std").build.Builder;
const Package = @import("Package.zig");

const models_url = "https://github.com/aws/aws-sdk-go-v2/archive/7502ff360b1c3b79cbe117437327f6ff5fb89f65.tar.gz";
const models_hash: ?[]const u8 = "1220a414719bff14c9362fb1c695e3346fa12ec2e728bae5757a57aae7738916ffd2";
const models_subdir = "codegen/sdk-codegen/aws-models/"; // note will probably not work on windows
const models_dir = "p" ++ std.fs.path.sep_str ++ (models_hash orelse "") ++ std.fs.path.sep_str ++ models_subdir;

pub fn build(b: *Builder) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const optimize = b.standardOptimizeOption(.{});

    // TODO: Embed the current git version in the code. We can do this
    // by looking for .git/HEAD (if it exists, follow the ref to /ref/heads/whatevs,
    // grab that commit, and use b.addOptions/exe.addOptions to generate the
    // Options file. See https://github.com/ziglang/zig/issues/14979 for usage
    // example.
    //
    // From there, I'm not sure what the generated file looks like or quite how
    // to use, but that should be easy. It may also give some ideas on the
    // code gen piece itself, though it might be nice to leave as a seperate
    // executable
    const exe = b.addExecutable(.{
        .name = "demo",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    const smithy_dep = b.dependency("smithy", .{
        // These are the arguments to the dependency. It expects a target and optimization level.
        .target = target,
        .optimize = optimize,
    });
    exe.addModule("smithy", smithy_dep.module("smithy"));

    const module = b.addModule("aws", .{
        .source_file = .{ .path = "src/aws.zig" },
    });
    exe.addModule("aws", module);
    // TODO: This does not work correctly due to https://github.com/ziglang/zig/issues/16354
    //
    // We are working here with kind of a weird dependency though. So we can do this
    // another way
    //
    // TODO: These target/optimize are not correct, as we need to run the thing
    // const codegen = b.anonymousDependency("codegen/", @import("codegen/build.zig"), .{
    //     .target = target,
    //     .optimize = optimize,
    // });
    // const codegen_cmd = b.addRunArtifact(codegen.artifact("codegen"));
    // exe.step.dependOn(&codegen_cmd.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/aws.zig" },
        .target = target,
        .optimize = optimize,
    });
    unit_tests.addModule("smithy", smithy_dep.module("smithy"));

    const run_unit_tests = b.addRunArtifact(unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const fm = b.step("fetch", "Fetch model files");
    var fetch_step = FetchStep.create(b, models_url, models_hash);
    fm.dependOn(&fetch_step.step);
    {
        const cg = b.step("gen", "Generate zig service code from smithy models");

        const cg_exe = b.addExecutable(.{
            .name = "codegen",
            .root_source_file = .{ .path = "codegen/src/main.zig" },
            // We need this generated for the host, not the real target
            // .target = target,
            .optimize = if (b.verbose) .Debug else .ReleaseSafe,
        });
        cg_exe.addModule("smithy", smithy_dep.module("smithy"));
        var cg_cmd = b.addRunArtifact(cg_exe);
        cg_cmd.addArg("--models");
        cg_cmd.addArg(try std.fs.path.join(
            b.allocator,
            &[_][]const u8{ b.global_cache_root.path.?, models_dir },
        ));
        // cg_cmd.addDirectoryArg(std.Build.FileSource.relative("codegen/models"));
        cg_cmd.addArg("--output");
        cg_cmd.addDirectoryArg(std.Build.FileSource.relative("src/models"));
        if (b.verbose)
            cg_cmd.addArg("--verbose");
        cg_cmd.step.dependOn(&fetch_step.step);
        // TODO: this should use zig_exe from std.Build
        // codegen should store a hash in a comment
        // this would be hash of the exe that created the file
        // concatenated with hash of input json. this would
        // allow skipping generated files. May not include hash
        // of contents of output file as maybe we want to tweak
        // manually??
        //
        // All the hashes can be in service_manifest.zig, which
        // could be fun to just parse and go nuts. Top of
        // file, generator exe hash. Each import has comment
        // with both input and output hash and we can decide
        // later about warning on manual changes...
        //
        // this scheme would permit cross plat codegen and maybe
        // we can have codegen added in a seperate repo,
        // though not sure how necessary that is
        // cg.dependOn(&b.addSystemCommand(&.{
        //     b.zig_exe,
        //     "build",
        //     "run",
        //     "-Doptimize=ReleaseSafe",
        // }).step);

        cg.dependOn(&cg_cmd.step);
        exe.step.dependOn(cg);
        unit_tests.step.dependOn(cg);
    }

    b.installArtifact(exe);
}
const FetchStep = struct {
    step: std.Build.Step,
    url: []const u8,
    hash: ?[]const u8,

    pub fn create(owner: *std.Build, url: []const u8, hash: ?[]const u8) *FetchStep {
        const fs = owner.allocator.create(FetchStep) catch @panic("OOM");
        fs.* = .{
            .step = std.Build.Step.init(.{
                .id = .custom,
                .name = "FetchStep",
                .owner = owner,
                .makeFn = make,
            }),
            .url = url,
            .hash = hash,
        };
        return fs;
    }

    fn make(step: *std.Build.Step, prog_node: *std.Progress.Node) !void {
        const b = step.owner;
        const self = @fieldParentPtr(FetchStep, "step", step);

        const alloc = b.allocator;
        var http_client: std.http.Client = .{ .allocator = alloc };
        defer http_client.deinit();

        var thread_pool: std.Thread.Pool = undefined;
        try thread_pool.init(.{ .allocator = alloc });
        defer thread_pool.deinit();
        const pkg = try Package.fetchAndUnpack(
            &thread_pool,
            &http_client,
            b.global_cache_root,
            .{
                .url = self.url,
                .hash = self.hash,
            },
            self.url,
            prog_node,
        );
        defer alloc.destroy(pkg);
        defer pkg.deinit();
    }
};

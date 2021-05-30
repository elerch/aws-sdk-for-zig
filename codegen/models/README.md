Model generation
================

Because only models actually used by the application will be
generated, one model or separate models do not make as much of a difference
as they do in other languages. We can combine all models from AWS into a single
comptime constant even, however, we're keeping zig files 1:1 with json files
for now.

The main executable, run with a "-s" first argument, will simply parse the
Smithy json files passed by the rest of the arguments and save each one as
its own file.json.zig. We will rely on shell commands to do the rest of the
renaming (and moving if necessary).

To run this, we can use `codegen -s models/*.json`, which takes 20 seconds
or so on my i5 chromebook and probably significantly faster on a real machine.
No attempt has been made to optimize. Also, there are several bugs:

* I do not think all the optional types have been sorted.
* I think there is necessary metadata missing from EC2Query style services
* The output will compile and is close to what `zig fmt` likes to see, but it
  has not yet been functionally tested
* It handles all the types in existing AWS services, but it does not handle
  all known Smithy types (e.g. blob and document are missing)
* It would be awesome to bring over the documentation from the model into
  zig-style doc comments
* Self-referencing types are hard-coded to cut off after several nesting
  operations. Ideally these would be pulled out into their own types, but
  realistically I'm not sure if that will matter long term, and it's a fair
  amount of work as everything now can be done in a single pass without post
  processing.
* This doesn't seem to build on 0.7.1 - you need master branch. I hope that
  0.8.0 will be out soon. If not, a few syntax changes need to be accommodated.

Some of these will likely be addressed as I integrate the code generated files into
the SDK engine.

The models are Smithy json files, sourced from the AWS v2 go sdk
for lack of a better place. I've just downloaded the main branch and copied
the files from the tree in place.


Model generation
================

Because only models actually used by the application will be
generated, one model or separate models do not make as much of a difference
as they do in other languages. We can combine all models from AWS into a single
comptime constant even, however, we're keeping zig files 1:1 with json files
for now.

Optimization plan will be done by the placing of a json file in the output
directory. The json file will contain a mapping between input files and generated
outputs, as well as a top level directory hash. We can skip the output generation
entirely if the top level hash matches, otherwise, individual hashes will be
compared and output files will only regenerate if the input or output has changed.


Todo
----

* I do not think all the optional types have been sorted.
* I think there is necessary metadata missing from EC2Query style services
* It handles all the types in existing AWS services, but it does not handle
  all known Smithy types (e.g. blob and document are missing)
* It would be awesome to bring over the documentation from the model into
  zig-style doc comments
* Self-referencing types are hard-coded to cut off after several nesting
  operations. Ideally these would be pulled out into their own types, but
  realistically I'm not sure if that will matter long term, and it's a fair
  amount of work as everything now can be done in a single pass without post
  processing.

The models are Smithy json files, sourced from the AWS v2 go sdk
for lack of a better place. Details are in build.zig of the parent project
that is now responsible for downloading/caching the project.

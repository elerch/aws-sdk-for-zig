# AWS SDK for Zig (zig-native branch)

[![Build Status](https://drone.lerch.org/api/badges/lobo/aws-sdk-for-zig/status.svg?ref=refs/heads/zig-native)](https://drone.lerch.org/api/badges/lobo/aws-sdk-for-zig/status.svg?ref=refs/heads/zig-native)

## WARNING: This branch is in development, with builds currently failing!

This SDK currently supports all AWS services except EC2 and S3. These two
services only support XML, and zig 0.8.0 and master both trigger compile
errors while incorporating the XML parser. S3 also requires some plumbing
tweaks in the signature calculation, which is planned for a zig version
(probably self-hosted 0.9.0) that no longer has an error triggered. Examples
of usage are in src/main.zig.

This is designed to be built statically using the `aws_c_*` libraries, so
we inherit a lot of the goodness of the work going on there. Current
executable size is 9.7M, about half of which is due to the SSL library.
Running strip on the executable after compilation (it seems zig strip
only goes so far), reduces this to 4.3M. This is for x86_linux,
(which is all that's tested at the moment).

## Building

`zig build` should work. It will build the code generation project, run
the code generation, then build the main project with the generated code.
There is also a Makefile included, but this hasn't been used in a while
and I'm not sure that works at the moment.

First time build should use `zig build -Dfetch` to fetch dependent packages
(zfetch and friends).

## Running

This library mimics the aws c libraries for it's work, so it operates like most
other 'AWS things'. main.zig gives you a handful of examples for working with services.
For local testing or alternative endpoints, there's no real standard, so
there is code to look for `AWS_ENDPOINT_URL` environment variable that will
supersede all other configuration.

TODO List:

* Implement credentials provider
* Implement sigv4 signing
* Implement jitter/exponential backoff. This appears to be configuration of
  `aws_c_io` and should therefore be trivial
* Implement timeouts and other TODO's in the code
* Switch to aws-c-cal upstream once [PR for full static musl build support is merged](https://github.com/awslabs/aws-c-cal/pull/89)
  (see Dockerfile)
* Implement [AWS restXml protocol](https://awslabs.github.io/smithy/1.0/spec/aws/aws-restxml-protocol.html).
  Includes S3. Total service count 4. This may be blocked due to the same issue as EC2.
* Implement [AWS EC2 query protocol](https://awslabs.github.io/smithy/1.0/spec/aws/aws-ec2-query-protocol.html).
  Includes EC2. Total service count 1. This is currently blocked, probably on
  self-hosted compiler coming in zig 0.9.0 (January 2022) due to compiler bug
  discovered. More details and llvm ir log can be found in the
  [XML branch](https://git.lerch.org/lobo/aws-sdk-for-zig/src/branch/xml).
* Implement sigv4a signing

Compiler wishlist/watchlist:

* [Merge PR to allow stripping -static](https://github.com/ziglang/zig/pull/8248)
* [comptime allocations](https://github.com/ziglang/zig/issues/1291) so we can read files, etc (or is there another way)

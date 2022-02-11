# AWS SDK for Zig (zig native branch)

[![Build Status](https://drone.lerch.org/api/badges/lobo/aws-sdk-for-zig/status.svg?ref=refs/heads/master)](https://drone.lerch.org/api/badges/lobo/aws-sdk-for-zig/)

This SDK currently supports all AWS services except EC2 and S3. These two
services only support XML, and more work is needed to parse and integrate
type hydration from the base parsing. S3 also requires some plumbing tweaks
in the signature calculation. Examples of usage are in src/main.zig.

Current executable size for the demo is 953k (90k of which is the AWS PEM file)
after compiling with -Drelease-safe and
[stripping the executable after compilation](https://github.com/ziglang/zig/issues/351).
This is for x86_linux. Tested targets:

* x86_64-linux
* riscv64-linux
* aarch64-linux
* x86_64-windows
* arm-linux
* aarch64-macos
* x86_64-macos

Tested targets are built, but not continuously tested, by CI.

## Building

`zig build` should work. It will build the code generation project, run
the code generation, then build the main project with the generated code.

First time build should use `zig build -Dfetch` to fetch dependent packages
(zfetch and friends).

## Running

This library mimics the aws c libraries for it's work, so it operates like most
other 'AWS things'. main.zig gives you a handful of examples for working with services.
For local testing or alternative endpoints, there's no real standard, so
there is code to look for `AWS_ENDPOINT_URL` environment variable that will
supersede all other configuration. Note that an alternative endpoint may
require passing in a client option to specify an different TLS root certificate
(pass null to disable certificate verification).

The [old branch](https://github.com/elerch/aws-sdk-for-zig/tree/aws-crt) exists
for posterity, and supports x86_64 linux. This branch is recommended moving
forward.

## Limitations

There are many nuances of AWS V4 signature calculation. S3 is not supported
because it uses many of these test cases. WebIdentityToken is not yet
implemented.

TODO List:

* Complete integration of Xml responses with remaining code base
* Implement [AWS restXml protocol](https://awslabs.github.io/smithy/1.0/spec/aws/aws-restxml-protocol.html).
  Includes S3. Total service count 4. This may be blocked due to the same issue as EC2.
* Implement [AWS EC2 query protocol](https://awslabs.github.io/smithy/1.0/spec/aws/aws-ec2-query-protocol.html).
  Includes EC2. Total service count 1. This may be blocked on a compiler bug,
  though has not been tested with zig 0.9.0. More details and llvm ir log can be found in the
  [XML branch](https://git.lerch.org/lobo/aws-sdk-for-zig/src/branch/xml).
* Implement sigv4a signing
* Implement jitter/exponential backoff
* Implement timeouts and other TODO's in the code
* Add option to cache signature keys

Compiler wishlist/watchlist:

* [Merge PR to allow stripping -static](https://github.com/ziglang/zig/pull/8248)
* [comptime allocations](https://github.com/ziglang/zig/issues/1291) so we can read files, etc (or is there another way)

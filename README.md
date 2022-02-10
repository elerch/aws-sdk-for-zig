# AWS SDK for Zig (zig native branch)

[![Build Status](https://drone.lerch.org/api/badges/lobo/aws-sdk-for-zig/status.svg?ref=refs/heads/master)](https://drone.lerch.org/api/badges/lobo/aws-sdk-for-zig/)


### NOTE: All tests pass, but credentials currently must be passed through environment

This SDK currently supports all AWS services except EC2 and S3. These two
services only support XML, and zig 0.8.0 and master both trigger compile
errors while incorporating the XML parser. S3 also requires some plumbing
tweaks in the signature calculation. Examples of usage are in src/main.zig.

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

Given that credential handling is still very basic, you may want to look at
the [old branch](https://github.com/elerch/aws-sdk-for-zig/tree/aws-crt) if
your needs include something more robust. Note that that branch supports
x86_64 linux only.

## Limitations

There are many nuances of AWS V4 signature calculation. S3 is not supported
because it uses many of these test cases. STS tokens using a session token
are not yet implemented, though should be trivial. I have also seen a few
service errors caused by discrepancies in signatures, though I don't know yet
if this was an issue in the service itself (has not repro'd) or if there
is a latent bug.

Only environment variable based credentials can be used at the moment.

TODO List:

* Implement [AWS restXml protocol](https://awslabs.github.io/smithy/1.0/spec/aws/aws-restxml-protocol.html).
  Includes S3. Total service count 4. This may be blocked due to the same issue as EC2.
* Implement [AWS EC2 query protocol](https://awslabs.github.io/smithy/1.0/spec/aws/aws-ec2-query-protocol.html).
  Includes EC2. Total service count 1. This may be blocked on a compiler bug,
  though has not been tested with zig 0.9.0. It may need to wait for zig 0.10.0
  when self-hosted compiler is likely to be completed (zig 0.10.0 eta May 2022)
  discovered. More details and llvm ir log can be found in the
  [XML branch](https://git.lerch.org/lobo/aws-sdk-for-zig/src/branch/xml).
* Implement sigv4a signing
* Implement jitter/exponential backoff
* Implement timeouts and other TODO's in the code
* Add option to cache signature keys

Compiler wishlist/watchlist:

* [Merge PR to allow stripping -static](https://github.com/ziglang/zig/pull/8248)
* [comptime allocations](https://github.com/ziglang/zig/issues/1291) so we can read files, etc (or is there another way)

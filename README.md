# AWS SDK for Zig

[![Build Status](https://drone.lerch.org/api/badges/lobo/aws-sdk-for-zig/status.svg?ref=refs/heads/master)](https://drone.lerch.org/api/badges/lobo/aws-sdk-for-zig/)

This SDK currently supports all AWS services except S3. See TODO list below.

Current executable size for the demo is 1.7M (90k of which is the AWS PEM file,
and approximately 600K for XML services) after compiling with -Drelease-safe and
[stripping the executable after compilation](https://github.com/ziglang/zig/issues/351).
This is for x86_linux, and will vary based on services used. Tested targets:

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
for posterity, and supports x86_64 linux. The old branch is deprecated.

## Limitations

There are many nuances of AWS V4 signature calculation. S3 is not supported
because it uses many of these edge cases. Also endpoint calculation is special
for S3. WebIdentityToken is not yet implemented.

TODO List:

* Implement initial S3 support. This involves:
  * Implementation of AWS SigV4 signature calculation for S3, which is unique
  * Implementation of S3 endpoint calculation, which is also unique to this service
* Bump to zig 0.9.1. iguanaTLS, used in zFetch is still [working out 0.9.1 issues](https://github.com/alexnask/iguanaTLS/pull/29)
* Implement sigv4a signing
* Implement jitter/exponential backoff
* Implement timeouts and other TODO's in the code
* Add option to cache signature keys

Compiler wishlist/watchlist:

* [Merge PR to allow stripping -static](https://github.com/ziglang/zig/pull/8248)
* [comptime allocations](https://github.com/ziglang/zig/issues/1291) so we can read files, etc (or is there another way)

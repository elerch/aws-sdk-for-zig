# AWS SDK for Zig

[![Build Status](https://actions-status.lerch.org/lobo/aws-sdk-for-zig/build)](https://git.lerch.org/lobo/aws-sdk-for-zig/actions?workflow=build.yaml&state=closed)

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

WebIdentityToken is not yet implemented.

TODO List:

* Bump to zig 0.11 and replace zFetch with [std.http.Client](https://github.com/ziglang/zig/blob/master/lib/std/http/Client.zig)
* Verify strip on static builds in 0.11
* Implement sigv4a signing
* Implement jitter/exponential backoff
* Implement timeouts and other TODO's in the code
* Add option to cache signature keys
* Move CI to github actions based on [gittea's implementation](https://blog.gitea.io/2022/12/feature-preview-gitea-actions/)

Compiler wishlist/watchlist:

* [comptime allocations](https://github.com/ziglang/zig/issues/1291) so we can read files, etc (or is there another way)

AWS SDK for Zig
===============

[![Build Status](https://actions-status.lerch.org/lobo/aws-sdk-for-zig/build)](https://git.lerch.org/lobo/aws-sdk-for-zig/actions?workflow=build.yaml&state=closed)

**NOTE: THIS SDK IS ONLY CURRENTLY USABLE FOR A SMALL SUBSET OF AWS SERVICES
            WITHOUT A PROXY. SEE LIMITATIONS SECTION BELOW**

Current executable size for the demo is 980k after compiling with -Doptimize=ReleaseSmall
in x86_linux, and will vary based on services used. Tested targets:

* x86_64-linux
* riscv64-linux
* aarch64-linux
* x86_64-windows
* arm-linux
* aarch64-macos
* x86_64-macos

Tested targets are built, but not continuously tested, by CI.

Building
--------

`zig build` should work. It will build the code generation project, fetch model
files from upstream AWS Go SDK v2, run the code generation, then build the main
project with the generated code. Testing can be done with `zig test`.

Note that there are some loose ends on this version as compared to the [0.9.0
branch](https://git.lerch.org/lobo/aws-sdk-for-zig/src/branch/0.9.0). More
details below in Limitations. This branch overall is superior, as is the 0.11
compiler, but if you need an edge case and don't want to issue a PR, feel free
to use that branch.

Using
-----

This is designed for use with the Zig 0.11 package manager, and exposes a module
called "aws". Set up `build.zig.zon` and add the dependency/module to your project
as normal and the package manager should do its thing.

Running the demo
----------------

This library mimics the aws c libraries for it's work, so it operates like most
other 'AWS things'. main.zig gives you a handful of examples for working with services.
For local testing or alternative endpoints, there's no real standard, so
there is code to look for `AWS_ENDPOINT_URL` environment variable that will
supersede all other configuration. Note that an alternative endpoint may
require passing in a client option to specify an different TLS root certificate
(pass null to disable certificate verification).

An [old branch based on aws-crt](https://github.com/elerch/aws-sdk-for-zig/tree/aws-crt) exists
for posterity, and supports x86_64 linux. The old branch is deprecated, so if
there are issues you see that work correctly in the aws-crt branch, please
file an issue.

Limitations
-----------

The zig 0.11 HTTP client supports TLS 1.3 only. This, IMHO, is a reasonable
restriction given its introduction 5 years ago, but is inflicting some short
term pain on this project as AWS has not yet fully implemented the protocol. AWS has
committed to [TLS 1.3 support across all services by the end of 2023](https://aws.amazon.com/blogs/security/faster-aws-cloud-connections-with-tls-1-3/), but many (most) services as of August 28th have not yet
been upgraded. Proxy support has been added, so to get to the services that
do not yet support TLS 1.3, you can use something like [mitmproxy](https://mitmproxy.org/)
to proxy those requests. Of course, this is not a good production solution...

WebIdentityToken is not yet implemented.

TODO List:

* Json parsing is based on a fork of the 0.9.0 (maybe earlier?) json parser.
  This needs a re-visit. Note also that a json.zig file is embedded/copied
  from the codegen project, so that also needs a second look.
* Take a look to see about compilation speed. With codegen caching this is
  reasonable, but still takes longer than needed.
* Upgrade the model files. This is a simple tasks, but I'd like the first
  item on this list to be completed first.
* Implement sigv4a signing
* Implement jitter/exponential backoff
* Implement timeouts and other TODO's in the code
* Add option to cache signature keys

Compiler wishlist/watchlist:

* [comptime allocations](https://github.com/ziglang/zig/issues/1291) so we can read files, etc (or is there another way)

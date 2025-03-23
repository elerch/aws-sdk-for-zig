AWS SDK for Zig
===============

[Zig 0.14](https://ziglang.org/download/#release-0.14.0):

[![Build Status: Zig 0.14.0](https://git.lerch.org/lobo/aws-sdk-for-zig/actions/workflows/build.yaml/badge.svg)](https://git.lerch.org/lobo/aws-sdk-for-zig/actions?workflow=build.yaml&state=closed)

[Last Mach Nominated Zig Version](https://machengine.org/docs/nominated-zig/):

[![Build Status: Mach nominated](https://git.lerch.org/lobo/aws-sdk-for-zig/actions/workflows/zig-mach.yaml/badge.svg)](https://git.lerch.org/lobo/aws-sdk-for-zig/actions?workflow=zig-mach.yaml&state=closed)

[Nightly Zig](https://ziglang.org/download/):

[![Build Status: Zig Nightly](https://git.lerch.org/lobo/aws-sdk-for-zig/actions/workflows/zig-nightly.yaml/badge.svg)](https://git.lerch.org/lobo/aws-sdk-for-zig/actions?workflow=zig-nightly.yaml&state=closed)

[Zig 0.13](https://ziglang.org/download/#release-0.13.0):

[![Build Status: Zig 0.13.0](https://git.lerch.org/lobo/aws-sdk-for-zig/actions/workflows/zig-previous.yaml/badge.svg)](https://git.lerch.org/lobo/aws-sdk-for-zig/actions?workflow=zig-previous.yaml&state=closed)


Current executable size for the demo is 980k after compiling with -Doptimize=ReleaseSmall
in x86_64-linux, and will vary based on services used. Tested targets:

* x86_64-linux
* riscv64-linux
* aarch64-linux
* x86_64-windows
* arm-linux
* aarch64-macos
* x86_64-macos

Tested targets are built, but not continuously tested, by CI.

Branches
--------

* **master**:      This branch tracks the latest released zig version
* **zig-0.13**:    This branch tracks the previous released zig version (0.13 currently).
                   Support for the previous version is best effort, generally
                   degrading over time. Fixes will generally appear in master, then
                   backported into the previous version.
* **zig-mach**:    This branch tracks the latest mach nominated version. A separate
                   branch is necessary as mach nominated is usually, but not always,
                   more recent than the latest production zig. Support for the mach
                   version is best effort.
* **zig-develop**: This branch tracks zig nightly, and is used mainly as a canary
                   for breaking changes that will need to be dealt with when
                   a new mach nominated version or new zig release appear.
                   Expect significant delays in any build failures.

Other branches/tags exist but are unsupported

Building
--------

`zig build` should work. It will build the code generation project, fetch model
files from upstream AWS Go SDK v2, run the code generation, then build the main
project with the generated code. Testing can be done with `zig build test`. Note that
this command tests on all supported architectures, so for a faster testing
process, use `zig build smoke-test` instead.

To make development even faster, a build option is provided to avoid the use of
LLVM. To use this, use the command `zig build -Dno-llvm smoke-test`. This
can reduce build/test time 300%. Note, however, native code generation in zig
is not yet complete, so you may see errors.

Using
-----

This is designed for use with the Zig package manager, and exposes a module
called "aws". Set up `build.zig.zon` and add the dependency/module to your project
as normal and the package manager should do its thing. A full example can be found
in [/example](example/build.zig.zon). This can also be used at build time in
a downstream project's `build.zig`.

Configuring the module and/or Running the demo
----------------------------------------------

This library mimics the aws c libraries for it's work, so it operates like most
other 'AWS things'. [/src/main.zig](src/main.zig) gives you a handful of examples
for working with services. For local testing or alternative endpoints, there's
no real standard, so there is code to look for an environment variable
`AWS_ENDPOINT_URL` variable that will supersede all other configuration.

Limitations
-----------

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

Dependency tree
---------------

No dependencies:
  * aws_authentication: base structure for credentials (only one type)
  * aws_http_base: contains basic structures for http requests/results
  * case: provides functions to change casing
  * date: provides limited date manipulation functions
  * json: custom version of earlier stdlib json parser
  * xml: custom xml parser library
  * url: custom url encoding

aws_credentials: Allows credential handling
  aws_authentication

aws_http:
  aws_http_base
  aws_signing

aws_signing: handles signing of http requests
  aws_http_base
  aws_authentication
  date

aws: main usage point for libraries
  aws_http
  json
  url
  case
  date
  servicemodel
  xml_shaper
  aws_credentials
  aws_authentication

main: main entrypoint for demo executable
  aws

servicemodel: Provides access to all aws service generated models
  all generated model files

xml_shaper: Manages interface from xml to in memory structures
  xml
  date

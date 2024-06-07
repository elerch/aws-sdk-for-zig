AWS SDK for Zig
===============

[Zig 0.13](https://ziglang.org/download/#release-0.13.0):

[![Build Status: Zig 0.13.0](https://git.lerch.org/lobo/aws-sdk-for-zig/actions/workflows/build.yaml/badge.svg)](https://git.lerch.org/lobo/aws-sdk-for-zig/actions?workflow=build.yaml&state=closed)

[Last Mach Nominated Zig Version](https://machengine.org/about/nominated-zig/):

[![Build Status: Mach nominated](https://git.lerch.org/lobo/aws-sdk-for-zig/actions/workflows/zig-mach.yaml/badge.svg?branch=zig-develop)](https://git.lerch.org/lobo/aws-sdk-for-zig/actions?workflow=zig-mach.yaml&state=closed)

[Nightly Zig](https://ziglang.org/download/):

[![Build Status: Zig Nightly](https://git.lerch.org/lobo/aws-sdk-for-zig/actions/workflows/zig-nightly.yaml/badge.svg?branch=zig-develop)](https://git.lerch.org/lobo/aws-sdk-for-zig/actions?workflow=zig-nightly.yaml&state=closed)

Current executable size for the demo is 980k after compiling with -Doptimize=ReleaseSmall
in x86_linux, and will vary based on services used. Tested targets:

* x86_64-linux
* riscv64-linux\*
* aarch64-linux
* x86_64-windows
* arm-linux
* aarch64-macos
* x86_64-macos

Tested targets are built, but not continuously tested, by CI.

\* On Zig 0.12/0.13, riscv64-linux disabled due to [LLLM's O(N^2) codegen](https://github.com/ziglang/zig/issues/18872)


Zig-Develop Branch
------------------

This branch is intended for use with the in-development version of Zig. This
starts with 0.12.0-dev.3180+83e578a18. This is aligned with [Mach Engine's Nominated
Zig Versions](https://machengine.org/about/nominated-zig/). Nightly zig versions
are difficult to keep up with and there is no special effort made there, build
status is FYI (and used as a canary for nominated zig versions).

Building
--------

`zig build` should work. It will build the code generation project, fetch model
files from upstream AWS Go SDK v2, run the code generation, then build the main
project with the generated code. Testing can be done with `zig test`.


Using
-----

This is designed for use with the Zig package manager, and exposes a module
called "aws". Set up `build.zig.zon` and add the dependency/module to your project
as normal and the package manager should do its thing. A full example can be found
in [/example](example/README.md).

Configuring the module and/or Running the demo
----------------------------------------------

This library mimics the aws c libraries for it's work, so it operates like most
other 'AWS things'. [/src/main.zig](src/main.zig) gives you a handful of examples
for working with services. For local testing or alternative endpoints, there's
no real standard, so there is code to look for `AWS_ENDPOINT_URL` environment
variable that will supersede all other configuration.

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

Services without TLS 1.3 support
--------------------------------

All AWS services should support TLS 1.3 at this point, but there are many regions
and several partitions, and not all of them have been tested, so your mileage
may vary. If something doesn't work, please submit an issue to let others know.

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

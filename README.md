AWS SDK for Zig
===============

[Last Mach Nominated Zig Version](https://machengine.org/about/nominated-zig/):

[![Build Status: Zig 0.12.0-dev.3180+83e578a18](https://actions-status.lerch.org/lobo/aws-sdk-for-zig/zig-mach)](https://git.lerch.org/lobo/aws-sdk-for-zig/actions?workflow=zig-mach.yaml&state=closed)

[Nightly Zig](https://ziglang.org/download/):

[![Build Status: Zig Nightly](https://actions-status.lerch.org/lobo/aws-sdk-for-zig/zig-nightly)](https://git.lerch.org/lobo/aws-sdk-for-zig/actions?workflow=zig-nightly.yaml&state=closed)

**NOTE: TLS 1.3 support is still deploying across AWS. Some services, especially S3,
        may or may not be available without a proxy, depending on the region.
        See limitations section below**

Current executable size for the demo is 980k after compiling with -Doptimize=ReleaseSmall
in x86_linux, and will vary based on services used. Tested targets:

* x86_64-linux
* riscv64-linux\*
* aarch64-linux
* x86_64-windows\*\*
* arm-linux
* aarch64-macos
* x86_64-macos

Tested targets are built, but not continuously tested, by CI.

\* On Zig 0.12, riscv64-linux tests get stuck forever in "LLVM Emit object"

\*\* On Zig 0.12, x86_64-windows tests have one test skipped as LLVM consumes all available RAM on the system


Zig-Develop Branch
------------------

This branch is intended for use with the in-development version of Zig. This
starts with 0.12.0-dev.3180+83e578a18. I will try to keep this branch up to date
with latest, but with a special eye towards aligning with [Mach Engine's Nominated
Zig Versions](https://machengine.org/about/nominated-zig/). As nightly zig versions
disappear off the downloads page (and back end server), we can use the mirroring
that the Mach Engine participates in to pull these versions.

Building
--------

`zig build` should work. It will build the code generation project, fetch model
files from upstream AWS Go SDK v2, run the code generation, then build the main
project with the generated code. Testing can be done with `zig test`.


Using
-----

This is designed for use with the Zig 0.11 package manager, and exposes a module
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

The zig 0.11 HTTP client supports TLS 1.3 only. AWS has committed to
[TLS 1.3 support across all services by the end of 2023](https://aws.amazon.com/blogs/security/faster-aws-cloud-connections-with-tls-1-3/),
but a few services as of April 1, 2024 have not been upgraded, and S3 is
a bit intermittent. Proxy support has been added, so to get to the services that
do not yet support TLS 1.3, you can use something like [mitmproxy](https://mitmproxy.org/)
to proxy those requests until roll out is complete.

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

Services without TLS 1.3 support (4 services out of 255 total)
---------------------------------------------------------------

The following service list is based on limited testing against us-west-2
region. Your mileage may vary, as there are thousands of endpoints against
many regions. It appears the TLS 1.3 rollout is fairly far along at
this point.

NOTE ON S3: For me, S3 is currently intermittently available using TLS 1.3, so
it appears deployments are in progress. The last couple days it has been
not been available consistently, so I have added it back to the list.

```
data.iot
models.lex
opsworks
s3
```

Dependency tree
---------------

No dependencies:
  * aws_authentication: base structure for credentials (only one type)
  * aws_http_base: contains basic structures for http requests/results
  * case: provides functions to change casing
  * date: provides limited date manipulation functions
  * http_client_17015_issue: zig 0.11 http client, with changes
  * json: custom version of earlier stdlib json parser
  * xml: custom xml parser library
  * url: custom url encoding

aws_credentials: Allows credential handling
  aws_authentication

aws_http:
  http_client_17015_issue
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

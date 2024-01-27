AWS SDK for Zig
===============

[![Build Status](https://actions-status.lerch.org/lobo/aws-sdk-for-zig/build)](https://git.lerch.org/lobo/aws-sdk-for-zig/actions?workflow=build.yaml&state=closed)

**NOTE: THIS SDK IS CURRENTLY UNUSABLE FOR SEVERAL IMPORTANT AWS SERVICES
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

Other branches
--------------

The default branch is fully functional but requires TLS 1.3. Until AWS Services
support TLS 1.3 at the end of 2023, the [0.9.0 branch](https://git.lerch.org/lobo/aws-sdk-for-zig/src/branch/0.9.0)
may be of use. More details below in limitations. This branch overall is
superior, as is the 0.11 compiler, but if you need a service that doesn't support
TLS 1.3 and you need it right away, feel free to use that branch. Note I do not
intend to update code in the 0.9.0 branch, but will accept PRs.

An [old branch based on aws-crt](https://github.com/elerch/aws-sdk-for-zig/tree/aws-crt) exists
for posterity, and supports x86_64 linux. The old branch is deprecated, so if
there are issues you see that work correctly in the aws-crt branch, please
file an issue. I can't think of a reason to use this branch any more. I do not
intend to entertain PRs on this branch, but reach out if you think it is important.

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

Services without TLS 1.3 support (37 services out of 255 total)
---------------------------------------------------------------

NOTE THAT EC2, S3, Lambda, DynamoDB, SNS, SQS are all part of this list!!

```
cloudsearch
codecommit
codestar
cognito-identity
cognito-idp
cognito-sync
data.iot
data.jobs.iot
dax
discovery
dynamodb
ec2
elasticache
elasticbeanstalk
elasticloadbalancing
featurestore-runtime.sagemaker
ingest.timestream
iotsitewise
kinesis
kinesisvideo
lambda
models.lex
monitoring
oidc
opsworks
personalize-runtime
query.timestream
runtime.lex
runtime.sagemaker
runtime-v2-lex
s3
sns
sqs
streams.dynamodb
sts
support
wafv2
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

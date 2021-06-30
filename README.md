# AWS SDK for Zig

Ok, so it's not actually an SDK (yet). Right now the SDK should support
any "query-based" operation and probably EC2, though this isn't tested yet.
Total service count should be around 18 services supported. If you use an
unsupported service, you'll get a compile error.

This is my first serious zig effort, so please issue a PR if the code isn't
"ziggy" or if there's a better way.

This is designed to be built statically using the `aws_c_*` libraries, so
we inherit a lot of the goodness of the work going on there. Current
executable size is 10.3M, about half of which is due to the SSL library.
This is for x86_linux (which is all that's tested at the moment).

## Building

I am assuming here that if you're playing with zig, you pretty much know
what you're doing, so I will stay brief.

First, the dependencies are required. Use the Dockerfile to build these.
a `docker build` will do, but be prepared for it to run a while. Openssl in
particular will take a while, but without any particular knowledge
I'm also hoping/expecting AWS to factor out that library sometime in
the future.

Once that's done, you'll have an alpine image with all dependencies ready
to go and zig master installed. There are some build-related things still
broken in 0.8.0 and hopefully 0.8.1 will address those and we can be on
a standard release.

* `zig build` should work. It will build the code generation project, run
  the code generation, then build the main project with the generated code.
* Install make and use the included Makefile. Going this path should be fine
  with zig 0.8.0 release, but code generation has not been added to the
  Makefile yet (ever?), so you'll be on your own for that.

## Running

This library uses the aws c libraries for it's work, so it operates like most
other 'AWS things'. Note that I tested by setting the appropriate environment
variables, so config files haven't gotten a run through.
main.zig gives you a program to call sts GetCallerIdentity.
For local testing or alternative endpoints, there's no real standard, so
there is code to look for `AWS_ENDPOINT_URL` environment variable that will
supercede all other configuration.

## Dependencies


Full dependency tree:
aws-c-auth
   * s2n
      * aws-lc
   * aws-c-common
   * aws-c-compression
     * aws-c-common
   * aws-c-http
     * s2n
     * aws-c-common
     * aws-c-io
       * aws-c-common
       * s2n
         * aws-lc
       * aws-c-cal
         * aws-c-common
         * aws-lc
     * aws-c-compression
       * aws-c-common
   * aws-c-cal
     * aws-c-common
     * aws-lc

Build order based on above:

1. aws-c-common
1. aws-lc
2. s2n
2. aws-c-cal
2. aws-c-compression
3. aws-c-io
4. aws-c-http
5. aws-c-auth

Dockerfile in this repo will manage this

TODO List:

* Implement jitter/exponential backoff. This appears to be configuration of `aws_c_io` and should therefore be trivial
* Implement timeouts and other TODO's in the code
* Implement error handling for 4xx, 5xx and other unexpected return values
* ✓ Implement generic response body -> Response type handling (right now, this is hard-coded)
* ✓ Implement codegen for services with xml structures (using Smithy models)
* ✓ Implement codegen for others (using Smithy models)
* Switch to aws-c-cal upstream once [PR for full static musl build support is merged](https://github.com/awslabs/aws-c-cal/pull/89) (see Dockerfile)
* Move to compiler on tagged release (hopefully 0.8.1)
(new 2021-05-29. I will proceed in this order unless I get other requests)
* ✓ Implement [AWS query protocol](https://awslabs.github.io/smithy/1.0/spec/aws/aws-query-protocol.html). This is the protocol in use by sts.getcalleridentity. Total service count 18
* Implement [AWS Json 1.0 protocol](https://awslabs.github.io/smithy/1.0/spec/aws/aws-json-1_0-protocol.html). Includes dynamodb. Total service count 18
* Implement [AWS Json 1.1 protocol](https://awslabs.github.io/smithy/1.0/spec/aws/aws-json-1_1-protocol.html). Includes ecs. Total service count 105
* Implement [AWS restXml protocol](https://awslabs.github.io/smithy/1.0/spec/aws/aws-restxml-protocol.html). Includes S3. Total service count 4.
* ✓ Implement [AWS EC2 query protocol](https://awslabs.github.io/smithy/1.0/spec/aws/aws-ec2-query-protocol.html). Includes EC2. Total service count 1.

Compiler wishlist/watchlist:

* ~~[Allow declarations for comptime type generation](https://github.com/ziglang/zig/issues/6709)~~

This is no longer as important. The primary issue was in the return value, but
due to the way AWS responses are provided, we are able to statically declare a
type and thus allow our types to be generated.

* [Merge PR to allow stripping -static](https://github.com/ziglang/zig/pull/8248)
* [comptime allocations](https://github.com/ziglang/zig/issues/1291) so we can read files, etc (or is there another way)

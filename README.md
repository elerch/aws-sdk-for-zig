# AWS SDK for Zig

Ok, so it's not actually an SDK (yet). Right now this is SDK supports sts
get-caller-identity action only. Why? Because it's one of the easiest to
support, so I started there. From here, the next major step is to codegen
the types necessary to support the various services. Currently this code is
dynamically generating the sts types so we are somewhat codegen ready, but
current comptime limitations might trip us up. The advantage of comptime is
that only types actually used would be generated vs the whole surface area
of AWS. That said, with most of the heavy lifting now coded, the addition
of the request/response types, even if all of them are added, should not
balloon the size beyond "reasonable". Of course this still needs to be be seen.

This is my first serious zig effort, so please issue a PR if the code isn't
"ziggy" or if there's a better way.

This is designed to be built statically using the `aws_c_*` libraries, so
we inherit a lot of the goodness of the work going on there. Implementing
get-caller-identity with all dependencies statically linked gives us a stripped
executable size of 5.3M for x86_linux (which is all that's tested at the moment).

## Building

I am assuming here that if you're playing with zig, you pretty much know
what you're doing, so I will stay brief.

First, the dependencies are required. Use the Dockerfile to build these.
a `docker build` will do, but be prepared for it to run a while. Openssl in
particular will take a while, but without any particular knowledge
I'm also hoping/expecting AWS to factor out that library sometime in
the future.

Once that's done, you'll have an alpine image with all dependencies ready
to go and zig 0.7.1 installed. The build.zig currently relies on
[this PR to allow stripping -static](https://github.com/ziglang/zig/pull/8248),
so either:

* Modify build.zig, then strip (or not) after the fact
* Install make and use the included Makefile

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
* Implement generic response body -> Response type handling (right now, this is hard-coded)
* Implement codegen for services with xml structures (using Smithy models)
* Implement codegen for others (using Smithy models)
* Switch to aws-c-cal upsream once PR for full static musl build support is merged (see Dockerfile)
* Remove compiler 0.7.1 shims when 0.8.0 is released

Compiler wishlist/watchlist:

* Fix the weirdness we see with comptime type generation (see aws.zig around line 135)
* ~~[Allow declarations for comptime type generation](https://github.com/ziglang/zig/issues/6709)~~

This is no longer as important. The primary issue was in the return value, but
due to the way AWS responses are provided, we are able to statically declare a
type and thus allow our types to be generated.

* [Merge PR to allow stripping -static](https://github.com/ziglang/zig/pull/8248)
* [comptime allocations](https://github.com/ziglang/zig/issues/1291) so we can read files, etc (or is there another way)

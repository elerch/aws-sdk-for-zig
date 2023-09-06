Example usage of aws-zig module by a client application
=======================================================

This directory has a fully functional command line application that utilizes
the aws-zig module using the Zig package manager introduced in Zig 0.11.

A couple things of note:

* Rather than the typical "we will use the source code repository archive",
  you will notice in build.zig.zon that the dependency URL is a Gitea actions
  artifact. This is due to the fact that the aws service models are generated,
  and the package manager does not currently (I think) have a way to perform
  compile steps when pulling in a package and using a module. In any case, this
  seems like a reasonable restriction. The aws-zig SDK repository will build
  and test each code change, along with model generation, then capture the
  generated files along with the actual SDK source code and upload the resulting
  artifact for use. To find the correct artifact, look at the [actions page](https://git.lerch.org/lobo/aws-sdk-for-zig/actions)
  and choose a run ([example](https://git.lerch.org/lobo/aws-sdk-for-zig/actions/runs/57)).
  Under Artifacts, you will see the tarball and can paste that link into `build.zig.zon`.
* The action naming is incorrect according to the zig naming guidelines. This
  will be fixed in the code generation process shortly, and this example will be
  updated accordingly.
* Many (most) AWS services still don't support TLS 1.3. I recommend using
  [mitmproxy](https://mitmproxy.org) during development. Otherwise, it is
  likely best to wait until service(s) important to you are supported on
  TLS 1.3.

Usage
-----

After configuring your AWS credentials using the standard tools, a simple
`zig build run` should be sufficient to run this example.

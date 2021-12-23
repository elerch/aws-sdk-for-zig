# We are looking for a static build, so we need to be on a musl system
# Zig uses clang, so for best compatibility, everything should be built
# using that compiler


# Establish a base container with build tools common to most projects
FROM alpine:3.13 AS base
# gcc gets us libgcc.a, even though the build should be using clang
RUN apk add --no-cache clang git cmake make lld musl-dev gcc && \
    rm /usr/bin/ld && \
    ln -s /usr/bin/ld.lld /usr/bin/ld && rm /usr/bin/gcc # just to be sure

FROM base AS common
RUN git clone --depth 1 -b v0.5.2 https://github.com/awslabs/aws-c-common && \
    mkdir aws-c-common-build && cd aws-c-common-build && \
    cmake ../aws-c-common && \
    make -j12 && make test && make install

RUN tar -czf aws-c-common-clang.tgz /usr/local/*

# The only tags currently on the repo are from 9/2020 and don't install
# anything, so we'll use current head of main branch (d60b60e)
FROM base AS awslc
RUN apk add --no-cache perl go g++ linux-headers && rm /usr/bin/g++ && rm /usr/bin/c++ && \
    git clone --depth 1000 https://github.com/awslabs/aws-lc && cd aws-lc && \
    git reset d60b60e --hard && cd .. && \
    cmake -S aws-lc -B aws-lc/build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_PREFIX_PATH=/usr/local -DCMAKE_INSTALL_PREFIX=/usr/local && \
    cmake --build aws-lc/build --config RelWithDebInfo --target install

RUN tar -czf aws-lc-clang.tgz /usr/local/*

FROM base AS s2n
ENV S2N_LIBCRYPTO=awslc
COPY --from=awslc /aws-lc-clang.tgz /
RUN git clone --depth 1 -b v1.0.5 https://github.com/aws/s2n-tls && \
    tar -xzf aws-lc-clang.tgz && \
    mkdir s2n-build && cd s2n-build && \
    cmake ../s2n-tls && \
    make -j12 && make install

RUN tar -czf s2n-clang.tgz /usr/local/*

FROM base AS cal
COPY --from=awslc /aws-lc-clang.tgz /
COPY --from=common /aws-c-common-clang.tgz /
# RUN git clone --depth 1 -b v0.5.5 https://github.com/awslabs/aws-c-cal && \
RUN git clone --depth 1 -b static-musl-builds https://github.com/elerch/aws-c-cal && \
    tar -xzf aws-c-common-clang.tgz && \
    tar -xzf aws-lc-clang.tgz && \
    mkdir cal-build && cd cal-build && \
    cmake -DCMAKE_MODULE_PATH=/usr/local/lib64/cmake ../aws-c-cal && \
    make -j12 && make install
# No make test:
#  40 - ecdsa_p384_test_key_gen_export (Failed)
RUN tar -czf aws-c-cal-clang.tgz /usr/local/*

FROM base AS compression
COPY --from=common /aws-c-common-clang.tgz /
RUN git clone --depth 1 -b v0.2.10 https://github.com/awslabs/aws-c-compression && \
    tar -xzf aws-c-common-clang.tgz && \
    mkdir compression-build && cd compression-build && \
    cmake -DCMAKE_MODULE_PATH=/usr/local/lib64/cmake ../aws-c-compression && \
    make -j12 && make test && make install

RUN tar -czf aws-c-compression-clang.tgz /usr/local/*

FROM base AS io
# Cal includes common and openssl
COPY --from=cal /aws-c-cal-clang.tgz /
COPY --from=s2n /s2n-clang.tgz /
RUN git clone --depth 1 -b v0.9.1 https://github.com/awslabs/aws-c-io && \
    tar -xzf s2n-clang.tgz && \
    tar -xzf aws-c-cal-clang.tgz && \
    mkdir io-build && cd io-build && \
    cmake -DCMAKE_MODULE_PATH=/usr/local/lib64/cmake ../aws-c-io && \
    make -j12 && make install

RUN tar -czf aws-c-io-clang.tgz /usr/local/*

FROM base AS http
# Cal includes common and openssl
# 2 test failures on musl - both "download medium file"
COPY --from=io /aws-c-io-clang.tgz /
COPY --from=compression /aws-c-compression-clang.tgz /
# RUN git clone --depth 1 -b v0.5.19 https://github.com/awslabs/aws-c-http && \
RUN git clone --depth 1 -b v0.6.1 https://github.com/awslabs/aws-c-http && \
    tar -xzf aws-c-io-clang.tgz && \
    tar -xzf aws-c-compression-clang.tgz && \
    mkdir http-build && cd http-build && \
    cmake -DCMAKE_MODULE_PATH=/usr/local/lib64/cmake ../aws-c-http && \
    make -j12 && make install

RUN tar -czf aws-c-http-clang.tgz /usr/local/*

FROM base AS auth
# http should have all other dependencies
COPY --from=http /aws-c-http-clang.tgz /
RUN git clone --depth 1 -b v0.5.0 https://github.com/awslabs/aws-c-auth && \
    tar -xzf aws-c-http-clang.tgz && \
    mkdir auth-build && cd auth-build && \
    cmake -DCMAKE_MODULE_PATH=/usr/local/lib64/cmake ../aws-c-auth && \
    make -j12 && make install # chunked_signing_test fails

RUN tar -czf aws-c-auth-clang.tgz /usr/local/*

FROM alpine:3.13 as final
COPY --from=auth /aws-c-auth-clang.tgz /
ADD https://ziglang.org/download/0.9.0/zig-linux-x86_64-0.9.0.tar.xz /
RUN tar -xzf /aws-c-auth-clang.tgz && mkdir /src && tar -C /usr/local -xf zig-linux* && \
    ln -s /usr/local/zig-linux*/zig /usr/local/bin/zig

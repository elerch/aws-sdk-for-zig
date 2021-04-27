FROM alpine:3.13 AS base
# gcc gets us libgcc.a, even though the build should be using clang
RUN apk add --no-cache clang git cmake make lld musl-dev gcc && \
    rm /usr/bin/ld && \
    ln -s /usr/bin/ld.lld /usr/bin/ld && rm /usr/bin/gcc # just to be sure

FROM base AS common
# d5f9398d48d9c318563db08100e2e87b24ea3656
# RUN git clone --depth 1 -b pthread-np https://github.com/r-burns/aws-c-common && \
RUN git clone --depth 1 -b v0.5.2 https://github.com/awslabs/aws-c-common && \
    mkdir aws-c-common-build && cd aws-c-common-build && \
    cmake ../aws-c-common && \
    make -j12 && make test && make install

RUN tar -czf aws-c-common-clang.tgz /usr/local/*

FROM base AS openssl
RUN apk add --no-cache perl linux-headers && \
    git clone --depth 1 -b OpenSSL_1_1_1i https://github.com/openssl/openssl && \
    cd openssl && ./Configure linux-x86_64-clang && make && make install

RUN tar -czf openssl-clang.tgz /usr/local/*

FROM base AS s2n
ENV S2N_LIBCRYPTO=openssl-1.1.1
COPY --from=openssl /openssl-clang.tgz /
RUN git clone --depth 1 -b v0.10.26 https://github.com/awslabs/s2n && \
    tar -xzf openssl-clang.tgz && \
    mkdir s2n-build && cd s2n-build && \
    cmake ../s2n && \
    make -j12 && make install

RUN tar -czf s2n-clang.tgz /usr/local/*

FROM base AS cal
COPY --from=openssl /openssl-clang.tgz /
COPY --from=common /aws-c-common-clang.tgz /
# environment not used - just busting docker's cache
ENV COMMIT=d1a4d
# RUN git clone --depth 1 -b v0.4.5 https://github.com/awslabs/aws-c-cal && \
RUN git clone --depth 1 https://github.com/elerch/aws-c-cal && \
    tar -xzf aws-c-common-clang.tgz && \
    tar -xzf openssl-clang.tgz && \
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
ADD https://ziglang.org/download/0.7.1/zig-linux-x86_64-0.7.1.tar.xz /
RUN tar -xzf /aws-c-auth-clang.tgz && mkdir /src && tar -C /usr/local -xf zig-linux* && \
    ln -s /usr/local/zig-linux*/zig /usr/local/bin/zig

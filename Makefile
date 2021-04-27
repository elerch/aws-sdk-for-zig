start-hand-test: src/main.zig src/aws.zig src/xml.zig
	@zig build-exe -static -I/usr/local/include -Isrc/ -lc --strip \
		--name start-hand-test src/main.zig src/bitfield-workaround.c \
		/usr/local/lib64/libaws-c-*.a \
		/usr/local/lib64/libs2n.a \
		/usr/local/lib/libcrypto.a \
		/usr/local/lib/libssl.a

elasticurl: curl.c
	@zig build-exe -static -I/usr/local/include -Isrc/ -lc --strip \
		--name elasticurl curl.c \
		/usr/local/lib64/libaws-c-*.a \
		/usr/local/lib64/libs2n.a \
		/usr/local/lib/libcrypto.a \
		/usr/local/lib/libssl.a

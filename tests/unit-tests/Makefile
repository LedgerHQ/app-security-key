CC ?= cc
RM ?= rm -f

CFLAGS ?= -O2 -Wall -Wextra -Wformat=2 -Wp,-MT,$@ -Wp,-MD,$(dir $@).$(notdir $@).d -fstack-protector
CFLAGS += -DPRINTF=printf
CFLAGS += -DUNIT_TESTS
CFLAGS += -I. -I../../include -I../../cbor-src

LDFLAGS ?= -Wl,-O1,-as-needed,-no-undefined,-z,relro,-z,now,--fatal-warnings -fstack-protector

# Use Address Sanitizer (ASAN) and Undefined Behavior Sanitizer (UBSAN)
# Require privileges when using a container. For example with Podman:
# podman run --cap-add=SYS_PTRACE --rm -ti -v "$(pwd):/app" ledgerhq/ledger-app-builder:1.6.0 make test
CFLAGS += -fsanitize=address,undefined
LDFLAGS += -fsanitize=address,undefined

PROGRAMS := test_cbip_decode test_cbip_encode fuzz_cbip_decode fuzz_cbip_helper

test: $(PROGRAMS)
	./test_cbip_encode
	for CBOR in cbor/*.cbor ; do ./test_cbip_decode "$$CBOR" > /dev/null || exit $$? ; done
	./fuzz_cbip_decode cbor/*.cbor
	./fuzz_cbip_helper cbor/*.cbor

clean:
	$(RM) $(PROGRAMS) ./*.o .*.d

test_cbip_decode: test_cbip_decode.o cbip_decode.o
	$(CC) $(LDFLAGS) -o $@ $^

test_cbip_encode: test_cbip_encode.o cbip_encode.o
	$(CC) $(LDFLAGS) -o $@ $^

fuzz_cbip_decode: fuzz_cbip_decode.cpp ../../cbor-src/cbip_decode.c
	clang -g -O1 -fsanitize=fuzzer,address $(CFLAGS) -UPRINTF -DPRINTF= -Wno-unused-value -o $@ fuzz_cbip_decode.cpp ../../cbor-src/cbip_decode.c

fuzz_cbip_helper: fuzz_cbip_helper.cpp ../../src/cbip_helper.c ../../cbor-src/cbip_decode.c
	clang -g -O1 -fsanitize=fuzzer,address $(CFLAGS) -UPRINTF -DPRINTF= -DHAVE_CBOR_DEBUG -DFUZZ -Wno-unused-value -o $@ fuzz_cbip_helper.cpp ../../src/cbip_helper.c ../../cbor-src/cbip_decode.c

cbip_decode.o: ../../cbor-src/cbip_decode.c
	$(CC) $(CFLAGS) -c -o $@ $<

cbip_encode.o: ../../cbor-src/cbip_encode.c
	$(CC) $(CFLAGS) -c -o $@ $<

test_cbip_decode.o: test_cbip_decode.c
	$(CC) $(CFLAGS) -c -o $@ $<

test_cbip_encode.o: test_cbip_encode.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: test clean

-include .*.d

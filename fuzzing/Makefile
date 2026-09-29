RM ?= rm -f

CFLAGS := -g -O1 -Wall -Wextra -Wformat=2 -fsanitize=fuzzer,address,undefined
CFLAGS += -DPRINTF= -DUNIT_TESTS -Wno-unused-value
# Undefined behavior must fail the corpus replay, not only print a warning.
CFLAGS += -fno-sanitize-recover=undefined
CFLAGS += -I../unit-tests -I../include -I../cbor-src -I../src -I../src/ctap2/

CORPUS := ../unit-tests/cbor/*.cbor

PROGRAMS := fuzz_cbip_decode fuzz_cbip_helper

# Replays the corpus once; run a binary without arguments for a real fuzzing session.
test: $(PROGRAMS)
	./fuzz_cbip_decode $(CORPUS)
	./fuzz_cbip_helper $(CORPUS)

clean:
	$(RM) $(PROGRAMS)

fuzz_cbip_decode: fuzz_cbip_decode.cpp ../cbor-src/cbip_decode.c
	clang $(CFLAGS) -o $@ $^

fuzz_cbip_helper: fuzz_cbip_helper.cpp ../src/cbip_helper.c ../cbor-src/cbip_decode.c
	clang $(CFLAGS) -DHAVE_CBOR_DEBUG -DFUZZ -o $@ $^

.PHONY: test clean

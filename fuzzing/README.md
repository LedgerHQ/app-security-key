# Fuzzers

libFuzzer targets for the CBOR parser (`cbor-src/cbip_decode.c`) and the CBOR helpers
(`src/cbip_helper.c`). They need `clang` with its compiler-rt runtimes.

Replay the corpus (`../unit-tests/cbor/`) once, as the CI does:

```
make -C fuzzing
```

Run a real fuzzing session:

```
./fuzzing/fuzz_cbip_decode unit-tests/cbor/
```

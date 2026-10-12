# Unit tests

The unit tests use the SDK's `LedgerUT` framework (Unity + CMock, see
`cmake/USAGE.md` in the SDK). They build and run on the host, with no device and no
Speculos.

## Requirements

- CMake >= 3.28, a host C compiler (GCC for coverage), Ruby (CMock's mock generator)
- `lcov` / `genhtml` for the coverage report
- `BOLOS_SDK` pointing at a Ledger Secure SDK checkout that ships `cmake/LedgerUT.cmake`

The `ledger-app-dev-tools` image has all of them.

## Launch the tests

From the repository root:

```
cd unit-tests
cmake -B build -S .
cmake --build build
ctest --test-dir build --output-on-failure
```

Coverage report (`build/coverage/index.html`):

```
cmake --build build --target generate_coverage
```

## Layout

- `test_<name>.c`: one Unity suite per file, declared in `CMakeLists.txt` with
  `ledger_unit_tests_add_test()`.
- `cbor/`: CBOR samples decoded by `test_cbip_decode`, and the expected output of
  `test_cbip_encode`. The fuzzers in `../fuzzing` use them as their corpus.
- `fakes/`: stand-ins for headers the app build generates, such as `glyphs.h`.
- `unit_test.h`: definitions the CBOR code needs when built without the SDK
  (`UNIT_TESTS`).
- `wipe_check.h`: records the `explicit_bzero()` calls of the source under test, so a
  test can check that a stack buffer it only saw through a mock was wiped.

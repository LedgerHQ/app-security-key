# Tests

## Functional test

A list of demo websites that can be used for testing can be found [here](https://github.com/herrjemand/awesome-webauthn#demos).
A great one is https://webauthn.me/. And especially its [debugger](https://webauthn.me/debugger) mode.


## Speculos functional test

Some functional tests are located in `tests/speculos/` directory.
They are using the Python client of [Speculos](https://github.com/LedgerHQ/speculos) to run the tests directly on the Speculos emulator.

See dedicated `README.md` in `tests/speculos` directory for how to launch them.


## Unit test

Some unit tests are located in `tests/unit-tests/` directory.
See dedicated `README.md` in `tests/unit-tests` directory for how to launch them.


## Solokeys FIDO2 tests

The application can be tested against [Solokeys FIDO2 tests](https://github.com/solokeys/fido2-tests) using Speculos.

To do so, first run the app in Speculos with usb transport setting set to `--usb U2F`.
For example:
```sh
# From repository root, cloning speculos project in the repository
git clone https://github.com/LedgerHQ/speculos
git -C speculos checkout d5d32d3b3147262cb40eed83dc9bb6ef0a5504e8 -b fido2-app
(cd speculos && cmake -Bbuild -H. && make -C build)

./speculos/speculos.py --log-level apdu:DEBUG --log-level usb:DEBUG bin/app.elf --usb U2F
```

You can then clone the Solokeys FIDO2 tests and apply some adjustments:
```sh
# From repository root, cloning fido2-tests project in the repository
git clone https://github.com/solokeys/fido2-tests
git -C fido2-tests checkout 591d3d2279949e08de0766897f24bcfd39af1339 -b fido2-app
git -C fido2-tests am ../tests/0001-Link-tests-with-Speculos-running-the-FIDO2-applicati.patch
git -C fido2-tests am ../tests/0002-Edit-test-to-make-them-work-on-Ledger-fido2-app.patch
```


Eventually, you can launch the tests:
```
cd fido2-tests
# In a virtual environment: pip3 install -r requirements.txt
# Warning fido2-tests and our tests over speculos both uses fido2 module
# but with different version.
pytest --sim tests/standard/fido2/test_reset.py --vendor ledger
pytest --sim tests/standard/fido2/test_make_credential.py --vendor ledger

# All tests from standard/u2f, standard/transport, standard/fido2 should either pass or be automatically skipped.
# Note that tests/standard/fido2/pin/test_pin.py test should be run isolated as at the final step the device end up in a locked situation where a Speculos restart (simulating a device reboot) is needed.
```

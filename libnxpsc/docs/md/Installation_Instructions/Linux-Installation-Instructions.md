# Linux installation
<a id="top"></a>

## Dependencies

Only a compiler and CMake.

```
sudo apt install build-essential cmake      # Debian, Ubuntu
sudo dnf install gcc cmake                  # Fedora
sudo pacman -S base-devel cmake             # Arch
```

## Build and install

```
git clone <this repository>
cd libnxpsc
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cd build && ctest --output-on-failure
sudo cmake --install .
```

## Talking to a reader

libnxpsc does not open the reader, your transport does. On Linux the two usual
choices are:

- **libnfc** - `sudo apt install libnfc-dev`, then call
  `nfc_initiator_transceive_bytes()` from your `transceive` callback.
- **PC/SC** - `sudo apt install libpcsclite-dev pcscd`, then `SCardTransmit()`.
  With PC/SC set `nxpsc_set_cmdset(card, NXPSC_CMDSET_NATIVE_ISO)`, the daemon
  will not pass raw native frames.

If a reader is claimed by the kernel NFC stack and libnfc cannot open it,
blacklist the `pn533_usb` module, the usual advice for that hardware applies
unchanged here.

^[Top](#top)

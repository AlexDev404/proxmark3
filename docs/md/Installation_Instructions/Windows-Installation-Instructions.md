# Windows installation
<a id="top"></a>

## Native, MSVC

Install Visual Studio with the C++ workload, or the Build Tools, then

```
cmake -S . -B build
cmake --build build --config Release
cd build && ctest -C Release --output-on-failure
```

The library links `bcrypt.lib` for `BCryptGenRandom`, the CMake build does this
for you.

The build produces both flavours:

| File | What it is |
|---|---|
| `nxpsc.lib` | static library, link it together with `bcrypt.lib` |
| `nxpsc.dll` | shared library, every non-static function exported |
| `nxpsc.dll.lib` | import library for `nxpsc.dll` |

The headers carry no `__declspec(dllexport)`, so the DLL is built with
`WINDOWS_EXPORT_ALL_SYMBOLS`, as the ELF and MinGW builds already export
everything. Bindings that load the DLL at run time (P/Invoke, ctypes, FFI) need
only `nxpsc.dll`.

## MinGW or MSYS2

```
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
```

## WSL

A WSL build is an ordinary Linux build, see the Linux page. USB readers are not
visible to WSL without `usbipd-win`; if the reader lives on the Windows side,
build natively instead.

## Talking to a reader

The winscard PC/SC API is built into Windows, so a PC/SC transport needs no
extra dependency. As with PC/SC anywhere, call
`nxpsc_set_cmdset(card, NXPSC_CMDSET_NATIVE_ISO)`.

^[Top](#top)

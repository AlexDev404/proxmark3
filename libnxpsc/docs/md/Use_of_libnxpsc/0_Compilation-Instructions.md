# 0. Compilation instructions
<a id="top"></a>

## Requirements

- a C11 compiler, gcc, clang or MSVC
- CMake 3.10 or later

Nothing else. The only third party code is a trimmed copy of the mbedtls AES and
DES block ciphers, vendored in `third_party/mbedtls`, so there is no dependency
to install and no system crypto library to find.

## Build

```
cmake -S . -B build
cmake --build build
```

This produces

| Artefact | Description |
|---|---|
| `libnxpsc.a` | static library |
| `libnxpsc.so` / `.dylib` / `.dll` | shared library, for FFI consumers |
| `nxpsc_test_crypto`, `nxpsc_test_protocol` | the test binaries |
| `nxpsc_personalize` | the example |

## Install

```
cmake --install build --prefix /usr/local
```

Installs the headers under `include/nxpsc`, the libraries, and a `libnxpsc.pc`
pkg-config file, so a consumer can simply

```
cc $(pkg-config --cflags libnxpsc) myapp.c $(pkg-config --libs libnxpsc)
```

## Building without CMake

The library is nine translation units with no generated sources, so dropping it
into an existing build is a matter of compiling `src/*.c` and the five mbedtls
files with `include/` and `third_party/` on the include path. That is the usual
route for MCU and Android NDK builds.

^[Top](#top)

# 4. Advanced compilation parameters
<a id="top"></a>

## CMake options

| Option | Default | Effect |
|---|---|---|
| `NXPSC_BUILD_SHARED` | `ON` | build the shared library as well as the static one |
| `NXPSC_BUILD_TESTS` | `ON` | build and register the test binaries with CTest |
| `NXPSC_BUILD_EXAMPLES` | `ON` | build the example |

For an embedded target, `-DNXPSC_BUILD_SHARED=OFF -DNXPSC_BUILD_TESTS=OFF
-DNXPSC_BUILD_EXAMPLES=OFF` leaves only the static library.

## Cross compiling

Nothing in the library is host specific except the random number source, so a
standard CMake toolchain file is enough:

```
cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=my-arm.cmake
```

## Random numbers

The library needs random bytes for the authentication nonces. It uses
`getrandom`/`/dev/urandom` on Unix and `BCryptGenRandom` on Windows, hence the
`bcrypt` link on that platform. A target with neither must provide its own entropy
source; this is the one place a bare metal port has to touch.

Do not weaken it. Predictable nonces break the authentication outright.

## Size

The whole library is roughly 200 kB of source and links to well under 100 kB of
code with `-Os`, with no heap use beyond the single `nxpsc_card_t` allocation in
`nxpsc_open()`. A caller that wants no allocation at all can keep that structure
itself; `nxpsc_close()` is then the only call to skip.

## Using it from other languages

The shared library exports a flat C API with no callbacks other than the
transport and no structs containing function pointers beyond it, so it binds
cleanly with ctypes, cffi, JNA, N-API and P/Invoke. Keep the `nxpsc_card_t`
pointer opaque on the foreign side.

^[Top](#top)

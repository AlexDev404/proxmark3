# macOS installation
<a id="top"></a>

## Dependencies

```
xcode-select --install
brew install cmake
```

## Build

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cd build && ctest --output-on-failure
```

Apple clang is the default compiler and the CI builds with clang as well, so the
library is expected to be warning free there.

## Universal binaries

```
cmake -S . -B build -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64"
```

## Talking to a reader

macOS ships PC/SC as part of the CryptoTokenKit framework, so a PC/SC transport
works out of the box; link `-framework PCSC`. libnfc is available from Homebrew
if you prefer direct USB access.

^[Top](#top)

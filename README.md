# decompatty

A small Qt-based binary analysis workbench for inspecting executables, heavily inspired by IDA.

## Features

- Opens 32-bit and 64-bit Mach-O binaries in either byte order, including universal / fat binaries
- Detects architecture, bitness, and endianness
- Parses symbols and extracts strings
- Tabbed views (disassembly, strings)
- Dockable panels

## Requirements

- CMake 3.22+
- A C++20 compiler (Clang/GCC)
- LLVM development libraries for the x86_64 disassembly plugin (`brew install llvm` on macOS)
- Qt 6 (Widgets)

## Build

```sh
cmake -S . -B build
cmake --build build
```

## Usage

```sh
./build/decompatty [file]
```

Inside decompatty, use **File > Open** (or Ctrl+O / Cmd+O) to load a binary.
Open views from **View > Open View**

## Screenshots

### Disassembly view
![Disassembly View](docs/screenshots/disassembly.png)

### Strings view
![Strings view](docs/screenshots/strings.png)
Fat binaries open the first architecture slice by default. The Mach-O parser exposes
its architecture table through `slices()` and accepts a `slice_index` constructor
argument to inspect another slice. File offsets refer to the original fat binary.
Disassembly requires a plugin matching the slice's architecture, bitness, and byte order.

Parser regression checks:

```sh
cmake --build build --target macho_tests
./build/macho_tests
```

The x86_64 plugin uses LLVM and displays Intel syntax. If LLVM is installed in a
custom location, pass `-DLLVM_DIR=/path/to/llvm/lib/cmake/llvm` when configuring.
Undecodable bytes appear as `.byte` rows so disassembly can continue.
The strings view escapes control characters such as `\n`, `\r`, and `\t`.

Strings display and x86_64 plugin checks:

```sh
cmake --build build --target disassembly_tests
QT_QPA_PLATFORM=offscreen ./build/disassembly_tests ./build/arch/arch_x86_64.so
```

Parsing and disassembly run on a background worker. The main Qt thread renders
incoming instruction batches in a table model, with a live instruction count in
the status bar. Opening another file cancels the previous decode. Closing and
reopening the disassembly tab restores the batches already received.

Threading and incremental display checks:

```sh
cmake --build build --target async_tests
QT_QPA_PLATFORM=offscreen ./build/async_tests ./build/arch
```

# decompatty

A small Qt-based binary analysis workbench for inspecting executables, heavily inspired by IDA.

## Features

- Opens PE, ELF, and Mach-O binaries
- Detects architecture, bitness, and endianness
- Parses symbols and extracts strings
- Tabbed views (disassembly, strings)
- Dockable panels

## Requirements

- CMake 3.22+
- A C++20 compiler (Clang/GCC)
- Qt 6 (Widgets)

## Build

```sh
cmake -S . -B build
cmake --build build
```

## Usage

```sh
./build/decompatty
```

Inside the app, use **File > Open** (or Ctrl+O / Cmd+O) to load a binary.
Open views from **View > Open View**
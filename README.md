# File Inspector | C++17 Signature Checker

A tiny **read-only** command-line tool that checks file header bytes (magic
numbers) and highlights when a filename extension doesn't match the detected
format. Useful as a first step in file triage, but **not an antivirus scanner**.

## Skills demonstrated

Modern C++17, standard-library file I/O, `std::filesystem`, binary analysis,
unit tests with CTest, and CMake builds. No third-party dependencies.

## Build and run

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
./build/file-inspector examples/not_really_a_png.txt
```

On Windows, the executable may be at `build/Debug/file-inspector.exe`.

The demo file is just **harmless text with an artificial PDF header** and a
`.txt` extension, so you can see how mismatches are reported.

## Recognized signatures

PNG, JPEG, GIF, PDF, ZIP, ELF, and files beginning with an `MZ` header.
An `MZ` header alone cannot prove a file is a valid Windows executable.

## Security notes & limitations

This tool only examines the first 16 bytes and never executes input files.
A matching signature doesn't guarantee a file is genuine or safe. ZIP-based
formats (such as DOCX and XLSX) share a ZIP signature, and file extensions can
be misleading. A future version could validate deeper structure and export
machine-readable reports.

Only inspect files you are allowed to access. Do not treat a mismatch as proof
of malicious behavior.

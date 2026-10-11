# Building plugxel

## Toolchain Prerequisites

- **Rust** (stable, targeting `wasm32-unknown-unknown`)
- **CMake** (v3.20+), **Ninja**
- **C++ Compiler** (MSVC 2022 on Windows, GCC/Clang on Linux with GTK4 developer libraries)

On Linux (Debian/Ubuntu):
```bash
sudo apt-get update && sudo apt-get install -y libgtk-4-dev pkg-config ninja-build libx11-dev build-essential
```

---

## 1. Automatic Builds

Run the platform-specific scripts to compile the Rust core runtime, build WASM plugins, and generate the C++ executable:

### Windows
```powershell
cd plug.cross\windows
.\make.bat
```
Outputs: `plug.cross/release/x64/plugxel-x64.exe` and `plugins/`

### Linux
```bash
cd plug.cross/linux
./make.sh
```
Outputs: `plug.cross/release/x86_64/plugxel-x64` and `plugins/`

---

## 2. Manual Step-by-Step Compilation

### Rust Runtime Static Library
```bash
cd plug.app/rt
cargo build --release --lib
```
*Generates: `plug.app/rt/target/release/tm_main.lib` (Windows) or `libtm_main.a` (Linux).*

### WASM Plugins
```bash
rustc --target wasm32-unknown-unknown --crate-type cdylib \
      plug.app/rt/src_plugins/pTerm/pTerm.rs \
      -o plugins/pTerm.wasm \
      -C opt-level=z -C lto=true
```

### CMake Configuration and Compilation

#### Windows
```cmd
cd plug.cross\windows
mkdir build
cd build
cmake -G Ninja -DRUST_LIB_PATH=../../../plug.app/rt/target/release/tm_main.lib -DCMAKE_BUILD_TYPE=Release ..
ninja
```

#### Linux
```bash
cd plug.cross/linux
mkdir build
cd build
cmake -G Ninja -DRUST_LIB_PATH=../../../plug.app/rt/target/release/libtm_main.a -DCMAKE_BUILD_TYPE=Release ..
ninja
```

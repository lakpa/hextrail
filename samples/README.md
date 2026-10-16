# Rebuilding the demonstration libraries

The app bundles these files in `hextrail/samples/`:

- `native_demo.c`: original benign C source.
- `libnative_demo.so`: compiled ELF64 AArch64 shared library with symbols.
- `libnative_demo_stripped.so`: the same library after stripping static symbols.

The fixtures were produced with Zig 0.14.1's Clang frontend in a development environment:

```bash
python -m pip install ziglang==0.14.1
python -m ziglang cc -target aarch64-linux-android -shared -nostdlib -fPIC -O1 -fno-inline \
  -Wl,-soname,libnative_demo.so \
  -o hextrail/samples/libnative_demo.so hextrail/samples/native_demo.c
python -m ziglang objcopy --strip-all \
  hextrail/samples/libnative_demo.so hextrail/samples/libnative_demo_stripped.so
```

No Android SDK or NDK is needed to inspect the bundled binaries. The freestanding link intentionally leaves `__android_log_write` unresolved, giving the import view a real Android API symbol to display. The fixtures are not packaged as an Android app and have not been tested by loading them on an Android device.

`calculate_total` contains validation and discount branches, `checksum_bytes` contains a loop, `validate_quantity` is a local symbol, and the two exported JNI-shaped names show how long mobile native symbols appear. Compiler optimisations include tail branches, which are intentionally not labelled as direct BL calls in this prototype.

For production Android builds, use your normal Android NDK toolchain and application configuration. Exact addresses in the fixture tests may change if the sample is rebuilt with another compiler/version.

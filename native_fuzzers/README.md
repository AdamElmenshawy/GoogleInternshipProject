# Native AOSP Fuzzer Harnesses

These are real libFuzzer harnesses that hand fuzzed bytes to **actual AOSP
libraries** — no mock classes, no simulated vulnerabilities. A crash is a
genuine bug in the library.

| Target | Library exercised | Harness |
|---|---|---|
| `hevc_extractor_fuzzer` | `libmp4extractor` (HEVC/H.265-in-MP4 parsing) | `stagefright_hevc/hevc_extractor_fuzzer.cpp` |
| `surface_flinger_fuzzer` | `libbinder` / SurfaceFlinger service | `binder_service/surface_flinger_fuzzer.cpp` |
| `webp_parser_fuzzer` | `libwebp` (VP8/VP8L decode) | `webp_image/webp_parser_fuzzer.cpp` |

> **Note on the HEVC target.** AOSP has no standalone HEVC extractor — HEVC
> (H.265) parsing lives in the `MPEG4Extractor` (`frameworks/av/media/extractors/mp4`),
> which handles `hvc1`/`hev1` tracks inside MP4 containers. The
> `hevc_extractor_fuzzer` therefore hands fuzzed bytes to the real
> `MPEG4Extractor` via the same `ExtractorFuzzerBase` infrastructure AOSP ships
> for its own extractor fuzzers. It mirrors the real `mp4_extractor_fuzzer`
> build (`extractor-fuzzer-defaults` + `libmp4extractor`).

## Why you need a Linux AOSP build tree

The Android platform build (Soong/make) is **Linux-only**. It does not run on
macOS. To build and run these harnesses you need:

1. A Linux machine (or cloud VM) with ~200 GB free disk and 16 GB+ RAM.
2. A checkout of AOSP (`repo init -u https://android.googlesource.com/platform/manifest -b android15-release`).
3. A userdebug Cuttlefish image for running the fuzzers on a virtual device.

## Set up Cuttlefish (userdebug)

1. Get a current `aosp_cf_x86_64-userdebug` image from
   [ci.android.com](https://ci.android.com) (or build it with `m`).
2. Install Cuttlefish on the Linux host:
   ```bash
   sudo apt install -y git adb
   git clone https://github.com/google/cuttlefish
   cd cuttlefish
   ./tools/build.sh
   sudo ./tools/install.sh
   ```
3. Launch the virtual device:
   ```bash
   cvd start
   adb devices   # should show a device
   ```

## Build a single fuzzer

```bash
cd <aosp-tree>
source build/envsetup.sh
lunch aosp_cf_x86_64-userdebug
m hevc_extractor_fuzzer
m surface_flinger_fuzzer
m webp_parser_fuzzer
```

Built binaries land under
`out/target/product/vsoc_x86_64/data/fuzz/x86_64/<target>/<target>`.

## Run on the device

```bash
# Push the binary (or let the pipeline do it via binaryPath)
adb push out/target/product/vsoc_x86_64/data/fuzz/x86_64/hevc_extractor_fuzzer/hevc_extractor_fuzzer \
  /data/fuzz/x86_64/hevc_extractor_fuzzer/
adb shell chmod 755 /data/fuzz/x86_64/hevc_extractor_fuzzer/hevc_extractor_fuzzer

# Run with libFuzzer
adb shell /data/fuzz/x86_64/hevc_extractor_fuzzer/hevc_extractor_fuzzer \
  -max_total_time=60 -artifact_prefix=/data/fuzz/x86_64/hevc_extractor_fuzzer/
```

Crash inputs land at `/data/fuzz/<arch>/<target>/crash-<hash>` and tombstones
at `/data/tombstones/tombstone_NN`. The pipeline pulls both.

## Minimize a crash (required for VRP)

```bash
adb shell /data/fuzz/x86_64/hevc_extractor_fuzzer/hevc_extractor_fuzzer \
  -minimize_crash=1 -artifact_prefix=/data/fuzz/minimized/ \
  /data/fuzz/x86_64/hevc_extractor_fuzzer/crash-<hash>
```

## Notes

- `fuzz_config.componentid` values are Google-internal fuzzing-infrastructure
  IDs. Verify them against the current AOSP `fuzz_config` docs before relying
  on them for infrastructure integration.
- The `corpus/` directory holds raw binary seeds (libFuzzer requires raw bytes,
  not hex text).

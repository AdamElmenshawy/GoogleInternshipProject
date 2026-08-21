import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { CrashCollector } from "./crash_collector.js";

/**
 * Native Fuzzer Runner.
 *
 * Modes:
 *   - "device" (default): runs a real libFuzzer binary on a connected Android
 *     device via ADB, collects genuine crash artifacts (crash-<hash> inputs and
 *     tombstones), and parses the real sanitizer output. Returns [] when the
 *     binary does not crash — it NEVER fabricates a finding.
 *   - "dry-run": returns clearly-marked synthetic fixtures (source:
 *     "simulation") for CI environments without a device. Must be explicitly
 *     opted into.
 *
 * All output fields are snake_case to match the rest of the pipeline.
 */
export class NativeFuzzerRunner {
  constructor(options = {}) {
    this.target = options.target || "hevc"; // 'hevc' | 'webp' | 'binder'
    this.mode = options.mode || "device";
    this.arch = options.arch || "arm64";
    this.fuzzTimeSec = options.maxTime || 30;
    this.artifactsDir = path.resolve("fuzzer/artifacts");
    this.nativeDir = path.resolve("native_fuzzers");
    this.verbose = options.verbose ?? true;
    this.simulationAllowed = options.simulationAllowed ?? false;
    // Optional path to a prebuilt fuzzer binary to push to the device.
    this.binaryPath = options.binaryPath || null;

    if (!fs.existsSync(this.artifactsDir)) {
      fs.mkdirSync(this.artifactsDir, { recursive: true });
    }
  }

  /**
   * Compiles the native C++ harness with host Clang/ASan. Used only for
   * host-side smoke tests; real device fuzzing uses an AOSP-built binary.
   */
  compileHostTarget(targetName = this.target) {
    let sourceFile, dictFile;
    if (targetName === "hevc") {
      sourceFile = path.join(this.nativeDir, "stagefright_hevc", "hevc_extractor_fuzzer.cpp");
      dictFile = path.join(this.nativeDir, "stagefright_hevc", "hevc.dict");
    } else if (targetName === "webp") {
      sourceFile = path.join(this.nativeDir, "webp_image", "webp_parser_fuzzer.cpp");
      dictFile = path.join(this.nativeDir, "webp_image", "webp.dict");
    } else {
      sourceFile = path.join(this.nativeDir, "binder_service", "surface_flinger_fuzzer.cpp");
      dictFile = null;
    }

    const binaryOut = path.join(this.artifactsDir, `${targetName}_fuzzer_bin`);

    let clangAvailable = false;
    try {
      execSync("clang++ --version", { stdio: "ignore" });
      clangAvailable = true;
    } catch {
      clangAvailable = false;
    }

    if (clangAvailable && fs.existsSync(sourceFile)) {
      try {
        if (this.verbose) console.log(`[Native Runner] Compiling ${targetName} with clang++ -fsanitize=fuzzer,address...`);
        execSync(`clang++ -O1 -fno-omit-frame-pointer -g -fsanitize=fuzzer,address -std=c++17 "${sourceFile}" -o "${binaryOut}"`, {
          stdio: ["ignore", "pipe", "pipe"],
          timeout: 15000
        });
        return { success: true, binary: binaryOut, dict: dictFile };
      } catch (err) {
        if (this.verbose) console.warn(`[Native Runner] Clang libFuzzer compile skipped: ${err.message}`);
      }
    }

    return { success: false, binary: null, dict: dictFile };
  }

  /**
   * Runs a real fuzzing session on a connected device.
   * Returns an array of parsed crash records; [] if no crash occurred.
   */
  async runOnDevice(targetName = this.target) {
    const onDeviceDir = `/data/fuzz/${this.arch}/${targetName}`;
    const onDeviceBinary = `${onDeviceDir}/${targetName}`;

    // 1. Verify a device is present.
    try {
      const devices = execSync("adb devices", { encoding: "utf-8", stdio: ["pipe", "pipe", "ignore"] })
        .trim().split("\n").slice(1)
        .filter(l => l.includes("device") && !l.includes("offline"));
      if (devices.length === 0) {
        throw new Error("No ADB device detected. Device mode requires a connected, authorized device.");
      }
    } catch (err) {
      throw new Error(`No ADB device detected. Device mode requires a connected, authorized device. (${err.message})`);
    }

    // 2. Ensure the binary is on the device.
    if (this.binaryPath && fs.existsSync(this.binaryPath)) {
      execSync(`adb shell mkdir -p ${onDeviceDir}`, { stdio: "ignore" });
      execSync(`adb push ${this.binaryPath} ${onDeviceBinary}`, { stdio: ["ignore", "pipe", "pipe"] });
      execSync(`adb shell chmod 755 ${onDeviceBinary}`, { stdio: "ignore" });
    } else {
      // Assume the binary is already present (e.g. built by `m <target>` in an AOSP tree).
      const present = execSync(`adb shell ls ${onDeviceBinary}`, { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] });
      if (!present.trim()) {
        throw new Error(`Fuzzer binary not found on device at ${onDeviceBinary}. Build it with 'm ${targetName}' in an AOSP tree, or pass binaryPath.`);
      }
    }

    // 3. Run libFuzzer with an artifact prefix so crash inputs land on device.
    const artifactPrefix = `${onDeviceDir}/`;
    const runCmd = [
      `adb shell ${onDeviceBinary}`,
      `-max_total_time=${this.fuzzTimeSec}`,
      `-artifact_prefix=${artifactPrefix}`,
      `-print_final_stats=1`,
    ].join(" ");

    if (this.verbose) console.log(`[Native Runner] Running: ${runCmd}`);
    let output = "";
    try {
      output = execSync(runCmd, { encoding: "utf-8", timeout: (this.fuzzTimeSec + 30) * 1000, stdio: ["ignore", "pipe", "pipe"] });
    } catch (err) {
      // libFuzzer exits non-zero when it finds a crash — that is the signal we want.
      output = (err.stdout || "") + (err.stderr || "");
    }

    // 4. Look for crash artifacts produced by libFuzzer.
    const crashFiles = [];
    try {
      const listing = execSync(`adb shell ls ${onDeviceDir}`, { encoding: "utf-8" });
      crashFiles.push(...listing.trim().split("\n").filter(f => f.startsWith("crash-")));
    } catch {
      // no artifacts dir listing
    }

    if (crashFiles.length === 0) {
      if (this.verbose) console.log(`[Native Runner] No crash artifacts produced for ${targetName}.`);
      return [];
    }

    // 5. Pull crash inputs and tombstones, parse the sanitizer report.
    const records = [];
    for (const crashFile of crashFiles) {
      const localCrash = path.join(this.artifactsDir, `${targetName}_${crashFile}`);
      try {
        execSync(`adb pull ${onDeviceDir}/${crashFile} ${localCrash}`, { stdio: ["ignore", "pipe", "pipe"] });
      } catch (err) {
        console.warn(`[Native Runner] Failed to pull ${crashFile}: ${err.message}`);
        continue;
      }

      const parsed = CrashCollector.parseCrash(output, {
        target_build: `Android 15 (Cuttlefish CVD - userdebug ${this.arch})`,
        source: "fuzzer",
      });
      parsed.reproducer_path = localCrash;
      parsed.reproducer_hex = fs.readFileSync(localCrash).toString("hex");
      parsed.sanitizer = this.detectSanitizer(output);
      parsed.target = targetName;
      records.push(parsed);
    }

    // 6. Pull any fresh tombstones for corroboration.
    try {
      const tombstones = new CrashCollector().pullTombstones(path.join(this.artifactsDir, "tombstones"), 3);
      if (tombstones.length > 0) {
        records.forEach(r => { r.tombstone_files = tombstones; });
      }
    } catch (err) {
      console.warn(`[Native Runner] Tombstone pull skipped: ${err.message}`);
    }

    if (this.verbose) {
      console.log(`[Native Runner] Surfaced ${records.length} real crash artifact(s) for ${targetName}.`);
    }
    return records;
  }

  /**
   * Heuristic to label the sanitizer from raw fuzzer output.
   */
  detectSanitizer(output) {
    if (/HWAddressSanitizer|hwaddress/i.test(output)) return "HWASan";
    if (/AddressSanitizer|heap-buffer-overflow|use-after-free/i.test(output)) return "ASan";
    if (/UndefinedBehaviorSanitizer/i.test(output)) return "UBSan";
    return "libFuzzer";
  }

  /**
   * Dry-run fixture. Returns a clearly-marked synthetic crash artifact so CI
   * without a device can exercise the pipeline. Never ingested as a finding.
   */
  runDryRun(targetName = this.target) {
    const fixture = this.dryRunFixture(targetName);
    const parsed = CrashCollector.parseCrash(fixture.rawReport, {
      target_build: fixture.target_build,
      source: "simulation",
      simulated: true,
    });
    parsed.sanitizer = fixture.sanitizer;
    parsed.reproducer_hex = fixture.reproducer_hex;
    parsed.reproducer_path = fixture.reproducerFile;
    parsed.target = targetName;
    parsed.simulated = true;
    return [parsed];
  }

  /**
   * Executes a native fuzzing run and returns structured crash artifacts.
   */
  async runFuzzSession(targetName = this.target) {
    if (this.verbose) {
      console.log(`[Native libFuzzer] Initializing fuzz session on target: ${targetName.toUpperCase()} (mode: ${this.mode})`);
    }

    if (this.mode === "dry-run" || this.mode === "simulation") {
      if (!this.simulationAllowed) {
        throw new Error(
          "Simulation mode is disabled. Set FUZZER_MODE=simulation (or pass --dry-run) explicitly to override."
        );
      }
      return this.runDryRun(targetName);
    }

    return this.runOnDevice(targetName);
  }

  /**
   * Hardcoded synthetic sanitizer reports, used ONLY for --dry-run.
   * These are not real findings and are marked as such.
   */
  dryRunFixture(targetName) {
    if (targetName === "hevc") {
      const reproducerHex = "0000000140010c01ffff016000000300fffe009a";
      const reproducerBytes = Buffer.from(reproducerHex, "hex");
      const crashFile = path.join(this.artifactsDir, `crash_hevc_dryrun.bin`);
      fs.writeFileSync(crashFile, reproducerBytes);

      const hwasanReport = `==1945==ERROR: HWAddressSanitizer: tag-mismatch on address 0x0059007412984000 at pc 0x0079012a474c
READ of size 4 at 0x0059007412984000 tags: 59/00 (ptr/mem) in thread T3 (Codec2-worker)
    #0 0x79012a474c in ihevcd_parse_slice_header /apex/com.android.media.swcodec/lib64/libstagefright_soft_c2hevcdec.so:620
    #1 0x79012a5230 in ihevcd_decode /apex/com.android.media.swcodec/lib64/libstagefright_soft_c2hevcdec.so:1480
    #2 0x7901285110 in C2SoftHevcDec::process /apex/com.android.media.swcodec/lib64/libcodec2_soft_common.so:410
    #3 0x790103b870 in android::Codec2Client::Component::queue /apex/com.android.media/lib64/libcodec2_client.so:180
0x0059007412984000 is located 0 bytes inside a 64-byte region [0x0059007412984000, 0x0059007412984040)
allocated by thread T3 (Codec2-worker) here:
    #0 0x7b8a10e420 in malloc /apex/com.android.runtime/lib64/bionic/libc.so
    #1 0x79012a4700 in ihevcd_parse_slice_header /apex/com.android.media.swcodec/lib64/libstagefright_soft_c2hevcdec.so:608
SUMMARY: HWAddressSanitizer: tag-mismatch /apex/com.android.media.swcodec/lib64/libstagefright_soft_c2hevcdec.so:620 in ihevcd_parse_slice_header`;

      return {
        target: "libstagefright_c2hevcdec",
        process: "/apex/com.android.media.swcodec/lib64/libstagefright_soft_c2hevcdec.so",
        sanitizer: "HWASan (tag-mismatch / heap-buffer-overflow)",
        signal: "SIGSEGV (SEGV_TAGCHECK)",
        fault_address: "0x0059007412984000",
        cause: "Heap out-of-bounds read/write tag-mismatch in HEVC slice parser",
        reproducerFile: crashFile,
        reproducer_hex: reproducerHex,
        backtrace: `      #00 pc 00000000000a474c  /apex/com.android.media.swcodec/lib64/libstagefright_soft_c2hevcdec.so (ihevcd_parse_slice_header+620)
      #01 pc 000000000009ec30  /apex/com.android.media.swcodec/lib64/libstagefright_soft_c2hevcdec.so (ihevcd_decode+1480)
      #02 pc 0000000000085110  /apex/com.android.media.swcodec/lib64/libcodec2_soft_common.so (C2SoftHevcDec::process+410)
      #03 pc 000000000003b870  /apex/com.android.media/lib64/libcodec2_client.so (android::Codec2Client::Component::queue+180)`,
        rawReport: hwasanReport,
        target_build: "Android 15 (Cuttlefish CVD - userdebug HWASan) [DRY-RUN FIXTURE]"
      };
    } else if (targetName === "webp") {
      const reproducerHex = "5249464620000000574542505650384c100000002f0120ffff";
      const reproducerBytes = Buffer.from(reproducerHex, "hex");
      const crashFile = path.join(this.artifactsDir, `crash_webp_dryrun.bin`);
      fs.writeFileSync(crashFile, reproducerBytes);

      const asanReport = `==2210==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60f000001200 at pc 0x00000048e912
WRITE of size 2 at 0x60f000001200 thread T0
    #0 0x48e912 in BuildHuffmanTable /system/lib64/libwebp.so:312
    #1 0x48f102 in ReadHuffmanCodes /system/lib64/libwebp.so:540
    #2 0x48a430 in VP8LDecodeHeader /system/lib64/libwebp.so:78
    #3 0x484110 in WebPDecode /system/lib64/libwebp.so:120
0x60f000001200 is located 0 bytes to the right of 256-byte region [0x60f000001100,0x60f000001200)
allocated by thread T0 here:
    #0 0x4210a8 in malloc /bionic/libc.so
    #1 0x48e890 in BuildHuffmanTable /system/lib64/libwebp.so:300`;

      return {
        target: "libwebp_decoder",
        process: "/system/lib64/libwebp.so",
        sanitizer: "ASan (heap-buffer-overflow)",
        signal: "SIGSEGV (SEGV_ACCERR)",
        fault_address: "0x60f000001200",
        cause: "Heap buffer overflow in VP8L lossless Huffman table construction",
        reproducerFile: crashFile,
        reproducer_hex: reproducerHex,
        backtrace: `      #00 pc 000000000008e912  /system/lib64/libwebp.so (BuildHuffmanTable+312)
      #01 pc 000000000008f102  /system/lib64/libwebp.so (ReadHuffmanCodes+540)
      #02 pc 000000000008a430  /system/lib64/libwebp.so (VP8LDecodeHeader+78)
      #03 pc 0000000000084110  /system/lib64/libwebp.so (WebPDecode+120)`,
        rawReport: asanReport,
        target_build: "Android 15 (Cuttlefish CVD - userdebug ASan) [DRY-RUN FIXTURE]"
      };
    } else {
      const reproducerHex = "ffffffff7fffffff000003ec";
      const crashFile = path.join(this.artifactsDir, `crash_binder_dryrun.bin`);
      fs.writeFileSync(crashFile, Buffer.from(reproducerHex, "hex"));

      return {
        target: "SurfaceFlinger_fuzzService",
        process: "/system/bin/surfaceflinger",
        sanitizer: "HWASan (tag-mismatch in IBinder transact)",
        signal: "SIGSEGV (SEGV_TAGCHECK)",
        fault_address: "0x00220078b4a21980",
        cause: "HWAddressSanitizer tag mismatch handling malformed Parcel in transact code 1004",
        reproducerFile: crashFile,
        reproducer_hex: reproducerHex,
        backtrace: `      #00 pc 0000000000045844  /system/lib64/libsurfaceflinger.so (android::SurfaceFlinger::onTransact+412)
      #01 pc 00000000000cf550  /system/lib64/libbinder.so (android::BBinder::transact+272)
      #02 pc 000000000003b12f  /system/lib64/libbinder.so (android::IPCThreadState::executeCommand+520)`,
        rawReport: "HWASan: tag-mismatch in SurfaceFlinger onTransact parcel unpacking",
        target_build: "Android 15 (VanillaIceCream - API 35 userdebug) [DRY-RUN FIXTURE]"
      };
    }
  }
}

// CLI runner
if (process.argv[1] && process.argv[1].endsWith("native_runner.js")) {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run") || args.includes("-d");
  const mode = process.env.FUZZER_MODE || (dryRun ? "dry-run" : "device");
  const target = args.find(a => !a.startsWith("-")) || "hevc";

  const runner = new NativeFuzzerRunner({
    target,
    mode,
    simulationAllowed: dryRun || process.env.FUZZER_MODE === "simulation",
  });

  runner.runFuzzSession().then(artifacts => {
    console.log(`Artifacts: ${artifacts.length} crash record(s)`);
    artifacts.forEach(a => console.log(`  ${a.crash_id} | ${a.sanitizer} | ${a.simulated ? "SIMULATED" : "REAL"}`));
  }).catch(err => {
    console.error(`[Native Runner] ${err.message}`);
    process.exit(1);
  });
}

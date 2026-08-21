/*
 * AOSP Binder / IPC Service Fuzzer for SurfaceFlinger.
 *
 * Uses the real AOSP fuzzService() framework (fuzzbinder) to drive the live
 * SurfaceFlinger service with fuzzed Parcels. No mock service, no simulated
 * logic — the bytes go straight into the real binder transaction path.
 *
 * Build inside an AOSP tree (Linux required):
 *   lunch aosp_cf_x86_64-userdebug
 *   m surface_flinger_fuzzer
 */
#include <fuzzbinder/libbinder_driver.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>

using namespace android;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;
    }

    // Resolve the live SurfaceFlinger service and fuzz its transaction codes.
    sp<IBinder> binder =
        defaultServiceManager()->getService(String16("SurfaceFlinger"));
    if (binder == nullptr) {
        return 0;
    }

    fuzzService(binder, FuzzedDataProvider(data, size));
    return 0;
}

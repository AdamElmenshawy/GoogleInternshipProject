/*
 * AOSP libwebp image parser fuzzer.
 *
 * Hands the fuzzed bytes to the real libwebp decoder (WebPGetFeatures +
 * WebPDecodeRGBA) so the real RIFF/VP8/VP8L/VP8X parsing code is exercised.
 * No simulated Huffman-table logic — any crash is a genuine libwebp bug.
 *
 * Build inside an AOSP tree (Linux required):
 *   lunch aosp_cf_x86_64-userdebug
 *   m webp_parser_fuzzer
 */
#include <webp/decode.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12 || size > (1 << 20)) {
        return 0; // Filter extreme sizes to keep fuzz throughput high.
    }

    // Parse the container header through the real feature parser.
    WebPBitstreamFeatures features;
    if (WebPGetFeatures(data, size, &features) != VP8_STATUS_OK) {
        return 0;
    }

    // Full decode exercises the lossless (VP8L) Huffman table construction
    // and the lossy (VP8) decode paths.
    uint8_t *out = WebPDecodeRGBA(data, size, nullptr, nullptr);
    WebPFree(out);

    return 0;
}

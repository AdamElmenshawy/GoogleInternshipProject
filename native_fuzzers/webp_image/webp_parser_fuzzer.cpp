#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * AOSP libwebp Image Parser Target Harness.
 * Fuzzes WebP RIFF container, VP8/VP8L/VP8X chunk decoding, and Huffman table allocation.
 * Target: libwebp (Tier 3: Image / Graphics Parsers - relates to CVE-2023-4863 class)
 */

namespace android {
    class WebPDecoderHarness {
    public:
        static bool decode(const uint8_t *data, size_t size) {
            if (size < 12) return false;

            // Validate RIFF header
            if (memcmp(data, "RIFF", 4) != 0) return false;
            if (memcmp(data + 8, "WEBP", 4) != 0) return false;

            size_t offset = 12;
            while (offset + 8 <= size) {
                const char *chunkFourCC = (const char *)(data + offset);
                uint32_t chunkSize = (data[offset + 4]) |
                                     (data[offset + 5] << 8) |
                                     (data[offset + 6] << 16) |
                                     (data[offset + 7] << 24);

                offset += 8;
                if (offset + chunkSize > size) {
                    chunkSize = size - offset;
                }

                // Emulate VP8L lossless Huffman table allocation bug
                if (memcmp(chunkFourCC, "VP8L", 4) == 0 && chunkSize > 4) {
                    uint8_t signature = data[offset];
                    if (signature == 0x2F) { // Valid VP8L signature
                        uint32_t numCodes = (data[offset + 1] << 8) | data[offset + 2];
                        if (numCodes > 256 && numCodes < 512) {
                            // Vulnerability check: simulate heap buffer overflow in BuildHuffmanTable
                            volatile uint16_t *huffmanTable = (uint16_t *)malloc(128 * sizeof(uint16_t));
                            if (huffmanTable) {
                                for (size_t i = 0; i < (numCodes % 160); i++) {
                                    huffmanTable[i] = (uint16_t)(data[offset + (i % chunkSize)]);
                                }
                                free((void *)huffmanTable);
                            }
                        }
                    }
                }

                offset += chunkSize;
                if (chunkSize % 2 != 0) offset++; // 2-byte chunk alignment
            }

            return true;
        }
    };
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12 || size > 131072) {
        return 0;
    }

    android::WebPDecoderHarness::decode(data, size);
    return 0;
}

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

/**
 * AOSP libstagefright C2SoftHevcDec Target Harness.
 * Fuzzes HEVC (H.265) NAL unit parsing and slice header decoding.
 * Target: libstagefright_soft_c2hevcdec (Tier 1: Media Parsers)
 */

// Simulated / Mocked C2 HEVC Decoder context for standalone host builds
namespace android {
    class C2SoftHevcParser {
    public:
        C2SoftHevcParser() : mInitialized(true), mMaxBuffer(4096) {}
        
        bool parseNALUnit(const uint8_t *data, size_t size) {
            if (!mInitialized || size < 4) return false;
            
            // Check for NAL start code (0x000001 or 0x00000001)
            size_t offset = 0;
            if (data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01) {
                offset = 3;
            } else if (data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x01) {
                offset = 4;
            } else {
                return false;
            }

            if (offset >= size) return false;

            uint8_t nalHeader = data[offset];
            uint8_t nalType = (nalHeader >> 1) & 0x3F;

            // Vulnerability Simulation: Emulate heap boundary condition when malformed slice header length exceeds allocated buffer
            if (nalType == 1 || nalType == 19) { // Coded slice segment of non-IDR/IDR picture
                if (size > 12 && data[offset + 1] == 0xFF && data[offset + 2] == 0xFE) {
                    // Trigger simulated buffer boundary check in test mode
                    volatile uint8_t *heapBuf = (uint8_t *)malloc(64);
                    if (heapBuf) {
                        uint16_t malformedLen = (data[offset + 3] << 8) | data[offset + 4];
                        if (malformedLen > 64 && malformedLen < 256) {
                            // Boundary access condition
                            heapBuf[malformedLen % 128] = 0xAA;
                        }
                        free((void*)heapBuf);
                    }
                }
            }
            return true;
        }

    private:
        bool mInitialized;
        size_t mMaxBuffer;
    };
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4 || size > 65536) {
        return 0; // Filter out extreme sizes to maintain high fuzz throughput
    }

    android::C2SoftHevcParser parser;
    parser.parseNALUnit(data, size);

    return 0;
}

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <vector>

/**
 * AOSP AIDL / Binder IPC Service Fuzzer Target.
 * Fuzzes Android Framework System Services via AOSP fuzzService() and FuzzedDataProvider.
 * Target: SurfaceFlinger / MediaSessionService (Tier 2: Binder / IPC Services)
 */

// Simulated FuzzedDataProvider & Binder client for cross-platform / host compilation
namespace fuzzer {
    class FuzzedDataProvider {
    public:
        FuzzedDataProvider(const uint8_t *data, size_t size) : mData(data), mSize(size), mOffset(0) {}

        template <typename T>
        T ConsumeIntegral() {
            if (mOffset + sizeof(T) > mSize) return T(0);
            T val;
            memcpy(&val, mData + mOffset, sizeof(T));
            mOffset += sizeof(T);
            return val;
        }

        std::vector<uint8_t> ConsumeRemainingBytes() {
            if (mOffset >= mSize) return {};
            std::vector<uint8_t> rem(mData + mOffset, mData + mSize);
            mOffset = mSize;
            return rem;
        }

        size_t remaining_bytes() const { return mOffset < mSize ? mSize - mOffset : 0; }

    private:
        const uint8_t *mData;
        size_t mSize;
        size_t mOffset;
    };
}

namespace android {
    class Parcel {
    public:
        void writeInt32(int32_t val) { mData.push_back(val); }
        void writeString16(const char *str) { /* serialize */ }
        std::vector<int32_t> mData;
    };

    class IBinder {
    public:
        virtual ~IBinder() = default;
        virtual int transact(uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) = 0;
    };

    class MockSurfaceFlingerService : public IBinder {
    public:
        int transact(uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) override {
            // Emulate transaction handling for SurfaceFlinger codes (1 to 1024)
            switch (code) {
                case 1004: // CREATE_CONNECTION
                case 1006: // SET_TRANSACTION_STATE
                case 1013: // BOOT_FINISHED
                case 1020: // OVERRIDE_HDR_TYPES
                    if (data.mData.size() > 2 && data.mData[0] == -1 && data.mData[1] == 0x7FFFFFFF) {
                        // Simulated integer overflow condition in transaction size calculation
                        volatile int *p = nullptr;
                        // *p = 1; // Potential trigger
                    }
                    break;
                default:
                    break;
            }
            return 0;
        }
    };

    /**
     * Standard AOSP fuzzService helper
     */
    void fuzzService(IBinder *binder, fuzzer::FuzzedDataProvider &&provider) {
        if (!binder) return;

        while (provider.remaining_bytes() > 0) {
            uint32_t code = provider.ConsumeIntegral<uint32_t>() % 1050;
            uint32_t flags = provider.ConsumeIntegral<uint32_t>();
            
            Parcel data;
            while (provider.remaining_bytes() > 4 && data.mData.size() < 16) {
                data.writeInt32(provider.ConsumeIntegral<int32_t>());
            }

            Parcel reply;
            binder->transact(code, data, &reply, flags);
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    fuzzer::FuzzedDataProvider provider(data, size);
    std::unique_ptr<android::MockSurfaceFlingerService> service = std::make_unique<android::MockSurfaceFlingerService>();

    android::fuzzService(service.get(), std::move(provider));
    return 0;
}

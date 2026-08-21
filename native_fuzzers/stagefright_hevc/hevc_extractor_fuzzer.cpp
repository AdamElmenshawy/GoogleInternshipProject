/*
 * AOSP libstagefright HEVC-in-MP4 extractor fuzzer.
 *
 * AOSP has no standalone HEVC extractor: HEVC (H.265) parsing lives in the
 * MPEG4Extractor (frameworks/av/media/extractors/mp4), which handles hvc1/hev1
 * tracks inside MP4 containers. This harness hands fuzzed bytes to the real
 * MPEG4Extractor through the same ExtractorFuzzerBase infrastructure AOSP
 * ships for its own extractor fuzzers (mp4_extractor_fuzzer, mkv_extractor_fuzzer,
 * ...). This harness has ZERO business logic of its own — any crash is a
 * genuine bug in the library.
 *
 * Build inside an AOSP tree (Linux required):
 *   lunch aosp_cf_x86_64-userdebug
 *   m hevc_extractor_fuzzer
 */
#include "ExtractorFuzzerBase.h"

#include "MPEG4Extractor.h"

using namespace android;

class HEVCExtractor : public ExtractorFuzzerBase {
 public:
  HEVCExtractor() = default;
  ~HEVCExtractor() = default;

  bool createExtractor() override;
};

bool HEVCExtractor::createExtractor() {
  mExtractor = new MPEG4Extractor(new DataSourceHelper(mDataSource->wrap()));
  if (!mExtractor) {
    return false;
  }
  mExtractor->name();
  setDataSourceFlags(DataSourceBase::kWalksPrefetching |
                     DataSourceBase::kIsCachingDataSource);
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if ((!data) || (size == 0)) {
    return 0;
  }
  HEVCExtractor* extractor = new HEVCExtractor();
  if (extractor) {
    extractor->processData(data, size);
    delete extractor;
  }
  return 0;
}

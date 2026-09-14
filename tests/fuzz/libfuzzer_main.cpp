// The libFuzzer entry point.
//
// Built only when NEXUS_BUILD_FUZZERS is on, one binary per target, selected by
// NEXUS_FUZZ_TARGET at compile time. The targets themselves live in
// fuzz_targets.hpp and are also driven by a deterministic corpus in the normal
// suite, so they cannot rot between fuzzing runs.
//
//   cmake -B build-fuzz -DNEXUS_BUILD_FUZZERS=ON \
//         -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
//   ./build-fuzz/tests/fuzz_security_envelope corpus/ -max_len=60000

#include "fuzz/fuzz_targets.hpp"

#include <cstddef>
#include <cstdint>

#ifndef NEXUS_FUZZ_TARGET
#define NEXUS_FUZZ_TARGET fuzz_security_envelope
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    nexus_fuzz::NEXUS_FUZZ_TARGET({data, size});
    return 0;
}

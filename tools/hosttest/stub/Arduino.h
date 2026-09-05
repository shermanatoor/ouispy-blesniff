// Minimal stand-in so src/text_summary.h's #include <Arduino.h> resolves when
// unit-testing on the host. Only the pieces text_summary.{h,cpp} touch.
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>

inline size_t strlcpy(char* dst, const char* src, size_t sz) {
    size_t n = strlen(src);
    if (sz) { size_t c = n < sz - 1 ? n : sz - 1; memcpy(dst, src, c); dst[c] = 0; }
    return n;
}

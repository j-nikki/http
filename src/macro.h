#pragma once

#include <bit>
#include <type_traits>

// `INLINE` means "no inline is error". For semantics of "it is not an error for
// there to be multiple definitions within the TU", use `inline`.
#define INLINE             inline __attribute__((always_inline))

#define CI                 constexpr INLINE

#define CAT(X, Y)          CAT_EXP(X, Y)
#define CAT_EXP(X, Y)      X##Y

#define STR(X)             STR_EXP(X)
#define STR_EXP(X)         #X

#define PARENS(...)        PARENS_EXP(__VA_ARGS__)
#define PARENS_EXP(...)    (__VA_ARGS__)

#define RM_PARENS          RM_PARENS_EXP
#define RM_PARENS_EXP(...) __VA_ARGS__

#ifndef NDEBUG
#define DBGE(...) __VA_ARGS__ // expression
#define DBGS(...) __VA_ARGS__ // statement
#else
#define DBGE(...) (void)0
#define DBGS(...)
#endif

namespace util::detail
{
template <class T>
using opaque =
    std::conditional_t<sizeof(T) == 1, uint8_t,
                       std::conditional_t<sizeof(T) == 2, uint16_t,
                                          std::conditional_t<sizeof(T) == 4, uint32_t, uint64_t>>>;
template <class T>
constexpr inline opaque<T> opaque_cast(const T &x) noexcept
{
    return std::bit_cast<opaque<T>>(x);
}
} // namespace util::detail

// expression check; requires string.h
#define CHECKE(For, ...)                                                                           \
    [&](decltype(__VA_ARGS__) CAT(check_, __LINE__)) -> decltype(__VA_ARGS__) {                    \
        using namespace ::util;                                                                    \
        if (!(CAT(check_, __LINE__) For)) {                                                        \
            fprintf(stderr, STR(PARENS(__VA_ARGS__)) " (%#llx) " #For " failed\n",                 \
                    static_cast<long long unsigned>(                                               \
                        ::util::detail::opaque_cast(CAT(check_, __LINE__))));                      \
            DBGE(__builtin_trap());                                                                \
            exit(1);                                                                               \
        }                                                                                          \
        return CAT(check_, __LINE__);                                                              \
    }(__VA_ARGS__)
// requires string.h
#define CHECK(For, ...)                                                                                                                                                                                                                                                       \
    [&](decltype(__VA_ARGS__) CAT(check_, __LINE__)) -> decltype(__VA_ARGS__) {                                                                                                                                                                                               \
        using namespace ::util;                                                                                                                                                                                                                                               \
        if (!(CAT(check_, __LINE__) For)) {                                                                                                                                                                                                                                   \
            fprintf(stderr, "%s (%#llx) < " #For " failed: %s\n", c_str<take_until<')', take_until<'(', strip_until<'(', CAT(STR(PARENS(__VA_ARGS__)), _s)>>>>.data(), static_cast<long long unsigned>(::util::detail::opaque_cast(CAT(check_, __LINE__))), strerror(errno)); \
            DBGE(__builtin_trap());                                                                                                                                                                                                                                           \
            exit(1);                                                                                                                                                                                                                                                          \
        }                                                                                                                                                                                                                                                                     \
        return CAT(check_, __LINE__);                                                                                                                                                                                                                                         \
    }(__VA_ARGS__)
// negative errno; string.h
#define CHECKN(...)                                                                                                                                                                                                                                                                      \
    [&](decltype(__VA_ARGS__) CAT(check_, __LINE__)) -> decltype(__VA_ARGS__) {                                                                                                                                                                                                          \
        using namespace ::util;                                                                                                                                                                                                                                                          \
        if (CAT(check_, __LINE__) < 0) {                                                                                                                                                                                                                                                 \
            fprintf(stderr, "%s (%#llx) >= 0 failed: %s\n", c_str<take_until<')', take_until<'(', strip_until<'(', CAT(STR(PARENS(__VA_ARGS__)), _s)>>>>.data(), static_cast<long long unsigned>(::util::detail::opaque_cast(CAT(check_, __LINE__))), strerror(-CAT(check_, __LINE__))); \
            DBGE(__builtin_trap());                                                                                                                                                                                                                                                      \
            exit(1);                                                                                                                                                                                                                                                                     \
        }                                                                                                                                                                                                                                                                                \
        return CAT(check_, __LINE__);                                                                                                                                                                                                                                                    \
    }(__VA_ARGS__)

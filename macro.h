#pragma once

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
#define DBGE(...) __VA_ARGS__
#else
#define DBGE(...) (void)0
#endif

// expression check; requires string.h
#define CHECKE(For, ...)                                                                           \
    [&](decltype(__VA_ARGS__) CAT(check_, __LINE__)) -> decltype(__VA_ARGS__) {                    \
        using namespace ::util;                                                                    \
        if (!(CAT(check_, __LINE__) For)) {                                                        \
            fprintf(stderr, STR(PARENS(__VA_ARGS__)) " (%#llx) < " #For " failed\n",               \
                    static_cast<long long unsigned int>(CAT(check_, __LINE__)));                   \
            DBGE(__builtin_trap());                                                                \
            exit(1);                                                                               \
        }                                                                                          \
        return CAT(check_, __LINE__);                                                              \
    }(__VA_ARGS__)
// requires string.h
#define CHECK(For, ...)                                                                                                                                                                                                                              \
    [&](decltype(__VA_ARGS__) CAT(check_, __LINE__)) -> decltype(__VA_ARGS__) {                                                                                                                                                                      \
        using namespace ::util;                                                                                                                                                                                                                      \
        if (!(CAT(check_, __LINE__) For)) {                                                                                                                                                                                                          \
            fprintf(stderr, "%s (%#llx) < " #For " failed: %s\n", c_str<take_until<')', take_until<'(', strip_until<'(', CAT(STR(PARENS(__VA_ARGS__)), _s)>>>>.data(), static_cast<long long unsigned int>(CAT(check_, __LINE__)), strerror(errno)); \
            DBGE(__builtin_trap());                                                                                                                                                                                                                  \
            exit(1);                                                                                                                                                                                                                                 \
        }                                                                                                                                                                                                                                            \
        return CAT(check_, __LINE__);                                                                                                                                                                                                                \
    }(__VA_ARGS__)
// negative errno; string.h
#define CHECKN(...)                                                                                                                                                                                                                                             \
    [&](decltype(__VA_ARGS__) CAT(check_, __LINE__)) -> decltype(__VA_ARGS__) {                                                                                                                                                                                 \
        using namespace ::util;                                                                                                                                                                                                                                 \
        if (CAT(check_, __LINE__) < 0) {                                                                                                                                                                                                                        \
            fprintf(stderr, "%s (%#llx) >= 0 failed: %s\n", c_str<take_until<')', take_until<'(', strip_until<'(', CAT(STR(PARENS(__VA_ARGS__)), _s)>>>>.data(), static_cast<long long unsigned int>(CAT(check_, __LINE__)), strerror(-CAT(check_, __LINE__))); \
            DBGE(__builtin_trap());                                                                                                                                                                                                                             \
            exit(1);                                                                                                                                                                                                                                            \
        }                                                                                                                                                                                                                                                       \
        return CAT(check_, __LINE__);                                                                                                                                                                                                                           \
    }(__VA_ARGS__)

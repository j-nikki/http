#include "http.h"

namespace http::detail
{
void headers_impl(const std::size_t nss, std::string_view *const res,
                  const std::string_view *const ss_, char *crlf, char *const crlfcrlf) noexcept
{
#pragma push_macro("CRLF")
#define CRLF(P) ((P)[0] == '\r' && (P)[1] == '\n')
    while (crlf != crlfcrlf) {
        crlf += 2;
        const auto fname = crlf;
        for (; crlf != crlfcrlf && *crlf != ':'; ++crlf)
            ;
        if (crlf == crlfcrlf) [[unlikely]]
            break;
        const auto lname = crlf;
        for (auto it = fname; it != lname; ++it) {
            const auto num = static_cast<unsigned char>(*it - 'A');
            *it            = (num <= 'Z' - 'A') ? 'a' + num : *it;
        }
        const std::string_view name{fname, lname};
        const std::span ss{ss_, nss};
        auto it = std::ranges::lower_bound(ss, name);
        if (it != ss.end() && *it == name) {
            // field is of interest - store into res
            ++crlf;
            for (; crlf != crlfcrlf && *crlf == ' '; ++crlf)
                ;
            if (crlf == crlfcrlf) [[unlikely]]
                break;
            const auto fval = crlf;
            for (; crlf != crlfcrlf && !CRLF(crlf); ++crlf)
                ;
            auto lval = crlf;
            for (; lval != fval && lval[-1] == ' '; --lval)
                ;
            const auto idx = std::distance(ss.begin(), it);
#if HTTP_DEBUG
            std::printf("Header[%zu] %.*s: %.*s\n", idx, static_cast<int>(lname - fname), fname,
                        static_cast<int>(lval - fval), fval);
#endif
            res[idx] = {fval, lval};
        } else {
            // field is not of interest - skip
            for (; crlf != crlfcrlf && !(CRLF(crlf)); ++crlf)
                ;
        }
    }
#pragma pop_macro("CRLF")
}

constexpr auto ct_srt = [] {
    auto res = content_types;
    std::ranges::sort(res, {}, &content_type::ext);
    return res;
}();
constexpr std::array<std::string_view, content_types.size()> ct_ext_srt = [] {
    std::array<std::string_view, content_types.size()> res;
    for (std::size_t i = 0; i < content_types.size(); ++i) {
        res[i] = ct_srt[i].ext;
    }
    return res;
}();
constexpr std::array<std::string_view, content_types.size()> ct_type_srt = [] {
    std::array<std::string_view, content_types.size()> res;
    for (std::size_t i = 0; i < content_types.size(); ++i) {
        res[i] = ct_srt[i].type;
    }
    return res;
}();
constexpr inline auto maxtype =
    *std::ranges::max_element(ct_type_srt, {}, [](const auto &t) { return t.size(); });
using namespace util;
constexpr inline auto nstatichdr =
    cat(http::status_line<200>, std::span<const char, maxtype.size()>{maxtype},
        "Content-Type: \r\nContent-Length:                   \r\n\r\n"_s)
        .size();

route static_impl(const dir_or_ct a0, const ndir_or_fname a1) noexcept
{
    const char *fname;
    char hdrbuf[nstatichdr];
    auto it = &hdrbuf[0];
    it      = std::ranges::copy(cat(status_line<200>, "Content-Type: "_s), it).out;
    if (!(std::bit_cast<uintptr_t>(a0) & 0b111)) {
        fname = a1.fname;
        it    = std::ranges::copy(*a0.ct, it).out;
    } else {
        auto &[buf, uri, _, _, _] = *co_await aio::state;
        if (uri.t != request_uri::abs_path || uri.malicious()) {
            co_await aio::write(cat(status_line<400>, "\r\n"_s));
            co_return;
        }

        std::ranges::copy(a0.dir, buf.data());
        fname     = uri.furi - a1.ndir;
        *uri.luri = '\0';

        auto fext = uri.luri;
        while (fext != uri.furi && fext[-1] != '.')
            --fext;
        const auto lb = std::ranges::lower_bound(ct_ext_srt, std::string_view{fext, uri.luri});
        if (lb != ct_ext_srt.end() && *lb == std::string_view{fext, uri.luri}) {
            it = std::ranges::copy(ct_type_srt[lb - ct_ext_srt.begin()], it).out;
        } else {
            it = std::ranges::copy("application/octet-stream"_s, it).out;
        }
    }
    it            = std::ranges::copy("\r\nContent-Length: "_s, it).out;

    const auto fd = open(fname, O_CLOEXEC);
    if (fd == -1) {
        co_await aio::write(cat(status_line<404>, "\r\n"_s));
        co_return;
    }

    DEFER[fd] { CHECK(== 0, close(fd)); };
    struct stat st;
    CHECK(== 0, fstat(fd, &st));
    if (!S_ISREG(st.st_mode)) {
        co_await aio::write(cat(status_line<403>, "\r\n"_s));
        co_return;
    }
    it = std::to_chars(it, hdrbuf + nstatichdr, st.st_size).ptr;
    it = std::ranges::copy("\r\n\r\n"_s, it).out;

    co_await aio::chain(aio::write(hdrbuf, static_cast<unsigned>(it - hdrbuf)),
                        aio::splice(fd, st.st_size));
};
} // namespace http::detail

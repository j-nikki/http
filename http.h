#pragma once

#include <algorithm>
#include <ranges>
#include <span>

#include "aio.h"
#include "magic_enum.hpp"
#include "util.h"

#ifndef HTTP_DEBUG
#ifndef NDEBUG
#define HTTP_DEBUG 1
#endif
#endif

namespace http
{
enum method { GET, POST, PUT, DELETE, HEAD, OPTIONS, TRACE, CONNECT, PATCH };
namespace detail
{
//
// request URI
//

template <util::string S>
CI bool matches(std::string_view sv) noexcept
{
    if (S.back() == '*') {
        return sv.starts_with(std::string_view{util::head<S.size() - 1, S>});
    } else {
        return sv == std::string_view{S};
    };
}
struct request_uri {
    char *fhost, *lhost;
    char *furi, *luri;
    enum type { asterisk, absolute, abs_path, authority } t;
    CI void set(char *f, char *l) noexcept
    {
        const std::string_view sv{f, l};
#pragma push_macro("SET_FL_SV")
#define SET_FL_SV(F, L, Sv)                                                                        \
    [&](auto &f_, auto &l_, auto sv_) {                                                            \
        f_ = f + std::distance(sv.begin(), sv_.begin());                                           \
        l_ = f_ + sv.size();                                                                       \
    }((F), (L), (Sv))
        if (sv == "*") {
            t = asterisk;
        } else if (sv.starts_with("http://") || sv.starts_with("https://")) {
            t = absolute;
            SET_FL_SV(fhost, lhost, sv.substr(sv.find("://") + 3));
            SET_FL_SV(furi, luri, sv.substr(sv.find('/', 8)));
        } else if (sv.starts_with("/")) {
            t = abs_path;
            SET_FL_SV(furi, luri, sv);
        } else {
            t = authority;
            SET_FL_SV(fhost, lhost, sv);
        }
#pragma pop_macro("SET_FL_SV")
    }
    CI bool malicious() const noexcept
    {
        return t == abs_path && std::string_view{furi, luri}.find("..") != std::string_view::npos;
    }
    template <util::string S>
    CI bool matches() const noexcept
    {
        if constexpr (S.size() == 1 && S[0] == '*') {
            return t == asterisk;
        } else if constexpr (S.size() >= 1 && S[0] == '/') {
            return t == abs_path && detail::matches<S>({furi, luri});
        } else {
            return t == authority && detail::matches<S>({fhost, lhost});
        }
    }
};

//
// coroutines
//

static constexpr auto nbuf = 8192uz;
struct task_state {
    std::array<char, nbuf> buf;
    request_uri uri;
    char *crlf, *crlfcrlf;
    method mtd;
};
using task =
    aio::detail::task<aio::detail::policy<void, task_state>{.stack = aio::stack_policy::none}>;
using route =
    aio::detail::task<aio::detail::policy<void, task_state *, decltype([](task_state &ts) {
                                              return &ts;
                                          })>{.stack = aio::stack_policy::return_}>;

//
// route store
//

template <class T>
concept route_factory = callable<T, route>;
template <std::size_t I>
struct store {
    template <method M, util::string S, route_factory F>
    struct writer {
        static constexpr auto method_ = M;
        static constexpr auto path    = S;
        using handler                 = F;
        CI bool matches(method m, const request_uri &uri) const noexcept
        {
            return m == M && uri.matches<S>();
        }
#if HTTP_DEBUG
        void print_info() const noexcept
        {
            const auto mtd_name = magic_enum::enum_name<M>();
            std::printf("Route[%zu] %.*s %.*s\n", I, static_cast<int>(mtd_name.size()),
                        mtd_name.data(), static_cast<int>(S.size()), S.data());
        }
#endif
        friend consteval auto get(store) { return writer{}; }
    };
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-template-friend"
    friend consteval auto get(store);
#pragma GCC diagnostic pop
};
template <method M, util::string S>
struct factory {
    template <std::size_t I = 0uz, route_factory F>
    CI auto operator=(F &&f) const
    {
        if constexpr (requires { get(store<I>{}); }) {
            return operator= <I + 1>(static_cast<F &&>(f));
        } else {
            typename store<I>::writer<M, S, F>{};
        }
    }
};

//
// status line
//

consteval std::string_view status_phrases(std::size_t status) noexcept
{
    // https://www.w3.org/Protocols/rfc2616/rfc2616-sec6.html#sec6.1.1
    switch (status) {
    case 100: return "Continue";
    case 101: return "Switching Protocols";
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 203: return "Non-Authoritative Information";
    case 204: return "No Content";
    case 205: return "Reset Content";
    case 206: return "Partial Content";
    case 300: return "Multiple Choices";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 305: return "Use Proxy";
    case 307: return "Temporary Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 402: return "Payment Required";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 406: return "Not Acceptable";
    case 407: return "Proxy Authentication Required";
    case 408: return "Request Time-out";
    case 409: return "Conflict";
    case 410: return "Gone";
    case 411: return "Length Required";
    case 412: return "Precondition Failed";
    case 413: return "Request Entity Too Large";
    case 414: return "Request-URI Too Large";
    case 415: return "Unsupported Media Type";
    case 416: return "Requested range not satisfiable";
    case 417: return "Expectation Failed";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Time-out";
    case 505: return "HTTP Version not supported";
    default: std::unreachable();
    }
}
template <std::size_t S>
constexpr inline auto status_line = [] {
    using util::operator""_s;
    constexpr std::array code{'0' + S / 100, '0' + S / 10 % 10, '0' + S % 10};
    constexpr auto phrase = status_phrases(S);
    return cat("HTTP/1.1 "_s, code, " "_s, std::span<const char, phrase.size()>{phrase}, "\r\n"_s);
}();

//
// serve logic
//

template <auto GetRoute>
constexpr inline auto serve = [] static noexcept -> task {
    using util::operator""_s;
    using util::findd;
    using std::operator""sv;

    // parse the header as follows:
    //   <method> sp1 <uri> sp2 <version> crlf
    //   (<header-field> crlf)...
    //   crlf
    auto &[buf, uri, crlf, crlfcrlf, mtd] = co_await aio::state;
    for (auto idx = 0uz;;) {
        auto spn = std::span{buf}.subspan(idx);
        idx += CHECKN(co_await aio::read(spn));
        auto it = std::ranges::search(spn, "\r\n\r\n"sv).begin();
        if (it != spn.end()) {
            crlfcrlf = &*it;
            break;
        } else if (idx == buf.size()) {
            co_await aio::write(cat(status_line<413>, "\r\n"_s));
            co_return;
        }
    }
    for (crlf = buf.data(); crlf[0] != '\r' || crlf[1] != '\n'; ++crlf)
        ;
    const auto frqln = buf.data();
    const auto lrqln = crlf;
    char *sp1, *sp2;
    if (!(sp1 = findd<' '>(frqln, lrqln)) || !(sp2 = findd<' '>(sp1 + 1, lrqln))) {
        co_await aio::write(cat(status_line<400>, "\r\n"_s));
        co_return;
    }
    const auto mtd_opt = magic_enum::enum_cast<method>(std::string_view{frqln, sp1});
    if (!mtd_opt) {
        co_await aio::write(cat(status_line<501>, "\r\n"_s));
        co_return;
    }
    mtd = *mtd_opt;
    if (util::index<"HTTP/1.0", "HTTP/1.1">(sp2 + 1, lrqln) == 2) {
        co_await aio::write(cat(status_line<505>, "\r\n"_s));
        co_return;
    }
    uri.set(sp1 + 1, sp2);
#if HTTP_DEBUG
#pragma push_macro("STRFMT")
#define STRFMT(F, L) , static_cast<int>((L) - (F)), (F)
    std::printf("Method: %.*s\nURI: %.*s\nVersion: %.*s\n" STRFMT(frqln, sp1) STRFMT(sp1 + 1, sp2)
                    STRFMT(sp2 + 1, lrqln));
#pragma pop_macro("STRFMT")
#endif

    // invoke the route that matches the method and uri
    co_await GetRoute(mtd, uri);
};

//
// build
//

template <auto NRoutes = 0uz>
CI auto build_impl() noexcept
{
    using util::operator""_s;
    static constexpr auto npos = std::string_view::npos;
#if HTTP_DEBUG
    std::printf("#routes: %zu\n", NRoutes);
#endif
    return serve<[]<std::size_t I = 0>(this auto &&self, method m, request_uri &uri) -> route {
        if constexpr (I == NRoutes) {
            return [] -> route { co_await aio::write(cat(status_line<404>, "\r\n"_s)); }();
        } else {
            const auto r = get(store<I>{});
            if (r.matches(m, uri)) {
#if HTTP_DEBUG
                r.print_info();
#endif
                return typename std::remove_cvref_t<decltype(r)>::handler{}();
            } else {
                return self.template operator()<I + 1>(m, uri);
            }
        }
    }>;
}
template <std::size_t I = 0, auto = [] {}>
CI auto build()
{
    if constexpr (requires { get(store<I>{}); }) {
        return build<I + 1>();
    } else {
        return build_impl<I>();
    }
}
} // namespace detail

template <util::string S>
constexpr inline detail::factory<GET, S> get;
template <util::string S>
constexpr inline detail::factory<POST, S> post;
template <util::string S>
constexpr inline detail::factory<PUT, S> put;
template <util::string S>
constexpr inline detail::factory<DELETE, S> delete_;
template <util::string S>
constexpr inline detail::factory<HEAD, S> head;
template <util::string S>
constexpr inline detail::factory<OPTIONS, S> options;
template <util::string S>
constexpr inline detail::factory<TRACE, S> trace;
template <util::string S>
constexpr inline detail::factory<CONNECT, S> connect;
template <util::string S>
constexpr inline detail::factory<PATCH, S> patch;

using detail::build;
using detail::route;
using detail::status_line;

} // namespace http

//
// headers
//

namespace http
{
namespace detail
{
template <util::string... Ss>
struct headers_res : std::array<std::string_view, sizeof...(Ss)> {
    static constexpr std::tuple ss_lc{([](auto s) {
        for (auto &c : s) {
            const auto num = static_cast<unsigned char>(c - 'A');
            c              = (num <= 'Z' - 'A') ? 'a' + num : c;
        }
        return s;
    })(Ss)...};
    static constexpr auto svs_idx = []<std::size_t... Is>(std::index_sequence<Is...>) {
        std::array res{std::pair{
            std::string_view{std::get<Is>(ss_lc).data(), std::get<Is>(ss_lc).size()}, Is}...};
        std::ranges::sort(res);
        std::array<std::size_t, sizeof...(Ss)> idx{};
        for (auto i = 0uz; i < res.size(); ++i)
            idx[res[i].second] = i;
        return std::pair{std::array{res[Is].first...}, idx};
    }(std::make_index_sequence<sizeof...(Ss)>{});
    static constexpr auto &svs = svs_idx.first;  // sorted string views
    static constexpr auto &idx = svs_idx.second; // original index to sorted index
    template <std::size_t I>
    CI std::string_view get() const noexcept
    {
        return (*this)[idx[I]];
    }
};

// stores fields of interest into res
void headers_impl(const std::size_t nss, std::string_view *const res,
                  const std::string_view *const ss, char *crlf, char *const crlfcrlf) noexcept;

template <util::string... Ss>
struct headers_awaitable : std::suspend_always {
    headers_res<Ss...> res_{};
    bool await_suspend(auto &h) noexcept
    {
        auto &[_, _, crlf, crlfcrlf, _] = *h.promise().state_;
        constexpr auto &ss_srt          = headers_res<Ss...>::svs;
        headers_impl(sizeof...(Ss), res_.data(), ss_srt.data(), crlf, crlfcrlf);
        return false;
    }
    headers_res<Ss...> await_resume() const noexcept { return res_; }
};
template <util::string... Ss>
struct headers_proxy {
    CI headers_awaitable<Ss...> awaitable() const noexcept { return {}; }
};
} // namespace detail
template <util::string... Ss>
constexpr inline detail::headers_proxy<Ss...> headers;
} // namespace http

template <util::string... Ss>
struct std::tuple_size<http::detail::headers_res<Ss...>>
    : std::integral_constant<std::size_t, sizeof...(Ss)> {};
template <std::size_t I, util::string... Ss>
struct std::tuple_element<I, http::detail::headers_res<Ss...>> {
    using type = std::string_view;
};

//
// static
//

namespace http
{
namespace detail
{
struct content_type {
    std::string_view ext;
    std::string_view type;
};
static constexpr std::array content_types{
    content_type{"html", "text/html"},
    content_type{"css", "text/css"},
    content_type{"js", "application/javascript"},
    content_type{"png", "image/png"},
    content_type{"jpeg", "image/jpeg"},
    content_type{"gif", "image/gif"},
    content_type{"ico", "image/x-icon"},
    content_type{"svg", "image/svg+xml"},
    content_type{"pdf", "application/pdf"},
    content_type{"json", "application/json"},
    content_type{"xml", "application/xml"},
    content_type{"zip", "application/zip"},
    content_type{"tar", "application/x-tar"},
    content_type{"gz", "application/gzip"},
    content_type{"bz2", "application/x-bzip2"},
    content_type{"7z", "application/x-7z-compressed"},
    content_type{"rar", "application/x-rar-compressed"},
    content_type{"mp3", "audio/mpeg"},
    content_type{"wav", "audio/wav"},
    content_type{"ogg", "audio/ogg"},
    content_type{"mp4", "video/mp4"},
    content_type{"webm", "video/webm"},
    content_type{"avi", "video/x-msvideo"},
    content_type{"mpeg", "video/mpeg"},
    content_type{"webp", "image/webp"},
    content_type{"woff", "font/woff"},
    content_type{"woff2", "font/woff2"},
    content_type{"ttf", "font/ttf"},
    content_type{"otf", "font/otf"},
    content_type{"eot", "application/vnd.ms-fontobject"},
    content_type{"svg", "image/svg+xml"},
};
union dir_or_ct {
    std::array<char, 4> dir;
    const std::string_view *ct;
};
union ndir_or_fname {
    std::size_t ndir;
    const char *fname;
};
route static_impl(const dir_or_ct a0, const ndir_or_fname a1) noexcept;
template <util::string Dir>
struct static_proxy {
    CI route operator()() const noexcept
    {
        static constexpr auto dir = cat(std::array<char, 4 - Dir.size()>{}, Dir);
        return static_impl({.dir = dir}, {.ndir = Dir.size()});
    }
};
template <util::string Name>
struct file_proxy {
    CI route operator()() const noexcept
    {
        static constexpr auto sv  = std::string_view{Name};
        static constexpr auto ext = sv.substr(sv.find_last_of('.') + 1);
        alignas(std::max(alignof(std::string_view), 8uz)) static constexpr auto ct =
            std::ranges::find(content_types, ext, &content_type::ext)->type;
        static constexpr auto cstr = util::c_str<Name>;
        return static_impl({.ct = &ct}, {.fname = cstr.data()});
    }
};
} // namespace detail
template <util::string Dir>
    requires(Dir.size() > 0 &&
             Dir.size() <= 4) // we modify buffer in-place, smallest is "GET " (4 characters)
constexpr inline detail::static_proxy<Dir> static_;
template <util::string Name>
constexpr inline detail::file_proxy<Name> file;
} // namespace http

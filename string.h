#include <concepts>
#include <iterator>
#include <string_view>

namespace util
{
template <std::size_t N>
struct string : std::array<char, N> {
    constexpr string(const char (&str)[N + 1]) noexcept : std::array<char, N>{}
    {
        for (auto i = 0uz; i < N; ++i) {
            (*this)[i] = str[i];
        }
    }
};
template <std::size_t N>
string(const char (&)[N]) -> string<N - 1>;

template <string S>
constexpr auto operator""_s() noexcept -> decltype(S)
{
    return S;
}

template <auto... Cs, std::forward_iterator I>
constexpr inline I find(I f, std::sentinel_for<I> auto l) noexcept
{
    while (f != l) {
        if ((... || (*f == Cs))) {
            return f;
        }
        ++f;
    }
    return f;
}

template <auto... Cs, std::forward_iterator I>
    requires std::default_initializable<I>
constexpr inline I findd(I f, std::sentinel_for<I> auto l) noexcept
{
    while (f != l) {
        if ((... || (*f == Cs))) {
            return f;
        }
        ++f;
    }
    return I{};
}

template <string... Ss, class... SvArgs>
    requires(requires(SvArgs... args) { std::string_view{args...}; })
constexpr inline std::size_t index(SvArgs... args) noexcept
{
    static constexpr std::array svs{std::string_view{Ss.data(), Ss.size()}...};
    for (auto i = 0uz; i < svs.size(); ++i) {
        if (svs[i] == std::string_view{args...}) {
            return i;
        }
    }
    return sizeof...(Ss);
}

template <class T>
concept catable = requires(T t) {
    { *std::begin(t) } -> std::convertible_to<char>;
    std::size(t);
};
constexpr inline auto cat(catable auto &&...ss) noexcept
{
    std::array<char, (std::size(ss) + ...)> c{};
    auto it = c.begin();
    (
        [&it](const auto &s) {
            for (char c : s)
                *it++ = c;
        }(ss),
        ...);
    return c;
}

template <auto X, auto Ys>
constexpr inline auto index_of = [] {
    for (auto i = 0uz; i < Ys.size(); ++i) {
        if (Ys[i] == X) {
            return i;
        }
    }
    return Ys.size();
}();

template <auto N, auto Ys>
constexpr inline auto head =
    []<size_t... Is>(std::index_sequence<Is...>) -> std::array<std::decay_t<decltype(Ys[0])>, N> {
    return {Ys[Is]...};
}(std::make_index_sequence<N>());

template <auto N, auto Ys>
constexpr inline auto drop = []<size_t... Is>(
    std::index_sequence<Is...>) -> std::array<std::decay_t<decltype(Ys[0])>, sizeof...(Is)>
{
    return {Ys[N + Is]...};
}
(std::make_index_sequence<sizeof(Ys) - N>());

template <auto X, auto Ys>
constexpr inline auto take_until = head<index_of<X, Ys>, Ys>;

template <auto X, auto Ys>
constexpr inline auto strip_until = drop<index_of<X, Ys> + 1, Ys>;

template <auto Xs>
constexpr inline auto c_str = []<size_t... Is>(
    std::index_sequence<Is...>) -> std::array<std::decay_t<decltype(Xs[0])>, sizeof...(Is) + 1>
{
    return {Xs[Is]..., static_cast<decltype(Xs[0])>('\0')};
}
(std::make_index_sequence<sizeof(Xs) / sizeof(Xs[0])>());
} // namespace util

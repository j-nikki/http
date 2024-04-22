#pragma once

#include <array>
#include <stdio.h>
#include <stdlib.h>
#include <utility>

template <class T, class R, class... Args>
concept callable = requires(T t) {
    { t(std::declval<Args>()...) } -> std::same_as<R>;
};

namespace util::impl
{
template <class F>
struct defer_t {
    F f;
    ~defer_t() { f(); }
};

struct defer_factory {
    template <class F>
    defer_t<F> operator=(F &&f) const
    {
        return {static_cast<F &&>(f)};
    }
};
} // namespace util::impl

#define DEFER const auto CAT(defer_, __LINE__) = ::util::impl::defer_factory{} =

namespace util
{
template <class Tpl, class F>
constexpr inline void for_each(Tpl &&tpl, F &&f) noexcept
{
    [&f]<std::size_t... Is>(Tpl &&tpl, std::index_sequence<Is...>) {
        (f(std::get<Is>(static_cast<Tpl &&>(tpl))), ...);
    }(static_cast<Tpl &&>(tpl),
      std::make_index_sequence<std::tuple_size_v<std::remove_cvref_t<Tpl>>>{});
}

template <class Tpl, class F>
constexpr inline void for_each_enum(Tpl &&tpl, F &&f) noexcept
{
    [&f]<std::size_t... Is>(Tpl &&tpl, std::index_sequence<Is...>) {
        (f(std::integral_constant<std::size_t, Is>{}, std::get<Is>(static_cast<Tpl &&>(tpl))), ...);
    }(static_cast<Tpl &&>(tpl),
      std::make_index_sequence<std::tuple_size_v<std::remove_cvref_t<Tpl>>>{});
}

struct empty {};
} // namespace util

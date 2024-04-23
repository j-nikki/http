#pragma once

#include <arpa/inet.h>
#include <coroutine>
#include <liburing.h>
#include <stdlib.h>
#include <string.h>
#include <tuple>

#ifndef AIO_DEBUG
#ifndef NDEBUG
#define AIO_DEBUG 1
#endif
#endif

#if __INTELLISENSE__
#define AIO_PEM_PREFIX "."
#endif

#if AIO_DEBUG
#include <source_location>
#endif

#ifdef AIO_PEM_PREFIX
#ifndef AIO_TLS
#define AIO_TLS 1
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#endif
#elifdef AIO_TLS
#error "AIO_TLS requires AIO_PEM_PREFIX"
#endif

#include "macro.h"
#include "string.h"
#include "util.h"

namespace aio
{
enum class stack_policy {
    none,    // we submit close SQE -> main loop destroys us
    return_, // we destroy awaiter and submit close SQE -> main loop destroys us
    jump,    // like return_, except we destroy awaiter eagerly
    call     // we resume awaiter
};
namespace detail
{
const inline auto accept_data    = reinterpret_cast<void *>(static_cast<uintptr_t>(0));
const inline auto nonresume_data = reinterpret_cast<void *>(static_cast<uintptr_t>(1));

//
// coroutine object
//

template <class Value, class State = util::empty, class StateInit = void>
struct policy {
    stack_policy stack = stack_policy::none;
    using state_type   = State;     // user-defined state
    using state_init   = StateInit; // user-defined state initializer
    using value_type   = Value;     // user-defined return value
};
template <policy P>
struct task_promise;
template <policy P>
struct task : std::coroutine_handle<task_promise<P>> {
    using promise_type = task_promise<P>;
    using state_type   = decltype(P)::state_type;
    using state_init   = decltype(P)::state_init;
    using value_type   = decltype(P)::value_type;
    constexpr bool await_ready() const noexcept
        requires(P.stack != stack_policy::none)
    {
        return false;
    }
    template <policy P2>
    void await_suspend(std::coroutine_handle<task_promise<P2>> h) noexcept
        requires(P.stack != stack_policy::none)
    {
        this->promise().caller_ = h;
        this->promise().ring    = h.promise().ring;
        this->promise().sockfd  = h.promise().sockfd;
        if constexpr (!std::is_void_v<state_init>) {
            if constexpr (requires { state_init{}(); })
                this->promise().state_ = state_init{}();
            else
                this->promise().state_ = state_init{}(h.promise().state_);
        }
        if constexpr (P.stack == stack_policy::jump)
            h.destroy();
        this->resume();
    }
    INLINE value_type await_resume() const noexcept
        requires(P.stack != stack_policy::none)
    {
#if AIO_TLS
        CHECKE(== nullptr, this->promise().ssl);
#endif
        if constexpr (P.stack != stack_policy::call)
            std::unreachable();
        if constexpr (!std::is_void_v<value_type>)
            return static_cast<value_type &&>(this->promise().value_);
    }
    INLINE state_type &state() noexcept
        requires(!std::is_same_v<state_type, util::empty>)
    {
        return this->promise().state_;
    }
};

//
// coroutine promise
//

template <policy P>
struct final_awaitable;
using result_t = decltype(io_uring_cqe::res);
struct opaque_task_promise {
#if AIO_TLS
    WOLFSSL *ssl DBGS(= nullptr);
#endif
    io_uring *ring;
    result_t result;
    int sockfd;
};
using opaque_task_handle = std::coroutine_handle<opaque_task_promise>;
template <class T>
struct value_store {
    T value_;
    constexpr void return_value(T &&v) noexcept { value_ = static_cast<T &&>(v); }
};
template <>
struct value_store<void> {
    constexpr void return_void() const noexcept {}
};
template <policy P>
struct task_promise : opaque_task_promise, value_store<typename decltype(P)::value_type> {
    [[no_unique_address]] decltype(P)::state_type state_;
    [[no_unique_address]] std::conditional_t<P.stack != stack_policy::none, std::coroutine_handle<>,
                                             util::empty> caller_;
#if AIO_DEBUG
    task_promise(std::source_location sl = std::source_location::current()) noexcept
    {
        printf("\033[1m%s:%d:\033[0m\n", sl.file_name(), sl.line());
        printf("\033[1m%p new\033[0m\n", task<P>::from_promise(*this).address());
    }
    ~task_promise() noexcept
    {
#if AIO_TLS
        DBGE(CHECK(== nullptr, ssl));
#endif
        printf("\033[1m%p delete\033[0m\n", task<P>::from_promise(*this).address());
    }
#endif
    task<P> get_return_object() noexcept { return {task<P>::from_promise(*this)}; }
    std::suspend_always initial_suspend() const noexcept { return {}; }
    final_awaitable<P> final_suspend() noexcept;
    auto await_transform(auto &&) noexcept;
    [[noreturn]] void unhandled_exception() const noexcept { exit(1); }
};

//
// final_awaitable
//

template <policy P>
struct final_awaitable : std::suspend_always {
    void await_suspend(std::coroutine_handle<task_promise<P>> h) noexcept
    {
        auto &p = h.promise();
        if constexpr (P.stack != stack_policy::call) {
            auto sqe = io_uring_get_sqe(p.ring);
            io_uring_prep_close(sqe, p.sockfd);
            io_uring_sqe_set_data(sqe, nonresume_data);
            io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
            io_uring_submit(p.ring);
        }
        if constexpr (P.stack == stack_policy::return_) {
            p.caller_.destroy();
        }
        if constexpr (P.stack == stack_policy::call) {
            const auto caller_ = p.caller_;
            h.destroy();
            caller_.resume();
        } else {
            h.destroy();
        }
    }
};
template <policy P>
inline final_awaitable<P> task_promise<P>::final_suspend() noexcept
{
    return {};
}

//
// state
//

template <policy P>
struct state_awaitable : std::suspend_always {
    std::coroutine_handle<task_promise<P>> h_;
    bool await_suspend(std::coroutine_handle<task_promise<P>> h) noexcept
    {
        h_ = h;
        return false;
    }
    decltype(P)::state_type &await_resume() noexcept { return h_.promise().state_; }
};
constexpr inline struct state_t {
} state;

//
// chain
//

template <class T>
concept chain_op = callable<T, void, opaque_task_promise &, io_uring_sqe *>;

template <class Ops, class Eops>
struct chain_awaitable;
template <chain_op... Ops, chain_op... EOps>
struct chain_awaitable<std::tuple<Ops...>, std::tuple<EOps...>> {
    [[no_unique_address]] std::tuple<Ops...> ops_;
    [[no_unique_address]] std::tuple<EOps...> eops_;
    [[no_unique_address]] std::conditional_t<sizeof...(EOps) != 0, opaque_task_promise *,
                                             util::empty> p_;
    result_t *result_;
    constexpr bool await_ready() const noexcept { return false; }
    template <policy P>
    void await_suspend(std::coroutine_handle<task_promise<P>> h) noexcept
    {
        auto &p = h.promise();
        if constexpr (sizeof...(EOps)) {
            p_ = &static_cast<opaque_task_promise &>(p);
        }
        result_ = &p.result;
        if constexpr (sizeof...(Ops)) {
            util::for_each_enum(std::move(ops_), [&]<class Op>(auto i, Op &&op) {
                const auto sqe = io_uring_get_sqe(p.ring);
                static_cast<Op &&>(op)(p, sqe);
                if constexpr (i + 1 < sizeof...(Ops)) {
                    io_uring_sqe_set_data(sqe, nonresume_data);
                    io_uring_sqe_set_flags(sqe, IOSQE_IO_HARDLINK | IOSQE_CQE_SKIP_SUCCESS);
                } else {
                    io_uring_sqe_set_data(sqe, h.address());
                }
            });
            io_uring_submit(p.ring);
        }
    }
    CI result_t await_resume() noexcept
    {
        if constexpr (sizeof...(EOps)) {
            util::for_each(std::move(eops_), [&]<class Op>(Op &&op) {
                const auto sqe = io_uring_get_sqe(p_->ring);
                static_cast<Op &&>(op)(*p_, sqe);
                io_uring_sqe_set_data(sqe, nonresume_data);
                io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
            });
            io_uring_submit(p_->ring);
        }
        return *result_;
    }
};
template <chain_op... Ops, chain_op... EOps>
chain_awaitable(std::tuple<Ops...>,
                std::tuple<EOps...>) -> chain_awaitable<std::tuple<Ops...>, std::tuple<EOps...>>;

template <class... Tpls>
[[nodiscard]] CI auto chain(Tpls &&...tpls) noexcept
{
    return chain_awaitable{std::tuple_cat(std::get<0>(static_cast<Tpls &&>(tpls))...),
                           std::tuple_cat(std::get<1>(static_cast<Tpls &&>(tpls))...)};
}

template <policy P>
template <class T>
INLINE auto task_promise<P>::await_transform(T &&t) noexcept
{
    if constexpr (std::is_same_v<T, const state_t &>)
        return state_awaitable<P>{};
    else if constexpr (requires { t.await_ready(); })
        return static_cast<T &&>(t);
    else if constexpr (requires { t.awaitable(); })
        return t.awaitable();
    else
        return chain(static_cast<T &&>(t));
}

//
// read
//

[[nodiscard]] CI auto read(void *buf, unsigned nbytes) noexcept
{
    return std::tuple{std::tuple{[=](auto &p, io_uring_sqe *sqe) {
                          io_uring_prep_read(sqe, p.sockfd, buf, nbytes, 0);
                      }},
                      std::tuple{}};
}

template <class T>
concept read_source = requires(T t) {
    { t.data() } -> std::convertible_to<void *>;
    { t.size() } -> std::convertible_to<unsigned int>;
} && sizeof(std::declval<T>().data()[0]) == 1;
[[nodiscard]] CI auto read(read_source auto &&src)
{
    return read(static_cast<void *>(src.data()), static_cast<unsigned int>(src.size()));
}

//
// write
//

[[nodiscard]] CI auto write(const void *buf, unsigned nbytes) noexcept
{
    return std::tuple{std::tuple{[=](auto &p, io_uring_sqe *sqe) {
                          io_uring_prep_write(sqe, p.sockfd, buf, nbytes, 0);
                      }},
                      std::tuple{}};
}

template <class T>
concept write_destination = requires(T t) {
    { t.data() } -> std::convertible_to<const void *>;
    { t.size() } -> std::convertible_to<unsigned int>;
} && sizeof(std::declval<T>().data()[0]) == 1;
[[nodiscard]] CI auto write(write_destination auto &&dst) noexcept
{
    return write(static_cast<const void *>(dst.data()), static_cast<unsigned int>(dst.size()));
}

//
// splice
//

[[nodiscard]] INLINE auto splice(int fd_in, unsigned int nbytes) noexcept
{
    int pipefds[2];
    CHECK(!= -1, pipe2(pipefds, O_CLOEXEC | O_NONBLOCK));
    const auto op1 = [=, fd = pipefds[1]](auto &p, io_uring_sqe *sqe) {
        io_uring_prep_splice(sqe, fd_in, 0, fd, -1, nbytes, SPLICE_F_NONBLOCK);
    };
    const auto op2 = [=, fd = pipefds[0]](auto &p, io_uring_sqe *sqe) {
        io_uring_prep_splice(sqe, fd, -1, p.sockfd, -1, nbytes, SPLICE_F_NONBLOCK);
    };
    const auto eop1 = [=, fd = pipefds[1]](auto &p, io_uring_sqe *sqe) {
        io_uring_prep_close(sqe, fd);
    };
    const auto eop2 = [=, fd = pipefds[0]](auto &p, io_uring_sqe *sqe) {
        io_uring_prep_close(sqe, fd);
    };
    return std::tuple{std::tuple{op1, op2}, std::tuple{eop1, eop2}};
}

inline void add_accept_request(io_uring *const ring, const int server_socket,
                               sockaddr_in *const client_addr, socklen_t *const client_addr_len)
{
    const auto sqe = io_uring_get_sqe(ring);
    io_uring_prep_accept(sqe, server_socket, reinterpret_cast<sockaddr *>(client_addr),
                         client_addr_len, 0);
    io_uring_sqe_set_data(sqe, accept_data);
    io_uring_submit(ring);
}

int setup_listening_socket(const char *ipno, const int port) noexcept;

class accept_socket
{
  public:
    CI accept_socket(int sock) noexcept : sock_{sock} {}
    INLINE accept_socket(const char *ipno, const int port) noexcept
        : sock_{detail::setup_listening_socket(ipno, port)}
    {
    }
    CI operator int() const noexcept { return sock_; }

  private:
    const int sock_;
};

#if AIO_TLS
template <int ZeroRet, auto Op>
int bio(WOLFSSL *ssl, char *buf, int sz, void *ctx) noexcept
{
    auto &p = *static_cast<opaque_task_promise *>(ctx);
    if (p.result) {
        if (p.result < 0) [[unlikely]] {
            switch (-p.result) {
            case EPIPE: return WOLFSSL_CBIO_ERR_CONN_CLOSE;
            default: return WOLFSSL_CBIO_ERR_GENERAL;
            }
        }
        auto res = p.result;
        p.result = 0;
        return res;
    }
    const auto sqe = io_uring_get_sqe(p.ring);
    Op(sqe, p.sockfd, buf, sz);
    io_uring_sqe_set_data(sqe, opaque_task_handle::from_promise(p).address());
    io_uring_submit(p.ring);
    return ZeroRet;
}

INLINE void report_handshake_fail(unsigned long err)
{
    char buf[80];
    fprintf(stderr, "TLS handshake failed with error %lu: %s\n", err,
            wolfSSL_ERR_error_string(err, buf));
}

enum class handshake_result {
    done,
    retry,
    error,
};
INLINE handshake_result handshake(opaque_task_promise &p) noexcept
{
    if (const auto acres = wolfSSL_accept_TLSv13(p.ssl); acres == SSL_SUCCESS) {
        return handshake_result::done;
    } else {
        switch (const auto res = wolfSSL_get_error(p.ssl, acres); res) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE: return handshake_result::retry;
        default: report_handshake_fail(res); return handshake_result::error;
        }
    }
}

bool setup_ktls(opaque_task_promise &p) noexcept;
#endif

[[noreturn]] static void serve_loop(io_uring *const ring, const accept_socket server_socket,
                                    auto &&spawn)
{
    // after accepting a connection:
    // 1. spawn a suspended coroutine
    // 2. perform a TLS handshake
    // 3. relay crypto info to kernel
    // 4. resume the coroutine
    signal(SIGPIPE, SIG_IGN);
    sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    add_accept_request(ring, server_socket, &client_addr, &client_addr_len);
#if AIO_TLS
    const auto wm = CHECKE(!= nullptr, wolfSSLv23_server_method());
    const auto wc = CHECKE(!= nullptr, wolfSSL_CTX_new(wm));
    DEFER[=] { wolfSSL_CTX_free(wc); };
    CHECKE(== SSL_SUCCESS,
           wolfSSL_CTX_use_PrivateKey_file(wc, AIO_PEM_PREFIX "/pkey.pem", SSL_FILETYPE_PEM));
    CHECKE(== SSL_SUCCESS,
           wolfSSL_CTX_use_certificate_file(wc, AIO_PEM_PREFIX "/cert.pem", SSL_FILETYPE_PEM));
    wolfSSL_CTX_SetIORecv(
        wc, &bio<WOLFSSL_CBIO_ERR_WANT_READ, [](io_uring_sqe *sqe, int sockfd, char *buf, int sz) {
            io_uring_prep_read(sqe, sockfd, buf, sz, 0);
        }>);
    wolfSSL_CTX_SetIOSend(
        wc, &bio<WOLFSSL_CBIO_ERR_WANT_WRITE, [](io_uring_sqe *sqe, int sockfd, char *buf, int sz) {
            io_uring_prep_write(sqe, sockfd, buf, sz, 0);
        }>);
#endif
    for (io_uring_cqe *cqe;; io_uring_cqe_seen(ring, cqe)) {
        CHECKN(io_uring_wait_cqe(ring, &cqe));
        const auto data = io_uring_cqe_get_data(cqe);
        if (data == accept_data) {
            CHECKN(cqe->res);
            add_accept_request(ring, server_socket, &client_addr, &client_addr_len);
            auto t                 = spawn();
            opaque_task_promise &p = t.promise();
            p.ring                 = ring;
            p.sockfd               = cqe->res;
#if AIO_TLS
            p.ssl    = CHECKE(!= nullptr, wolfSSL_new(wc));
            p.result = 0;
            CHECK(== SSL_SUCCESS, wolfSSL_set_cipher_list(p.ssl, "TLS_AES_128_GCM_SHA256"));
            CHECK(== SSL_SUCCESS, wolfSSL_set_fd(p.ssl, p.sockfd));
            wolfSSL_SetIOReadCtx(p.ssl, &p);
            wolfSSL_SetIOWriteCtx(p.ssl, &p);
            switch (const auto hd = handshake(p)) {
            case handshake_result::retry: continue;
            case handshake_result::error:
                wolfSSL_free(p.ssl);
                p.ssl = nullptr;
                t.destroy();
                continue;
            default: std::unreachable();
            }
#else
            t.resume();
#endif
        } else if (data == nonresume_data) [[unlikely]] {
            CHECKE(< 0, cqe->res);
            fprintf(stderr, "nonresuming operation failed: %s\n", strerror(-cqe->res));
        } else {
            auto h  = opaque_task_handle::from_address(data);
            auto &p = h.promise();
            CHECKE(== false, h.done());
            p.result = cqe->res;
#if AIO_TLS
            if (p.ssl) {
                switch (const auto hd = handshake(p)) {
                case handshake_result::retry: continue;
                case handshake_result::error: {
                    bool err;
                    err = true;
                    if (0) {
                    case handshake_result::done: err = !setup_ktls(p);
                    }
                    wolfSSL_free(p.ssl);
                    p.ssl = nullptr;
                    if (!err)
                        break;
                    h.destroy();
                    continue;
                }
                default: std::unreachable();
                }
            }
#endif
            h.resume();
        }
    }
}

struct uring_opts {
    unsigned int entries;
    unsigned int flags;
};

template <class Spawn, class Key = decltype([] {})>
[[noreturn]] static void serve_loop(uring_opts opts, accept_socket &&server_socket, Spawn &&spawn)
{
    io_uring ring;
    static io_uring *s_ring = &ring;
    signal(
        SIGINT, +[](int signo) {
            printf("^C pressed. Shutting down.\n");
            io_uring_queue_exit(s_ring);
            exit(0);
        });
    io_uring_queue_init(opts.entries, &ring, opts.flags);
    serve_loop(&ring, static_cast<accept_socket &&>(server_socket), static_cast<Spawn &&>(spawn));
}
} // namespace detail
template <class R = void>
using task = detail::task<detail::policy<R>{.stack = stack_policy::none}>;
template <class R = void>
using subtask = detail::task<detail::policy<R>{.stack = stack_policy::call}>;

using detail::chain;
using detail::read;
using detail::serve_loop;
using detail::splice;
using detail::state;
using detail::write;
} // namespace aio

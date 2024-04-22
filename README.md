# server

This is a work-in-progress C++ project with two central files:

- `aio.h` provides facilities for asynchronous I/O in C++
- `http.h` is an HTTP request parser and response generator

## aio

`aio.h` uses io_uring for queueing I/O tasks and waits for their completion in a main loop. When a coroutine submits an I/O task, it will associate the SQE with the coroutine. Upon receiving an CQE, it resumes the associated coroutine.

```cpp
#include "aio.h"
std::string_view hdr400 = "HTTP/1.0 400 Bad Request\r\nContent-Type: text/html\r\n\r\n";
int main() {
    aio::serve_loop({256, 0}, {"127.0.0.1", 8080}, [] -> aio::task {
        std::array<char, READ_SZ> buf;
        auto n = co_await aio::read(buf);
        printf(".....\nread result: %d\n", n);
        printf("%.*s%s", n, buf.data(), !n || buf[n - 1] != '\n' ? "\033[7m%\033[0m\n" : "");

        const auto fd = open("400.html", 0);
        DEFER[fd] { CHECK(== 0, close(fd)); };

        struct stat st;
        CHECK(== 0, fstat(fd, &st));

        n = co_await aio::chain(aio::write(hdr400), aio::splice(fd, st.st_size));
        printf(".....\nchain result: %d\n", n);
    });
}
```

## http

`http.h` uses the facilities provided by `aio.h` for the purpose of HTTP request parsing and response generation. Note that it uses stateful metapgrogramming via friend injection, a "feature" which might be subject to removal.

```cpp
#include "http.h"
int main()
{
    using namespace util;
    http::get<"/">           = http::file<"dist/index.html">;
    http::get<"/*">          = http::static_<"dist">;
    http::get<"/admin.html"> = [] -> http::route {
        const auto [auth, accept] = co_await http::headers<"Authorization", "Accept">;
        if (auth != "test") {
            co_await aio::write(cat(http::status_line<401>,
                                    "WWW-Authenticate: Basic realm=\"Secure Area\"\r\n\r\n"_s));
            co_return;
        }
        co_await aio::write(cat(http::status_line<200>, "Content-type: text/html\r\n\r\n"_s,
                                "<html><body><h1>Admin</h1></body></html>"_s));
    };
    aio::serve_loop({256, 0}, {"127.0.0.1", 8080}, http::build());
}
```

#include "aio.h"
#include "http.h"
#include "util.h"

#define PORT        8888
#define QUEUE_DEPTH 256
#define READ_SZ     8192

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
    aio::serve_loop({QUEUE_DEPTH, 0}, {"127.0.0.1", PORT}, http::build());
}

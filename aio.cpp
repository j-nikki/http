#include "aio.h"

int aio::detail::setup_listening_socket(const char *ipno, const int port) noexcept
{
    const auto sock = CHECK(!= -1, socket(PF_INET, SOCK_STREAM, 0));

    int enable      = 1;
    CHECK(>= 0, setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)));

    sockaddr_in srv_addr{
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr   = {0},
        .sin_zero   = {0},
    };

    CHECK(== 1, inet_pton(AF_INET, ipno, &srv_addr.sin_addr));

    CHECK(>= 0, bind(sock, (const struct sockaddr *)&srv_addr, sizeof(srv_addr)));

    CHECK(>= 0, listen(sock, 10));

    return sock;
}

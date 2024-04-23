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

#if AIO_TLS
bool aio::detail::setup_ktls(opaque_task_promise &p) noexcept
{
    const auto nkey = wolfSSL_GetKeySize(p.ssl);
    CHECK(== 0, setsockopt(p.sockfd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")));

    tls12_crypto_info_aes_gcm_128 ci;
    ci.info.version     = TLS_1_3_VERSION;
    ci.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    uint64_t seq;
    wolfSSL_GetSequenceNumber(p.ssl, &seq);
    seq      = htobe64(seq);

    auto key = (wolfSSL_GetSide(p.ssl) == WOLFSSL_CLIENT_END) ? wolfSSL_GetClientWriteKey(p.ssl)
                                                              : wolfSSL_GetServerWriteKey(p.ssl);
    auto iv  = (wolfSSL_GetSide(p.ssl) == WOLFSSL_CLIENT_END) ? wolfSSL_GetClientWriteIV(p.ssl)
                                                              : wolfSSL_GetServerWriteIV(p.ssl);

    memcpy(ci.key, key, nkey);
    memcpy(ci.salt, iv, 4);
    memcpy(ci.iv, (iv + 4), 8);
    memcpy(ci.rec_seq, &seq, sizeof(seq));
    CHECK(== 0, setsockopt(p.sockfd, SOL_TLS, TLS_TX, &ci, sizeof(ci)));

    key = (wolfSSL_GetSide(p.ssl) == WOLFSSL_CLIENT_END) ? wolfSSL_GetServerWriteKey(p.ssl)
                                                         : wolfSSL_GetClientWriteKey(p.ssl);
    iv  = (wolfSSL_GetSide(p.ssl) == WOLFSSL_CLIENT_END) ? wolfSSL_GetServerWriteIV(p.ssl)
                                                         : wolfSSL_GetClientWriteIV(p.ssl);
    memcpy(ci.key, key, nkey);
    memcpy(ci.salt, iv, 4);
    memcpy(ci.iv, (iv + 4), 8);
    memcpy(ci.rec_seq, &seq, sizeof(seq));
    CHECK(== 0, setsockopt(p.sockfd, SOL_TLS, TLS_RX, &ci, sizeof(ci)));

    return true;
}
#endif

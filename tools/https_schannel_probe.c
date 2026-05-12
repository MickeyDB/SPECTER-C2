#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <schannel.h>
#include <security.h>
#include <stdio.h>
#include <string.h>

static int send_all(SOCKET s, const unsigned char *buf, int len) {
    int off = 0;
    while (off < len) {
        int n = send(s, (const char *)buf + off, len - off, 0);
        if (n <= 0) return 0;
        off += n;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "www.microsoft.com";
    const char *path = argc > 2 ? argv[2] : "/";
    const char *port = "443";

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *res = NULL;
    int gai = getaddrinfo(host, port, &hints, &res);
    if (gai != 0 || !res) {
        printf("getaddrinfo failed: %d\n", gai);
        return 2;
    }

    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        freeaddrinfo(res);
        return 3;
    }

    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        printf("connect failed: %d\n", WSAGetLastError());
        freeaddrinfo(res);
        closesocket(sock);
        return 4;
    }
    freeaddrinfo(res);
    printf("tcp connected to %s:443\n", host);

    SCHANNEL_CRED cred;
    memset(&cred, 0, sizeof(cred));
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
    cred.dwFlags = SCH_USE_STRONG_CRYPTO;

    CredHandle hcred;
    SECURITY_STATUS ss = AcquireCredentialsHandleA(
        NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &hcred, NULL);
    if (ss != SEC_E_OK) {
        printf("AcquireCredentialsHandleA failed: 0x%08lx\n", (unsigned long)ss);
        return 5;
    }

    CtxtHandle hctx;
    memset(&hctx, 0, sizeof(hctx));
    int have_ctx = 0;
    unsigned long attrs = 0;
    unsigned long flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                          ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
                          ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION;
    unsigned char inbuf[32768];
    unsigned long in_used = 0;

    SecBuffer outb = {0, SECBUFFER_TOKEN, NULL};
    SecBufferDesc outd = {SECBUFFER_VERSION, 1, &outb};
    ss = InitializeSecurityContextA(&hcred, NULL, (SEC_CHAR *)host, flags, 0, 0,
                                    NULL, 0, &hctx, &outd, &attrs, NULL);
    if (ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_OK) {
        printf("Initial ISC failed: 0x%08lx\n", (unsigned long)ss);
        return 6;
    }
    have_ctx = 1;
    if (outb.cbBuffer && outb.pvBuffer) {
        if (!send_all(sock, (const unsigned char *)outb.pvBuffer, (int)outb.cbBuffer)) {
            printf("send client hello failed\n");
            return 7;
        }
        FreeContextBuffer(outb.pvBuffer);
    }

    while (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE) {
        int n = recv(sock, (char *)inbuf + in_used, (int)(sizeof(inbuf) - in_used), 0);
        if (n <= 0) {
            printf("handshake recv failed: %d\n", WSAGetLastError());
            return 8;
        }
        in_used += (unsigned long)n;

        SecBuffer ib[2];
        ib[0].cbBuffer = in_used;
        ib[0].BufferType = SECBUFFER_TOKEN;
        ib[0].pvBuffer = inbuf;
        ib[1].cbBuffer = 0;
        ib[1].BufferType = SECBUFFER_EMPTY;
        ib[1].pvBuffer = NULL;
        SecBufferDesc id = {SECBUFFER_VERSION, 2, ib};

        outb.cbBuffer = 0;
        outb.BufferType = SECBUFFER_TOKEN;
        outb.pvBuffer = NULL;
        outd.cBuffers = 1;
        outd.pBuffers = &outb;
        ss = InitializeSecurityContextA(&hcred, &hctx, (SEC_CHAR *)host, flags, 0, 0,
                                        &id, 0, NULL, &outd, &attrs, NULL);
        if (outb.cbBuffer && outb.pvBuffer) {
            if (!send_all(sock, (const unsigned char *)outb.pvBuffer, (int)outb.cbBuffer)) {
                printf("send handshake token failed\n");
                return 9;
            }
            FreeContextBuffer(outb.pvBuffer);
        }
        if (ib[1].BufferType == SECBUFFER_EXTRA && ib[1].cbBuffer > 0) {
            memmove(inbuf, inbuf + (in_used - ib[1].cbBuffer), ib[1].cbBuffer);
            in_used = ib[1].cbBuffer;
        } else if (ss != SEC_E_INCOMPLETE_MESSAGE) {
            in_used = 0;
        }
        if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_INCOMPLETE_MESSAGE) {
            printf("ISC loop failed: 0x%08lx\n", (unsigned long)ss);
            return 10;
        }
    }
    if (!have_ctx || ss != SEC_E_OK) {
        printf("TLS handshake did not complete: 0x%08lx\n", (unsigned long)ss);
        return 11;
    }
    printf("tls handshake OK\n");

    SecPkgContext_StreamSizes sizes;
    ss = QueryContextAttributesA(&hctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
    if (ss != SEC_E_OK) {
        printf("QueryContextAttributesA failed: 0x%08lx\n", (unsigned long)ss);
        return 12;
    }

    char req[2048];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, host);
    unsigned char sendbuf[8192];
    if ((unsigned long)req_len + sizes.cbHeader + sizes.cbTrailer > sizeof(sendbuf)) {
        printf("request too large\n");
        return 13;
    }

    memcpy(sendbuf + sizes.cbHeader, req, (size_t)req_len);
    SecBuffer sb[4];
    sb[0].cbBuffer = sizes.cbHeader; sb[0].BufferType = SECBUFFER_STREAM_HEADER; sb[0].pvBuffer = sendbuf;
    sb[1].cbBuffer = (unsigned long)req_len; sb[1].BufferType = SECBUFFER_DATA; sb[1].pvBuffer = sendbuf + sizes.cbHeader;
    sb[2].cbBuffer = sizes.cbTrailer; sb[2].BufferType = SECBUFFER_STREAM_TRAILER; sb[2].pvBuffer = sendbuf + sizes.cbHeader + req_len;
    sb[3].cbBuffer = 0; sb[3].BufferType = SECBUFFER_EMPTY; sb[3].pvBuffer = NULL;
    SecBufferDesc sd = {SECBUFFER_VERSION, 4, sb};
    ss = EncryptMessage(&hctx, 0, &sd, 0);
    if (ss != SEC_E_OK) {
        printf("EncryptMessage failed: 0x%08lx\n", (unsigned long)ss);
        return 14;
    }
    int enc_len = (int)(sb[0].cbBuffer + sb[1].cbBuffer + sb[2].cbBuffer);
    if (!send_all(sock, sendbuf, enc_len)) {
        printf("send encrypted request failed\n");
        return 15;
    }
    printf("encrypted request sent (%d bytes plaintext)\n", req_len);

    unsigned long data_in = 0;
    for (;;) {
        int n = recv(sock, (char *)inbuf + data_in, (int)(sizeof(inbuf) - data_in), 0);
        if (n <= 0) {
            printf("recv closed before decrypted response\n");
            return 16;
        }
        data_in += (unsigned long)n;
        SecBuffer rb[4];
        rb[0].cbBuffer = data_in; rb[0].BufferType = SECBUFFER_DATA; rb[0].pvBuffer = inbuf;
        rb[1].cbBuffer = 0; rb[1].BufferType = SECBUFFER_EMPTY; rb[1].pvBuffer = NULL;
        rb[2].cbBuffer = 0; rb[2].BufferType = SECBUFFER_EMPTY; rb[2].pvBuffer = NULL;
        rb[3].cbBuffer = 0; rb[3].BufferType = SECBUFFER_EMPTY; rb[3].pvBuffer = NULL;
        SecBufferDesc rd = {SECBUFFER_VERSION, 4, rb};
        ss = DecryptMessage(&hctx, &rd, 0, NULL);
        if (ss == SEC_E_INCOMPLETE_MESSAGE) continue;
        if (ss != SEC_E_OK && ss != SEC_I_CONTEXT_EXPIRED) {
            printf("DecryptMessage failed: 0x%08lx\n", (unsigned long)ss);
            return 17;
        }
        for (int i = 0; i < 4; i++) {
            if (rb[i].BufferType == SECBUFFER_DATA && rb[i].cbBuffer > 0) {
                unsigned long out = rb[i].cbBuffer < 512 ? rb[i].cbBuffer : 512;
                fwrite(rb[i].pvBuffer, 1, out, stdout);
                printf("\n");
                printf("https probe OK, decrypted %lu bytes\n", rb[i].cbBuffer);
                return 0;
            }
        }
    }
}

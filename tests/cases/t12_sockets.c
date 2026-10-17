/* t12: Winsock over host sockets — in-guest TCP server + client roundtrip
 * on 127.0.0.1, with select() (Windows fd_set layout) and nonblocking IO. */
#include <winsock2.h>
#include <stdio.h>
#include <string.h>

static void ferr(const char *what)
{
    printf("T12 FAIL %s (wsa=%d)\n", what, WSAGetLastError());
}

int main(void)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { ferr("startup"); return 1; }

    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) { ferr("socket"); return 2; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(19999);
    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) != 0) { ferr("bind"); return 3; }
    if (listen(srv, 1) != 0) { ferr("listen"); return 4; }

    SOCKET cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (cli == INVALID_SOCKET) { ferr("cli socket"); return 5; }
    if (connect(cli, (struct sockaddr *)&addr, sizeof addr) != 0) { ferr("connect"); return 6; }

    /* Nonblocking accept via select with the WINSOCK fd_set layout. */
    u_long one = 1;
    ioctlsocket(srv, FIONBIO, &one);
    fd_set rs;
    FD_ZERO(&rs);
    FD_SET(srv, &rs);
    struct timeval tv = { 2, 0 };
    int sel = select(0, &rs, NULL, NULL, &tv);
    if (sel != 1 || !FD_ISSET(srv, &rs)) { ferr("select"); return 7; }
    SOCKET conn = accept(srv, NULL, NULL);
    if (conn == INVALID_SOCKET) { ferr("accept"); return 8; }

    if (send(cli, "PING", 4, 0) != 4) { ferr("send"); return 9; }
    char buf[32] = { 0 };
    int r = recv(conn, buf, sizeof buf - 1, 0);
    if (r != 4 || strcmp(buf, "PING") != 0) { ferr("recv"); return 10; }

    send(conn, "PONG", 4, 0);
    memset(buf, 0, sizeof buf);
    r = recv(cli, buf, sizeof buf - 1, 0);
    if (r != 4 || strcmp(buf, "PONG") != 0) { ferr("roundtrip"); return 11; }

    closesocket(conn);
    closesocket(cli);
    closesocket(srv);
    WSACleanup();
    puts("T12 SOCKETS OK");
    return 0;
}

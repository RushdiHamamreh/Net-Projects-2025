#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 5000
#define HEADER_SIZE 16

int main() {
    WSADATA wsa;
    SOCKET serverSock, clientSock;
    struct sockaddr_in server, client;
    int c, fileCounter = 1;

    printf("Starting TCP Voice Server...\n");

    WSAStartup(MAKEWORD(2,2), &wsa);

    // Create socket
    serverSock = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;   // Listen to any device on the LAN
    server.sin_port = htons(PORT);

    // Bind
    bind(serverSock, (struct sockaddr *)&server, sizeof(server));

    // Listen
    listen(serverSock, 3);

    printf("Server is running. Waiting for clients...\n");

    c = sizeof(struct sockaddr_in);

    while (1) {
        clientSock = accept(serverSock, (struct sockaddr *)&client, &c);
        printf("\nClient connected!\n");

        // Receive file size header
        char headerBuf[HEADER_SIZE + 1];
        int readBytes = recv(clientSock, headerBuf, HEADER_SIZE, 0);
        if (readBytes <= 0) {
            printf("Client failed.\n");
            closesocket(clientSock);
            continue;
        }
        headerBuf[HEADER_SIZE] = '\0';
        int fileSize = atoi(headerBuf);

        printf("Incoming voice file (%d bytes)...\n", fileSize);

        // Create output filename
        char filename[50];
        sprintf(filename, "received_%d.wav", fileCounter++);
        FILE *fp = fopen(filename, "wb");

        // Receive file data
        int totalReceived = 0;
        char buffer[4096];

        while (totalReceived < fileSize) {
            int n = recv(clientSock, buffer, sizeof(buffer), 0);
            if (n <= 0) break;

            fwrite(buffer, 1, n, fp);
            totalReceived += n;
        }

        fclose(fp);
        closesocket(clientSock);

        printf("Saved: %s (%d bytes)\n", filename, totalReceived);
        printf("Waiting for next client...\n");
    }

    closesocket(serverSock);
    WSACleanup();
    return 0;
}

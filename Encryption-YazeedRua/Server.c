// server.c
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 12345
#define BUFFER_SIZE 4096

// MUST match client key (32 bytes for AES-256)
unsigned char KEY[] = "ThisIsA32ByteLongSecretKey123456";

// Helper: send all data (even if in chunks)
int send_all(SOCKET sock, const unsigned char* data, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(sock, (const char*)(data + sent), len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

// Helper: receive exactly n bytes
int recv_all(SOCKET sock, unsigned char* buf, int n) {
    int received = 0;
    while (received < n) {
        int r = recv(sock, (char*)(buf + received), n - received, 0);
        if (r <= 0) return -1;
        received += r;
    }
    return 0;
}

// Encrypt using AES-256-GCM
int encrypt_aes_gcm(const unsigned char* plaintext, int plaintext_len,
                    unsigned char* ciphertext, unsigned char* tag, unsigned char* nonce) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto fail;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) goto fail;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, KEY, nonce)) goto fail;

    int len;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) goto fail;
    int ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) goto fail;
    ciphertext_len += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) goto fail;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;

fail:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int main() {
    WSADATA wsa;
    SOCKET server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[-] WSAStartup failed\n");
        return 1;
    }

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("[-] Socket creation failed\n");
        WSACleanup();
        return 1;
    }

    // Set socket options (reuse address)
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        printf("[-] setsockopt failed\n");
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) == SOCKET_ERROR) {
        printf("[-] Bind failed\n");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    // Listen
    if (listen(server_fd, 1) == SOCKET_ERROR) {
        printf("[-] Listen failed\n");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    printf("[+] Server listening on port %d...\n", PORT);

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) == INVALID_SOCKET) {
            printf("[-] Accept failed\n");
            continue;
        }

        printf("[+] Connection accepted\n");

        // === Receive filename ===
        unsigned char fname_len_bytes[4];
        if (recv_all(new_socket, fname_len_bytes, 4) < 0) {
            printf("[-] Failed to receive filename length\n");
            closesocket(new_socket);
            continue;
        }
        int fname_len = (fname_len_bytes[0] << 24) |
                        (fname_len_bytes[1] << 16) |
                        (fname_len_bytes[2] << 8) |
                        fname_len_bytes[3];

        if (fname_len <= 0 || fname_len > 256) {
            printf("[-] Invalid filename length\n");
            closesocket(new_socket);
            continue;
        }

        unsigned char* filename = malloc(fname_len + 1);
        if (!filename) {
            printf("[-] Memory allocation failed\n");
            closesocket(new_socket);
            continue;
        }
        if (recv_all(new_socket, filename, fname_len) < 0) {
            printf("[-] Failed to receive filename\n");
            free(filename);
            closesocket(new_socket);
            continue;
        }
        filename[fname_len] = '\0';
        printf("[+] Filename: %s\n", filename);

        // === Receive file size ===
        unsigned char file_size_bytes[8];
        if (recv_all(new_socket, file_size_bytes, 8) < 0) {
            printf("[-] Failed to receive file size\n");
            free(filename);
            closesocket(new_socket);
            continue;
        }
        long long file_size = ((long long)file_size_bytes[0] << 56) |
                              ((long long)file_size_bytes[1] << 48) |
                              ((long long)file_size_bytes[2] << 40) |
                              ((long long)file_size_bytes[3] << 32) |
                              ((long long)file_size_bytes[4] << 24) |
                              ((long long)file_size_bytes[5] << 16) |
                              ((long long)file_size_bytes[6] << 8) |
                              ((long long)file_size_bytes[7]);

        if (file_size <= 0 || file_size > 100000000) { // 100 MB limit
            printf("[-] Invalid file size\n");
            free(filename);
            closesocket(new_socket);
            continue;
        }

        // === Receive file data ===
        unsigned char* file_data = malloc(file_size);
        if (!file_data) {
            printf("[-] Memory allocation failed\n");
            free(filename);
            closesocket(new_socket);
            continue;
        }
        if (recv_all(new_socket, file_data, file_size) < 0) {
            printf("[-] Failed to receive file data\n");
            free(filename);
            free(file_data);
            closesocket(new_socket);
            continue;
        }

        printf("[+] Received file '%s' (%lld bytes)\n", filename, file_size);

        // === Encrypt ===
        unsigned char nonce[12];
        if (!RAND_bytes(nonce, 12)) {
            printf("[-] Failed to generate nonce\n");
            free(filename);
            free(file_data);
            closesocket(new_socket);
            continue;
        }

        unsigned char* ciphertext = malloc(file_size + 16); // +16 for tag
        unsigned char tag[16];
        int ciphertext_len = encrypt_aes_gcm(file_data, file_size, ciphertext, tag, nonce);
        if (ciphertext_len < 0) {
            printf("[-] Encryption failed\n");
            free(filename);
            free(file_data);
            free(ciphertext);
            closesocket(new_socket);
            continue;
        }

        // Encrypted format: [12 nonce][ciphertext][16 tag]
        long long enc_total_size = 12 + ciphertext_len + 16;
        unsigned char* encrypted_full = malloc(enc_total_size);
        if (!encrypted_full) {
            free(filename);
            free(file_data);
            free(ciphertext);
            closesocket(new_socket);
            continue;
        }
        memcpy(encrypted_full, nonce, 12);
        memcpy(encrypted_full + 12, ciphertext, ciphertext_len);
        memcpy(encrypted_full + 12 + ciphertext_len, tag, 16);

        // === Send back encrypted size (8 bytes) ===
        unsigned char enc_size_bytes[8];
        enc_size_bytes[0] = (enc_total_size >> 56) & 0xFF;
        enc_size_bytes[1] = (enc_total_size >> 48) & 0xFF;
        enc_size_bytes[2] = (enc_total_size >> 40) & 0xFF;
        enc_size_bytes[3] = (enc_total_size >> 32) & 0xFF;
        enc_size_bytes[4] = (enc_total_size >> 24) & 0xFF;
        enc_size_bytes[5] = (enc_total_size >> 16) & 0xFF;
        enc_size_bytes[6] = (enc_total_size >> 8) & 0xFF;
        enc_size_bytes[7] = enc_total_size & 0xFF;

        if (send_all(new_socket, enc_size_bytes, 8) < 0 ||
            send_all(new_socket, encrypted_full, enc_total_size) < 0) {
            printf("[-] Failed to send encrypted data\n");
        } else {
            printf("[+] Encrypted file sent back (%lld bytes)\n", enc_total_size);
        }

        // Cleanup
        free(filename);
        free(file_data);
        free(ciphertext);
        free(encrypted_full);
        closesocket(new_socket);
    }

    closesocket(server_fd);
    WSACleanup();
    return 0;
}
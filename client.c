#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mmsystem.h>
#include <stdio.h>
#include <conio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")

#define SAMPLE_RATE 44100
#define BITS_PER_SAMPLE 16
#define CHANNELS 1
#define PORT 5000
#define HEADER_SIZE 16

void writeWavHeader(FILE *fp, int dataSize) {
    int chunkSize = 36 + dataSize;
    int subchunk1Size = 16;
    short audioFormat = 1;
    short numChannels = CHANNELS;
    int sampleRate = SAMPLE_RATE;
    short bitsPerSample = BITS_PER_SAMPLE;
    short blockAlign = numChannels * bitsPerSample / 8;
    int byteRate = sampleRate * blockAlign;

    fwrite("RIFF", 1, 4, fp);
    fwrite(&chunkSize, 4, 1, fp);
    fwrite("WAVEfmt ", 1, 8, fp);
    fwrite(&subchunk1Size, 4, 1, fp);
    fwrite(&audioFormat, 2, 1, fp);
    fwrite(&numChannels, 2, 1, fp);
    fwrite(&sampleRate, 4, 1, fp);
    fwrite(&byteRate, 4, 1, fp);
    fwrite(&blockAlign, 2, 1, fp);
    fwrite(&bitsPerSample, 2, 1, fp);
    fwrite("data", 1, 4, fp);
    fwrite(&dataSize, 4, 1, fp);
}

int main() {
    while (1) {
        printf("\nPress ENTER to start recording, or Q to quit: ");
        int c = getch();
        if (c == 'q' || c == 'Q') break;

        printf("\nRecording... Press ENTER again to stop.\n");

        HWAVEIN hWaveIn;
        WAVEFORMATEX waveFormat;
        WAVEHDR header;
        int bufferSize = SAMPLE_RATE * CHANNELS * (BITS_PER_SAMPLE/8) * 10; // 10 seconds buffer chunks
        char *buffer = malloc(bufferSize);

        waveFormat.wFormatTag = WAVE_FORMAT_PCM;
        waveFormat.nChannels = CHANNELS;
        waveFormat.nSamplesPerSec = SAMPLE_RATE;
        waveFormat.wBitsPerSample = BITS_PER_SAMPLE;
        waveFormat.nBlockAlign = CHANNELS * BITS_PER_SAMPLE / 8;
        waveFormat.nAvgBytesPerSec = SAMPLE_RATE * waveFormat.nBlockAlign;
        waveFormat.cbSize = 0;

        waveInOpen(&hWaveIn, WAVE_MAPPER, &waveFormat, 0, 0, CALLBACK_NULL);

        header.lpData = buffer;
        header.dwBufferLength = bufferSize;
        header.dwFlags = 0;
        header.dwLoops = 1;

        waveInPrepareHeader(hWaveIn, &header, sizeof(WAVEHDR));
        waveInAddBuffer(hWaveIn, &header, sizeof(WAVEHDR));

        waveInStart(hWaveIn);

        // Wait for ENTER to stop recording
        while (!kbhit());
        getch(); // clear

        waveInStop(hWaveIn);
        waveInUnprepareHeader(hWaveIn, &header, sizeof(WAVEHDR));
        waveInClose(hWaveIn);

        FILE *fp = fopen("record.wav", "wb");
        writeWavHeader(fp, header.dwBytesRecorded);
        fwrite(buffer, 1, header.dwBytesRecorded, fp);
        fclose(fp);

        free(buffer);

        printf("Saved voice as record.wav (%d bytes)\n", header.dwBytesRecorded);

        // ---------------- SEND TO SERVER -------------------

        WSADATA wsa;
        SOCKET sock;
        struct sockaddr_in server;
        char header16[HEADER_SIZE + 1];

        FILE *f = fopen("record.wav", "rb");
        fseek(f, 0, SEEK_END);
        int fileSize = ftell(f);
        fseek(f, 0, SEEK_SET);

        printf("File size = %d bytes\n", fileSize);

        WSAStartup(MAKEWORD(2, 2), &wsa);

        sock = socket(AF_INET, SOCK_STREAM, 0);

        char ip[50];
        printf("Enter Server IP: ");
        scanf("%s", ip);

        server.sin_family = AF_INET;
        server.sin_port = htons(PORT);
        server.sin_addr.s_addr = inet_addr(ip);

        connect(sock, (struct sockaddr *)&server, sizeof(server));

        snprintf(header16, HEADER_SIZE, "%-16d", fileSize);
        send(sock, header16, HEADER_SIZE, 0);

        char fileBuffer[4096];
        int n;
        while ((n = fread(fileBuffer, 1, sizeof(fileBuffer), f)) > 0) {
            send(sock, fileBuffer, n, 0);
        }

        fclose(f);
        closesocket(sock);
        WSACleanup();

        printf("Voice sent successfully!\n");
    }

    return 0;
}

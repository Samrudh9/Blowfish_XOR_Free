#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char BYTE;


uint32_t F(uint32_t x, uint32_t key) {
    return (x + key); // Addition Only (MOD 2^32 automatically)
}


void encrypt_block(uint32_t *L, uint32_t *R, uint32_t key) {
    for (int i = 0; i < 8; i++) {
        uint32_t f = F(*R, key);

        // MAIN MODIFICATION
        *L = *L ^ f;  

        // Feistel Swap
        uint32_t temp = *L;
        *L = *R;
        *R = temp;
    }
}

/* ---------- DECRYPT (XOR-Free Reversible) ---------- */
void decrypt_block(uint32_t *L, uint32_t *R, uint32_t key) {
    for (int i = 7; i >= 0; i--) {

        // Feistel Swap (reverse order)
        uint32_t temp = *R;
        *R = *L;
        *L = temp;

        uint32_t f = F(*R, key);

        *L = *L ^ f;
    }
}

/* ---------- File Encrypt ---------- */
void encrypt_file(const char *inFile, const char *outFile, uint32_t key) {
    FILE *in = fopen(inFile, "rb");
    FILE *out = fopen(outFile, "wb");

    if (!in || !out) {
        printf("Error opening files!\n");
        return;
    }

    BYTE buffer[8];
    size_t data;

    while ((data = fread(buffer, 1, 8, in)) > 0) {
        if (data < 8) {
            for (size_t i = data; i < 8; i++)
                buffer[i] = 0; // Padding
        }

        uint32_t L = (buffer[0]<<24)|(buffer[1]<<16)|(buffer[2]<<8)|buffer[3];
        uint32_t R = (buffer[4]<<24)|(buffer[5]<<16)|(buffer[6]<<8)|buffer[7];

        encrypt_block(&L, &R, key);

        buffer[0] = L>>24; buffer[1] = L>>16; buffer[2] = L>>8; buffer[3] = L;
        buffer[4] = R>>24; buffer[5] = R>>16; buffer[6] = R>>8; buffer[7] = R;

        fwrite(buffer, 1, 8, out);
    }

    fclose(in);
    fclose(out);
    printf("Encryption Done Successfully!\n");
}

/* ---------- File Decrypt ---------- */
void decrypt_file(const char *inFile, const char *outFile, uint32_t key) {
    FILE *in = fopen(inFile, "rb");
    FILE *out = fopen(outFile, "wb");

    if (!in || !out) {
        printf("Error opening files!\n");
        return;
    }

    BYTE buffer[8];
    size_t data;

    while ((data = fread(buffer, 1, 8, in)) > 0) {
        uint32_t L = (buffer[0]<<24)|(buffer[1]<<16)|(buffer[2]<<8)|buffer[3];
        uint32_t R = (buffer[4]<<24)|(buffer[5]<<16)|(buffer[6]<<8)|buffer[7];

        decrypt_block(&L, &R, key);

        buffer[0] = L>>24; buffer[1] = L>>16; buffer[2] = L>>8; buffer[3] = L;
        buffer[4] = R>>24; buffer[5] = R>>16; buffer[6] = R>>8; buffer[7] = R;

        fwrite(buffer, 1, 8, out);
    }

    fclose(in);
    fclose(out);
    printf("Decryption Done Successfully!\n");
}

/* ---------- MAIN MENU ---------- */
int main() {
    int choice;
    char input[100], output[100];
    uint32_t key;

    while (1) {
        printf("\n=== XOR-Free Blowfish Style Cipher ===\n");
        printf("1. Encrypt File\n");
        printf("2. Decrypt File\n");
        printf("3. Exit\n");
        printf("Enter choice: ");
        scanf("%d", &choice);

        if (choice == 3) break;

        printf("Enter input file: ");
        scanf("%s", input);
        printf("Enter output file: ");
        scanf("%s", output);
        printf("Enter key (integer): ");
        scanf("%u", &key);

        if (choice == 1)
            encrypt_file(input, output, key);
        else if (choice == 2)
            decrypt_file(input, output, key);
        else
            printf("Invalid choice!\n");
    }

    return 0;
}


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define ROUNDS     16
#define BLOCK_SIZE  8

static const uint32_t P_INIT[ROUNDS + 2] = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B
};
uint32_t P[ROUNDS + 2];
uint32_t S[4][256];
void encrypt_block(uint32_t *L, uint32_t *R);

uint32_t schonhage_mod_mul(uint32_t a, uint32_t b) {
    if (a == 0) a = 1;
    if (b == 0) b = 1;

    uint64_t product = (uint64_t)a * (uint64_t)b;
    uint32_t low  = (uint32_t)(product & 0xFFFFFFFF);
    uint32_t high = (uint32_t)(product >> 32);

    if (low >= high)
        return low - high;
    else
        return low - high + 1;  /* borrow: add modulus 2^32+1 */
}

uint32_t F(uint32_t x) {
    uint8_t a = (x >> 24) & 0xFF;
    uint8_t b = (x >> 16) & 0xFF;
    uint8_t c = (x >>  8) & 0xFF;
    uint8_t d =  x        & 0xFF;

    /* Schonhage modular multiply replaces XOR */
    uint32_t y = schonhage_mod_mul(S[0][a], S[1][b]);
    y = y + S[2][c];
    y = y + S[3][d];
    return y;
}

static const uint32_t PI_SEEDS[4] = {
    0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7
};

void init_sboxes(void) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 256; j++) {
            S[i][j] = PI_SEEDS[i] + (uint32_t)(j * 0x010101) +
                      (uint32_t)(i * 0x1010101);
        }
    }
}

void key_schedule(const uint8_t *key, int key_len) {
    int i, j, k;

    init_sboxes();
    memcpy(P, P_INIT, sizeof(P));  /* reset P to original Pi values */

    /* Mix key bytes into P-array */
    j = 0;
    for (i = 0; i < ROUNDS + 2; i++) {
        uint32_t data = 0;
        for (k = 0; k < 4; k++) {
            data = (data << 8) | key[j % key_len];
            j++;
        }
        P[i] = P[i] + data;
    }

    /* Generate final P-array */
    uint32_t L = 0, R = 0;
    for (i = 0; i < ROUNDS + 2; i += 2) {
        encrypt_block(&L, &R);
        P[i]     = L;
        P[i + 1] = R;
    }

    /* Generate final S-boxes */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 256; j += 2) {
            encrypt_block(&L, &R);
            S[i][j]     = L;
            S[i][j + 1] = R;
        }
    }
}

/*
 * ============================================================
 * ENCRYPT BLOCK (XOR-Free Feistel)
 *
 *   Standard Blowfish per round:
 *     L ^= P[i];  R ^= F(L);  swap(L,R)
 *
 *   XOR-Free version:
 *     L += P[i];  R += F(L);  swap(L,R)
 *
 *   F is applied to L (the modified half), result goes to R.
 *   This ensures F(L) can be recomputed in decrypt because
 *   after reverse-swap, L still holds the same modified value.
 * ============================================================
 */
void encrypt_block(uint32_t *L, uint32_t *R) {
    uint32_t l = *L, r = *R;
    uint32_t t;

    for (int i = 0; i < ROUNDS; i++) {
        l = l + P[i];       /* subkey mixing on L */
        r = r + F(l);       /* F of modified L -> into R */
        t = l; l = r; r = t; /* swap */
    }

    /* Undo last swap */
    t = l; l = r; r = t;

    /* Final whitening */
    r = r + P[ROUNDS];
    l = l + P[ROUNDS + 1];

    *L = l;
    *R = r;
}

void decrypt_block(uint32_t *L, uint32_t *R) {
    uint32_t l = *L, r = *R;
    uint32_t t;

    /* Reverse final whitening */
    l = l - P[ROUNDS + 1];
    r = r - P[ROUNDS];

    /* Reverse the undo-last-swap (= do a swap) */
    t = l; l = r; r = t;

    for (int i = ROUNDS - 1; i >= 0; i--) {
        /* Reverse swap from encrypt */
        t = l; l = r; r = t;

        /* Reverse R += F(L): L still holds A+P[i] */
        r = r - F(l);

        /* Reverse L += P[i] */
        l = l - P[i];
    }

    *L = l;
    *R = r;
}

void encrypt_file(const char *in_path, const char *out_path) {
    FILE *fin = fopen(in_path, "rb");
    FILE *fout = fopen(out_path, "wb");
    if (!fin || !fout) { printf("  Error opening files!\n"); return; }

    uint8_t buf[8];
    size_t n, total = 0;
    while ((n = fread(buf, 1, 8, fin)) > 0) {
        if (n < 8) memset(buf + n, 0, 8 - n);

        uint32_t L = (buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|buf[3];
        uint32_t R = (buf[4]<<24)|(buf[5]<<16)|(buf[6]<<8)|buf[7];
        encrypt_block(&L, &R);
        buf[0]=L>>24; buf[1]=L>>16; buf[2]=L>>8; buf[3]=L;
        buf[4]=R>>24; buf[5]=R>>16; buf[6]=R>>8; buf[7]=R;

        fwrite(buf, 1, 8, fout);
        total += 8;
    }
    fclose(fin); fclose(fout);
    printf("  Encrypted %u bytes -> %s\n", (unsigned)total, out_path);
}

void decrypt_file(const char *in_path, const char *out_path) {
    FILE *fin = fopen(in_path, "rb");
    FILE *fout = fopen(out_path, "wb");
    if (!fin || !fout) { printf("  Error opening files!\n"); return; }

    uint8_t buf[8];
    size_t n, total = 0;
    while ((n = fread(buf, 1, 8, fin)) > 0) {
        uint32_t L = (buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|buf[3];
        uint32_t R = (buf[4]<<24)|(buf[5]<<16)|(buf[6]<<8)|buf[7];
        decrypt_block(&L, &R);
        buf[0]=L>>24; buf[1]=L>>16; buf[2]=L>>8; buf[3]=L;
        buf[4]=R>>24; buf[5]=R>>16; buf[6]=R>>8; buf[7]=R;

        fwrite(buf, 1, 8, fout);
        total += 8;
    }
    fclose(fin); fclose(fout);
    printf("  Decrypted %u bytes -> %s\n", (unsigned)total, out_path);
}
int main() {
    int choice;
    char in_file[256], out_file[256], key_str[256];

    printf("\n");
    printf("  =====================================================\n");
    printf("  |  BLOWFISH - XOR-Free + Schonhage Modular         |\n");
    printf("  |                                                   |\n");
    printf("  |  Feistel: ADD mod 2^32 (no XOR)                  |\n");
    printf("  |  F-func: Schonhage multiply mod (2^32 + 1)       |\n");
    printf("  |  16 rounds, 64-bit block, variable key           |\n");
    printf("  =====================================================\n");

    while (1) {
        printf("\n  1. Encrypt File\n");
        printf("  2. Decrypt File\n");
        printf("  3. Block Demo (verify encrypt/decrypt)\n");
        printf("  4. Schonhage Multiply Demo\n");
        printf("  5. Exit\n");
        printf("  Choice: ");

        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }
        if (choice == 5) break;

        switch (choice) {
        case 1: case 2:
            printf("  Key: "); scanf("%s", key_str);
            key_schedule((uint8_t*)key_str, (int)strlen(key_str));
            printf("  Input file: "); scanf("%s", in_file);
            printf("  Output file: "); scanf("%s", out_file);
            if (choice == 1) encrypt_file(in_file, out_file);
            else             decrypt_file(in_file, out_file);
            break;

        case 3: {
            printf("  Key: "); scanf("%s", key_str);
            key_schedule((uint8_t*)key_str, (int)strlen(key_str));

            uint32_t L = 0x11223344, R = 0x55667788;
            uint32_t oL = L, oR = R;

            printf("\n  Plaintext  : %08X %08X\n", L, R);
            encrypt_block(&L, &R);
            printf("  Ciphertext : %08X %08X\n", L, R);
            decrypt_block(&L, &R);
            printf("  Decrypted  : %08X %08X\n", L, R);
            printf("  Match      : %s\n",
                   (L == oL && R == oR) ? "YES" : "NO - ERROR!");
            break;
        }

        case 4: {
            printf("\n  Schonhage: (a * b) mod (2^32 + 1)\n\n");
            uint32_t pairs[][2] = {
                {0x12345678, 0x9ABCDEF0},
                {0xFFFFFFFF, 0x00000002},
                {0xDEADBEEF, 0xCAFEBABE}
            };
            for (int i = 0; i < 3; i++) {
                uint32_t a = pairs[i][0], b = pairs[i][1];
                printf("  %08X * %08X = %08X\n",
                       a, b, schonhage_mod_mul(a, b));
            }
            break;
        }
        }
    }

    printf("\n  Bye!\n");
    return 0;
}

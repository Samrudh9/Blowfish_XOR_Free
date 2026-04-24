#include <stdio.h>
#include <stdint.h>

/* -----------------------------------------------------
   SIMPLE Blowfish DEMO
   - No full S-boxes
   - No CBC
   - Only 1 block encryption
   - Shows Standard vs XOR-Free version
   - Includes Schönhage Modular Multiply
----------------------------------------------------- */

/* Small dummy S-box values (not real Blowfish S-boxes) */
uint32_t S0[256];
uint32_t S1[256];
uint32_t S2[256];
uint32_t S3[256];

/* Initialize simple S-boxes with repeating pattern */
void init_sboxes() {
    for (int i = 0; i < 256; i++) {
        S0[i] = (i * 13) ^ 0x12345678;
        S1[i] = (i * 7)  ^ 0x87654321;
        S2[i] = (i * 5)  ^ 0x10203040;
        S3[i] = (i * 9)  ^ 0x55667788;
    }
}

/* Schönhage modular multiply: (a*b) mod (2^32 + 1) */
uint32_t schonhage_mod(uint32_t a, uint32_t b) {
    uint64_t prod = (uint64_t)a * (uint64_t)b;

    uint32_t low  = (uint32_t)prod;
    uint32_t high = (uint32_t)(prod >> 32);

    uint32_t res = low - high;
    if (low < high)
        res += 1;

    return res;
}

/* ------------------ Standard Blowfish F function ------------------- */
uint32_t F_standard(uint32_t x) {
    uint8_t a = (x >> 24) & 0xFF;
    uint8_t b = (x >> 16) & 0xFF;
    uint8_t c = (x >> 8)  & 0xFF;
    uint8_t d = x & 0xFF;

    uint32_t y = (S0[a] + S1[b]) ^ S2[c];
    y += S3[d];
    return y;
}

/* ------------------ XOR-Free Blowfish F function ------------------- */
uint32_t F_xorfree(uint32_t x) {
    uint8_t a = (x >> 24) & 0xFF;
    uint8_t b = (x >> 16) & 0xFF;
    uint8_t c = (x >> 8)  & 0xFF;
    uint8_t d = x & 0xFF;

    uint32_t m = schonhage_mod(S0[a], S1[b]);
    uint32_t s = m + S2[c] + S3[d];

    return (s << (d & 31)) | (s >> (32 - (d & 31)));
}

/* ------------------- Standard Blowfish round ----------------------- */
void blowfish_standard(uint32_t *L, uint32_t *R) {
    for (int i = 0; i < 4; i++) {  // simplified: 4 rounds
        *L = *L ^ F_standard(*R);
        uint32_t temp = *L;
        *L = *R;
        *R = temp;
    }
}

/* ------------------- XOR-Free Blowfish round ------------------------ */
void blowfish_xorfree(uint32_t *L, uint32_t *R) {
    for (int i = 0; i < 4; i++) {  // simplified: 4 rounds
        *L = *L + F_xorfree(*R);  // + instead of XOR
        uint32_t temp = *L;
        *L = *R;
        *R = temp;
    }
}

int main() {
    init_sboxes();

    uint32_t L = 0x11223344;
    uint32_t R = 0x55667788;

    uint32_t L2 = L;
    uint32_t R2 = R;

    printf("\n--- SIMPLE BLOWFISH DEMO ---\n");
    printf("Input Block : %08X %08X\n", L, R);

    /* Standard Blowfish */
    blowfish_standard(&L, &R);
    printf("\nStandard Blowfish Output:\n");
    printf("%08X %08X\n", L, R);

    /* XOR-free Blowfish */
    blowfish_xorfree(&L2, &R2);
    printf("\nXOR-Free + Schönhage Blowfish Output:\n");
    printf("%08X %08X\n", L2, R2);

    return 0;
}

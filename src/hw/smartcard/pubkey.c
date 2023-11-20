#include <openssl/bn.h>

#include <stdlib.h>
#include <string.h>

/*
    README: fill PK_N from gpg key (without first zero). Install libssl-dev gcc.
    Compile and run: gcc public.c -o pk -lcrypto ; ./pk
*/

uint8_t PK_N[] = { // NOTE: n of public key
};

int PK_N_SIZE = sizeof(PK_N);

void
print_u32(const char *msg, const uint8_t *data, int u32_count) {
    printf("%s ", msg);

    uint32_t res;
    for (int i = 0; i < u32_count; ++i) {
        res = (data[((u32_count - 1 - i) * 4) + 0] << 24) |
                (data[((u32_count - 1 - i) * 4) + 1] << 16) |
                (data[((u32_count - 1 - i) * 4) + 2] << 8) |
                (data[((u32_count - 1 - i) * 4) + 3] << 0);
        printf("0x%02X, ", res);
    }

    printf("\n\n");
}

int main() {
    BIGNUM *r32 = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *n = BN_new();
    BIGNUM *rr = BN_new();
    BIGNUM *n0inv = BN_new();

    BN_bin2bn(PK_N, PK_N_SIZE, n);

    BN_set_bit(r32, 32);
    BN_mod(n0inv, n, r32, ctx);
    BN_mod_inverse(n0inv, n0inv, r32, ctx);
    BN_sub(n0inv, r32, n0inv);

    printf("PUBKEY_N0INV = 0x%02X\n\n", (uint32_t)BN_get_word(n0inv));

    BN_set_bit(rr, PK_N_SIZE * 8);
    BN_mod_sqr(rr, rr, n, ctx);

    uint8_t pk_rr[PK_N_SIZE];
    BN_bn2bin(rr, pk_rr);

    int u32_count = PK_N_SIZE / sizeof(uint32_t);

    print_u32("PUBKEY_N = ", PK_N, u32_count);
    print_u32("PUBKEY_RR = ", pk_rr, u32_count);

    return 0;
}

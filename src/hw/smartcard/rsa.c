#include "./rsa.h"
#include "./pubkey.h"

#include "string.h"

#define RSANUMBYTES	PUBKEY_SIZE
#define RSANUMWORDS	(RSANUMBYTES / sizeof(u32))

struct rsa_public_key {
    u32 *n;
    u32 *rr;
    u32 n0inv;
};

static void
sub_mod(const struct rsa_public_key *key, u32 *a)
{
    s64 A = 0;
    u32 i;
    for (i = 0; i < RSANUMWORDS; ++i) {
        A += (u64)a[i] - key->n[i];
        a[i] = (u32)A;
        A >>= 32;
    }
}

static int
ge_mod(const struct rsa_public_key *key, const u32 *a)
{
    u32 i;
    for (i = RSANUMWORDS; i;) {
        --i;
        if (a[i] < key->n[i])
            return 0;
        if (a[i] > key->n[i])
            return 1;
    }
    return 1;  /* equal */
}

static u64
mula32(u32 a, u32 b, u32 c) {
    return (u64)a * b + c;
}

static u64
mulaa32(u32 a, u32 b, u32 c, u32 d) {
    return (u64)a * b + c + d;
}

static void mont_mul_add(const struct rsa_public_key *key,
                         u32 *c,
                         const u32 a,
                         const u32 *b)
{
    u64 A = mula32(a, b[0], c[0]);
    u32 d0 = (u32)A * key->n0inv;
    u64 B = mula32(d0, key->n[0], A);
    u32 i;

    for (i = 1; i < RSANUMWORDS; ++i) {
        A = mulaa32(a, b[i], c[i], A >> 32);
        B = mulaa32(d0, key->n[i], A, B >> 32);
        c[i - 1] = (u32)B;
    }

    A = (A >> 32) + (B >> 32);

    c[i - 1] = (u32)A;

    if (A >> 32)
        sub_mod(key, c);
}

static void
mont_mul(const struct rsa_public_key *key,
         u32 *c,
         const u32 *a,
         const u32 *b)
{
    u32 i;
    for (i = 0; i < RSANUMWORDS; ++i)
        c[i] = 0;

    for (i = 0; i < RSANUMWORDS; ++i)
        mont_mul_add(key, c, a[i], b);
}

static void
mod_pow(const struct rsa_public_key *key, u8 *inout,
        u32 *workbuf32)
{
    u32 *a = workbuf32;
    u32 *a_r = a + RSANUMWORDS;
    u32 *aa_r = a_r + RSANUMWORDS;
    u32 *aaa = aa_r;  /* Re-use location. */
    int i;

    /* Convert from big endian byte array to little endian word array. */
    for (i = 0; i < RSANUMWORDS; ++i) {
        u32 tmp =
            (inout[((RSANUMWORDS - 1 - i) * 4) + 0] << 24) |
            (inout[((RSANUMWORDS - 1 - i) * 4) + 1] << 16) |
            (inout[((RSANUMWORDS - 1 - i) * 4) + 2] << 8) |
            (inout[((RSANUMWORDS - 1 - i) * 4) + 3] << 0);
        a[i] = tmp;
    }

    /* TODO(drinkcat): This operation could be precomputed to save time. */
    mont_mul(key, a_r, a, key->rr);  /* a_r = a * RR / R mod M */
/*
#ifdef CONFIG_RSA_EXPONENT_3
        mont_mul(key, aa_r, a_r, a_r);
        mont_mul(key, a, aa_r, a_r);
        mont_mul_1(key, aaa, a);
#else
*/
        /* Exponent 65537 */
    for (i = 0; i < 16; i += 2) {
        mont_mul(key, aa_r, a_r, a_r); /* aa_r = a_r * a_r / R mod M */
        mont_mul(key, a_r, aa_r, aa_r);/* a_r = aa_r * aa_r / R mod M */
    }
    mont_mul(key, aaa, a_r, a);  /* aaa = a_r * a / R mod M */
//#endif

    /* Make sure aaa < mod; aaa is at most 1x mod too large. */
    if (ge_mod(key, aaa))
        sub_mod(key, aaa);

    /* Convert to bigendian byte array */
    for (i = RSANUMWORDS - 1; i >= 0; --i) {
        u32 tmp = aaa[i];
        *inout++ = (u8)(tmp >> 24);
        *inout++ = (u8)(tmp >> 16);
        *inout++ = (u8)(tmp >>  8);
        *inout++ = (u8)(tmp >>  0);
    }
}

static int
check_padding(const u8 *sig, int data_len)
{
    u8 *ptr = (u8 *)sig;
    int result = 0;
    int i;

    /* First 2 bytes are always 0x00 0x01 */
    result |= *ptr++ ^ 0x00;
    result |= *ptr++ ^ 0x01;

    /* Then 0xff bytes until the tail */
    for (i = 0; i < RSANUMBYTES - data_len - 3; i++)
        result |= *ptr++ ^ 0xff;

    result |= *ptr++ ^ 0x00;

    return !!result;
}

static int
rsa_verify_sign(const struct rsa_public_key *key, const u8 *signature,
               const u8 *data, int data_len, u32 *workbuf32)
{
    u8 buf[RSANUMBYTES];

    /* Copy input to local workspace. */
    memcpy(buf, signature, RSANUMBYTES);

    mod_pow(key, buf, workbuf32); /* In-place exponentiation. */

    /* Check the PKCS#1 padding */
    if (check_padding(buf, data_len) != 0)
        return 0;

    /* Check the digest. */
    if (memcmp(buf + RSANUMBYTES - data_len, data, data_len) != 0)
        return 0;

    return 1;  /* All checked out OK. */
}

int
rsa_verify(const u8 *sign, const u8 *data, int data_len) {
    struct rsa_public_key key;
    u32 workbuf32[3 * RSANUMWORDS];

    key.n = PUBKEY_N;
    key.rr = PUBKEY_RR;
    key.n0inv = PUBKEY_N0INV;

    return rsa_verify_sign(&key, sign, data, data_len, workbuf32);
}

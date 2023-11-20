#include "./openpgp.h"

#include "./rsa.h"
#include "./ccid.h"
#include "./hash.h"
#include "./pubkey.h"

#include "util.h"
#include "bregs.h"

#include "string.h"
#include "output.h"

#define KDF_ITERSALTED_S2K	0x03

struct kdf {
    u8 kdf_algo;
    u8 hash_algo;

    u8 salt_len;
    u8 salt[0xFF];

    u32 iterations;
};

static int
is_success(const u8 *data) {
    int ret = is_ccid_success(data, 0x80);

    if (ret) {
        u8 len = data[1] + 8;
        ret = (data[len] == 0x90) && (data[len + 1] == 0x00);
    }

    return ret;
}

int
select_openpgp(void) {
    u8 apdu[] = { 0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00 };
    u8 *r = send_ccid_msg(0x6F, apdu, sizeof(apdu));

    return is_success(r);
}

static int
init_kdf(struct kdf *kdf) {
    u8 apdu[] = { 0x00, 0xCA, 0x00, 0xF9, 0x00 };

    u8 *r = send_ccid_msg(0x6F, apdu, sizeof(apdu));
    int ret = is_success(r);

    if (ret) {
        u32 iterations = r[21];
        iterations += r[20] << 8;
        iterations += r[19] << 16;
        iterations += r[18] << 24;

        kdf->kdf_algo = r[12];
        kdf->hash_algo = r[15];

        kdf->salt_len = r[23];
        kdf->iterations = iterations;

        memcpy(kdf->salt, r + 24, kdf->salt_len);
    }

    return ret;
}

static int
kdf_itersalted_s2k(const struct kdf *kdf, const u8 *input, int input_len, u8 *output) {
    int total_len = kdf->salt_len + input_len;
    u8 buf[total_len];

    memcpy(buf, kdf->salt, kdf->salt_len);
    memcpy(buf + kdf->salt_len, input, input_len);

    return hash(kdf->hash_algo, buf, total_len, output, kdf->iterations);
}

static int
read_input(u8 *buf, int buf_size) {
    int ret = 0;
    printf("Enter smart card PIN:\n");

    struct bregs br;
    memset(&br, 0, sizeof(br));

    for (ret = 0; ret < buf_size; ret++) {
        br.ah = 0;
        handle_16(&br);

        if (br.al == 13) break;

        buf[ret] = br.al;
    }

    return ret;
}

int
verify_pin(void) {
    struct kdf kdf;
    if (!init_kdf(&kdf)) return 0;

    u8 pin_buf[0xFF]; // NOTE: max pin length
    u8 pin_len = read_input(pin_buf, sizeof(pin_buf));

    if (kdf.kdf_algo == KDF_ITERSALTED_S2K) pin_len = kdf_itersalted_s2k(&kdf, pin_buf, pin_len, pin_buf);
    u8 apdu[pin_len + 5];

    apdu[0] = 0x00;
    apdu[1] = 0x20;
    apdu[2] = 0x00;
    apdu[3] = 0x82;
    apdu[4] = pin_len;

    memcpy(apdu + 5, pin_buf, pin_len);
    u8 *r = send_ccid_msg(0x6F, apdu, 5 + pin_len);

    return is_success(r);
}

static void
init_auth_apdu(u8 *apdu) {
    u32 esp = getesp();

    u32 r1 = rdtscll();
    u8 r1b = r1;

    u32 r2 = timer_calc(r1b + 1);
    u8 r2b = r2;

    u32 r3 = readl((void*)esp - r1b);
    u32 r4 = readl((void*)esp - r2b);

    u32 r5 = readl((void*)esp + r1b);
    u32 r6 = readl((void*)esp + r2b);

    u32 buf[] = { r1, r2, r3, r4, r5, r6 };
    u8 buf_size = sizeof(buf);

    hash(0x08, (u8*)buf, buf_size, apdu + 5, buf_size + r1b + r2b);

    apdu[1] = 0x88;
    apdu[4] = 0x20;
}

int
internal_auth(void) {
    u8 apdu[38] = {};
    u8 sign[PUBKEY_SIZE];

    init_auth_apdu(apdu);

    u8 *r = send_ccid_msg(0x6F, apdu, sizeof(apdu));
    if (r == NULL) return 0;

    mdelay(1000);
    r = recv_ccid_msg();

    u16 r_len = r[1] | (r[2] << 8);
    if (r_len > PUBKEY_SIZE) return 0; // NOTE: prevent buffer overflow

    memcpy(sign, r + 10, r_len);
    if (r[8] == 0x01 && r[r_len + 8] == 0x61) {
        u8 tail_len = r[r_len + 9];
        r_len -= 2;

        if (r_len + tail_len > PUBKEY_SIZE) return 0; // NOTE: prevent buffer overflow

        apdu[1] = 0xC0;
        apdu[4] = tail_len;

        r = send_ccid_msg(0x6F, apdu, 5);
        if (is_success(r)) memcpy(sign + r_len, r + 10, tail_len);
    }

    return is_success(r) && rsa_verify(sign, apdu + 5, 32);
}

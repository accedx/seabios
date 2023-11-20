#include "./hash.h"
#include "sha.h"

int
hash(u8 algo, const u8 *data, u32 length, u8 *hash, u32 iterations) {
    int ret = 0;

    switch (algo) {
        case 0x08: sha256_it(data, length, hash, iterations); ret = 32; break;
        case 0x0A: sha512_it(data, length, hash, iterations); ret = 64; break;
    }

    return ret;
}

#ifndef __SMARTCARD_HASH_H
#define __SMARTCARD_HASH_H

#include "types.h"

int hash(u8 algo, const u8 *data, u32 length, u8 *hash, u32 iterations);

#endif

#ifndef __SHA_H
#define __SHA_H

#include "types.h" // u32

void sha1(const u8 *data, u32 length, u8 *hash);
void sha256(const u8 *data, u32 length, u8 *hash);
void sha384(const u8 *data, u32 length, u8 *hash);
void sha512(const u8 *data, u32 length, u8 *hash);

void sha256_it(const u8 *data, u32 length, u8 *hash, u32 count);
void sha512_it(const u8 *data, u32 length, u8 *hash, u32 count);

#endif // sha.h

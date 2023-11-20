#ifndef __SMARTCARD_RSA_H
#define __SMARTCARD_RSA_H

#include "types.h"

int rsa_verify(const u8 *sign, const u8 *data, int data_len);

#endif

#ifndef __SMARTCARD_OPENPGP_H
#define __SMARTCARD_OPENPGP_H

int select_openpgp(void);
int internal_auth(void);
int verify_pin(void);

#endif

#ifndef __SMARTCARD_H
#define __SMARTCARD_H

#include "./usb.h"

int smartcard_auth(void);
int smartcard_init(struct usbdevice_s *usbdev);

#endif

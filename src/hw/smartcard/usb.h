#ifndef __SMARTCARD_USB_H
#define __SMARTCARD_USB_H

#include "hw/usb.h"

#define USB_RECV_LEN	64

int usb_recv(u8 *buf);
int usb_send(u8 *data, int length);

void usb_free_pipes(void);
int usb_init_pipes(struct usbdevice_s *usbdev);

#endif

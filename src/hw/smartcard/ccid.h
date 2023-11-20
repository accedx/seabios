#ifndef __SMARTCARD_CCID_H
#define __SMARTCARD_CCID_H

#include "./usb.h"

int ccid_init_bufs(void);
void ccid_free_bufs(void);

int is_ccid_success(const u8 *data, u8 msg_type);
struct usb_interface_descriptor* get_ccid_iface(const struct usb_config_descriptor *config);

u8* send_ccid_msg(u8 msg_type, const u8 *data, u32 data_len); // NOTE: can return NULL
u8* recv_ccid_msg(void);

int icc_power_on(void);
int get_slot_status(void);

#endif

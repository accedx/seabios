#include "./ccid.h"

#include "malloc.h"
#include "string.h"

#define CCID_BUF_SIZE	5*USB_RECV_LEN	// NOTE: the standard value for dwMaxCCIDMessageLength is 271

static u8 bSeq = 0;
static struct {
    u8 *send;
    u8 *recv;
} ccid_bufs;

int
ccid_init_bufs(void) {
    ccid_bufs.send = malloc_tmp(CCID_BUF_SIZE);
    ccid_bufs.recv = malloc_tmp(CCID_BUF_SIZE);

    return ccid_bufs.send && ccid_bufs.recv;
}

void
ccid_free_bufs(void) {
    free(ccid_bufs.send);
    free(ccid_bufs.recv);

    ccid_bufs.send = NULL;
    ccid_bufs.recv = NULL;
}

static int
is_ccid(const struct usb_interface_descriptor *iface) {
    struct usb_device_descriptor *desc = (void*)iface + iface->bLength;
    return desc->bLength == 0x36 && desc->bDescriptorType == 0x21;
}

static int
is_smartcard(const struct usb_interface_descriptor *iface) {
    return iface->bInterfaceClass == 0x0B &&
        iface->bInterfaceSubClass == 0 && iface->bInterfaceProtocol == 0;
}

struct usb_interface_descriptor*
get_ccid_iface(const struct usb_config_descriptor *config) {
    int num_iface = config->bNumInterfaces;

    struct usb_interface_descriptor *ret = NULL;
    struct usb_interface_descriptor *iface = (void*)(&config[1]);

    while (num_iface) {
        if (iface->bDescriptorType == USB_DT_INTERFACE) {
            num_iface--;

            if (is_smartcard(iface) && is_ccid(iface)) {
                ret = iface;
                break;
            }
        }
        iface = (void*)iface + iface->bLength;
    }

    return ret;
}

u8*
send_ccid_msg(u8 msg_type, const u8 *data, u32 data_len) {
    u8 *s = ccid_bufs.send;
    memset(s, 0, CCID_BUF_SIZE);

    if (data_len + 10 > CCID_BUF_SIZE) return NULL; // NOTE: prevent buffer overflow

    s[0] = msg_type;

    s[1] = data_len;
    s[2] = data_len >> 8;
    s[3] = data_len >> 16;
    s[4] = data_len >> 24;

    s[6] = bSeq++;

    memcpy(s + 10, data, data_len);
    return (usb_send(s, data_len + 10)) ? NULL : recv_ccid_msg();
}

u8*
recv_ccid_msg(void) {
    u8 *r = ccid_bufs.recv;
    memset(r, 0, CCID_BUF_SIZE);

    int rc = usb_recv(r);
    if (rc == 0) {
        u32 data_len = 10 + (r[1] | (r[2] << 8) | (r[3] << 16) | (r[4] << 24));
        u32 chunks = data_len / USB_RECV_LEN;

        int max_chunks = (CCID_BUF_SIZE / USB_RECV_LEN) - 1;
        if (chunks > max_chunks) chunks = max_chunks; // NOTE: prevent buffer overflow

        for (int i = 1; i <= chunks; i++) if (usb_recv(r + USB_RECV_LEN * i)) break;
    }

    return r;
}

int
is_ccid_success(const u8 *data, u8 msg_type) {
    return (data != NULL) && (data[0] == msg_type) && (data[7] == 0x00) && (data[8] == 0x00);
}

int
get_slot_status(void) {
    u8 *r = send_ccid_msg(0x65, NULL, 0);
    return is_ccid_success(r, 0x81);
}

int
icc_power_on(void) {
    u8 *r = send_ccid_msg(0x62, NULL, 0);
    return is_ccid_success(r, 0x80);
}

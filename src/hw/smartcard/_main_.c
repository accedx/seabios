#include "./_main_.h"

#include "./ccid.h"
#include "./openpgp.h"

static int init_success = 0;

int
smartcard_init(struct usbdevice_s *usbdev)
{
    struct usb_interface_descriptor *ccid_iface = get_ccid_iface(usbdev->config);
    if (ccid_iface == NULL || init_success) return 0;

    usbdev->iface = ccid_iface;

    if (
        usb_init_pipes(usbdev) && ccid_init_bufs() &&
        get_slot_status() && icc_power_on()
    ) {
        init_success = 1;
    } else {
        ccid_free_bufs();
        usb_free_pipes();
    }

    return init_success;
}

int
smartcard_auth(void) {
    int ret = 0;

    if (
        init_success && select_openpgp() &&
        verify_pin() && internal_auth()
    ) {
        ret = 1;
    }

    ccid_free_bufs();
    usb_free_pipes();

    return ret;
}

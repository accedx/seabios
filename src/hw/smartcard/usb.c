#include "./usb.h"

static struct {
    struct usbdevice_s *usbdev;

    struct usb_pipe *in;
    struct usb_pipe *out;
} pipes;

int
usb_init_pipes(struct usbdevice_s *usbdev) {
    struct usb_endpoint_descriptor *ep_in = usb_find_desc(usbdev, USB_ENDPOINT_XFER_BULK, USB_DIR_IN);
    struct usb_endpoint_descriptor *ep_out = usb_find_desc(usbdev, USB_ENDPOINT_XFER_BULK, USB_DIR_OUT);

    pipes.usbdev = usbdev;

    pipes.in = usb_alloc_pipe(usbdev, ep_in);
    pipes.out = usb_alloc_pipe(usbdev, ep_out);

    return pipes.in && pipes.out;
}

void
usb_free_pipes(void) {
    usb_free_pipe(pipes.usbdev, pipes.in);
    usb_free_pipe(pipes.usbdev, pipes.out);

    pipes.in = NULL;
    pipes.out = NULL;
}

int
usb_recv(u8 *buf) {
    return usb_send_bulk(pipes.in, USB_DIR_IN, buf, USB_RECV_LEN);
}

int
usb_send(u8 *data, int length) {
    return usb_send_bulk(pipes.out, USB_DIR_OUT, data, length);
}

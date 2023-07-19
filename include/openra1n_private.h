#ifndef OPENRA1N_PRIVATE_H
#define OPENRA1N_PRIVATE_H

#ifdef HAVE_LIBUSB
#include <libusb-1.0/libusb.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <inttypes.h>
#else
#include <CommonCrypto/CommonCrypto.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/IOUSBLib.h>

#if TARGET_OS_IPHONE
#define kUSBPipeStalled kUSBHostReturnPipeStalled
#else
#define kUSBPipeStalled kIOUSBPipeStalled
#endif

#endif

#define DFU_DNLOAD (1)
#define APPLE_VID (0x5AC)
#define DFU_STATUS_OK (0)
#define DFU_GET_STATUS (3)
#define DFU_CLR_STATUS (4)
#define MAX_BLOCK_SZ (0x50)
#define DFU_MODE_PID (0x1227)
#define DFU_STATE_MANIFEST (7)
#define EP0_MAX_PACKET_SZ (0x40)
#define DFU_FILE_SUFFIX_LEN (16)
#define DFU_MAX_TRANSFER_SZ (0x800)
#define DFU_STATE_MANIFEST_SYNC (6)
#define ARM_16K_TT_L2_SZ (0x2000000U)
#define DFU_STATE_MANIFEST_WAIT_RESET (8)
#define USB_MAX_STRING_DESCRIPTOR_IDX (10)

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef struct usb_handle
{
    uint16_t vid, pid;
#ifdef HAVE_LIBUSB
    struct libusb_device_handle *device;
#else
    io_service_t serv;
    IOUSBDeviceInterface320 **device;
    CFRunLoopSourceRef async_event_source;
#endif
} usb_handle_t;

typedef int (*usb_check_cb_t)(usb_handle_t *, void *);

enum usb_transfer
{
    USB_TRANSFER_OK,
    USB_TRANSFER_ERROR,
    USB_TRANSFER_STALL,
    USB_TRANSFER_TIMEOUT,
};

typedef struct
{
    enum usb_transfer ret;
    uint32_t sz;
} transfer_ret_t;

typedef struct
{
    uint32_t endpoint, pad_0;
    uint64_t io_buffer;
    uint32_t status, io_len, ret_cnt, pad_1;
    uint64_t callback, next;
} dfu_callback_t;

typedef struct
{
    dfu_callback_t callback;
} openra1n_overwrite_t;

typedef struct
{
    uint8_t b_len, b_descriptor_type;
    uint16_t bcd_usb;
    uint8_t b_device_class, b_device_sub_class, b_device_protocol, b_max_packet_sz;
    uint16_t id_vendor, id_product, bcd_device;
    uint8_t i_manufacturer, i_product, i_serial_number, b_num_configurations;
} device_descriptor_t;
extern device_descriptor_t device_descriptor;

extern unsigned int usb_timeout, usb_abort_timeout_min;

bool send_usb_control_request(const usb_handle_t *handle,
                              uint8_t bm_request_type,
                              uint8_t b_request,
                              uint16_t w_value,
                              uint16_t w_index,
                              void *p_data,
                              size_t w_len,
                              transfer_ret_t *transfer_ret);
bool send_usb_control_request_async(const usb_handle_t *handle,
                                    uint8_t bm_request_type,
                                    uint8_t b_request,
                                    uint16_t w_value,
                                    uint16_t w_index,
                                    void *p_data,
                                    size_t w_len,
                                    unsigned usb_abort_timeout,
                                    transfer_ret_t *transfer_ret);

bool send_usb_control_request_no_data(const usb_handle_t *handle,
                                      uint8_t bm_request_type,
                                      uint8_t b_request,
                                      uint16_t w_value,
                                      uint16_t w_index,
                                      size_t w_len,
                                      transfer_ret_t *transfer_ret);
bool send_usb_control_request_async_no_data(const usb_handle_t *handle,
                                            uint8_t bm_request_type,
                                            uint8_t b_request,
                                            uint16_t w_value,
                                            uint16_t w_index,
                                            size_t w_len,
                                            unsigned usb_abort_timeout,
                                            transfer_ret_t *transfer_ret);
char *get_usb_serial_number(usb_handle_t *handle);

int openra1n_check_usb_device(usb_handle_t *handle,
                              void *pwned);
#endif

#ifdef HAVE_LIBUSB
#include <openra1n.h>
#include <common.h>

static libusb_context* ctx = NULL;

OPENRA1N_EXPORT void openra1n_close_usb_handle(usb_handle_t *handle)
{
    libusb_close(handle->device);
    libusb_exit(ctx);
    ctx = NULL;
}

OPENRA1N_EXPORT void openra1n_reset_usb_handle(usb_handle_t *handle)
{
    libusb_reset_device(handle->device);
}

int openra1n_wait_usb_handle(usb_handle_t *handle, void *arg)
{
    int cpid;
    if(libusb_init(&ctx) == LIBUSB_SUCCESS)
    {
        for(;;)
        {
            if((handle->device = libusb_open_device_with_vid_pid(ctx, handle->vid, handle->pid)) != NULL)
            {
                if(libusb_set_configuration(handle->device, 1) == LIBUSB_SUCCESS && (cpid = openra1n_check_usb_device(handle, arg)))
                {
                    return cpid;
                }
                libusb_close(handle->device);
            }
            openra1n_sleep_ms(usb_timeout);
        }
    }
    return 0;
}

static void usb_async_cb(struct libusb_transfer *transfer)
{
    *(int *)transfer->user_data = 1;
}

bool send_usb_control_request(const usb_handle_t *handle,
                              uint8_t bm_request_type,
                              uint8_t b_request,
                              uint16_t w_value,
                              uint16_t w_index,
                              void *p_data,
                              size_t w_len,
                              transfer_ret_t *transfer_ret)
{
    int ret = libusb_control_transfer(handle->device, bm_request_type, b_request, w_value, w_index, p_data, (uint16_t)w_len, usb_timeout);
    
    if(transfer_ret != NULL)
    {
        if(ret >= 0)
        {
            transfer_ret->sz = (uint32_t)ret;
            transfer_ret->ret = USB_TRANSFER_OK;
        }
        else if(ret == LIBUSB_ERROR_PIPE)
        {
            transfer_ret->ret = USB_TRANSFER_STALL;
        }
        else if(ret == LIBUSB_ERROR_TIMEOUT)
        {
            transfer_ret->ret = USB_TRANSFER_TIMEOUT;
        }
        else
        {
            transfer_ret->ret = USB_TRANSFER_ERROR;
        }
    }
    return true;
}

bool send_usb_control_request_async(const usb_handle_t *handle,
                                    uint8_t bm_request_type,
                                    uint8_t b_request,
                                    uint16_t w_value,
                                    uint16_t w_index,
                                    void *p_data,
                                    size_t w_len,
                                    unsigned usb_abort_timeout,
                                    transfer_ret_t *transfer_ret)
{
    struct libusb_transfer *transfer = libusb_alloc_transfer(0);
    struct timeval tv;
    int completed = 0;
    uint8_t *buf;
    
    if(transfer != NULL)
    {
        if((buf = malloc(LIBUSB_CONTROL_SETUP_SIZE + w_len)) != NULL)
        {
            if((bm_request_type & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT)
            {
                memcpy(buf + LIBUSB_CONTROL_SETUP_SIZE, p_data, w_len);
            }
            libusb_fill_control_setup(buf, bm_request_type, b_request, w_value, w_index, (uint16_t)w_len);
            libusb_fill_control_transfer(transfer, handle->device, buf, usb_async_cb, &completed, usb_timeout);
            if(libusb_submit_transfer(transfer) == LIBUSB_SUCCESS)
            {
                tv.tv_sec = usb_abort_timeout / 1000;
                tv.tv_usec = (usb_abort_timeout % 1000) * 1000;
                while(completed == 0 && libusb_handle_events_timeout_completed(ctx, &tv, &completed) == LIBUSB_SUCCESS)
                {
                    libusb_cancel_transfer(transfer);
                }
                if(completed != 0)
                {
                    if((bm_request_type & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN)
                    {
                        memcpy(p_data, libusb_control_transfer_get_data(transfer), transfer->actual_length);
                    }
                    if(transfer_ret != NULL)
                    {
                        transfer_ret->sz = (uint32_t)transfer->actual_length;
                        if(transfer->status == LIBUSB_TRANSFER_COMPLETED)
                        {
                            transfer_ret->ret = USB_TRANSFER_OK;
                        }
                        else if(transfer->status == LIBUSB_TRANSFER_STALL)
                        {
                            transfer_ret->ret = USB_TRANSFER_STALL;
                        }
                        else if(transfer->status == LIBUSB_TRANSFER_TIMED_OUT)
                        {
                            transfer_ret->ret = USB_TRANSFER_TIMEOUT;
                        }
                        else
                        {
                            transfer_ret->ret = USB_TRANSFER_ERROR;
                        }
                    }
                }
            }
            free(buf);
        }
        libusb_free_transfer(transfer);
    }
    return completed != 0;
}

#endif

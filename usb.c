#include <openra1n_usb.h>
#include <common.h>

unsigned usb_timeout, usb_abort_timeout_min;

bool send_usb_control_request_no_data(const usb_handle_t *handle,
                                      uint8_t bm_request_type,
                                      uint8_t b_request,
                                      uint16_t w_value,
                                      uint16_t w_index,
                                      size_t w_len,
                                      transfer_ret_t *transfer_ret)
{
    bool ret = false;
    void *p_data;
    
    if(w_len == 0)
    {
        ret = send_usb_control_request(handle, bm_request_type, b_request, w_value, w_index, NULL, 0, transfer_ret);
    }
    else if((p_data = malloc(w_len)) != NULL)
    {
        memset(p_data, '\0', w_len);
        ret = send_usb_control_request(handle, bm_request_type, b_request, w_value, w_index, p_data, w_len, transfer_ret);
        free(p_data);
    }
    return ret;
}

bool send_usb_control_request_async_no_data(const usb_handle_t *handle,
                                            uint8_t bm_request_type,
                                            uint8_t b_request,
                                            uint16_t w_value,
                                            uint16_t w_index,
                                            size_t w_len,
                                            unsigned usb_abort_timeout,
                                            transfer_ret_t *transfer_ret)
{
    bool ret = false;
    void *p_data;
    
    if(w_len == 0)
    {
        ret = send_usb_control_request_async(handle, bm_request_type, b_request, w_value, w_index, NULL, 0, usb_abort_timeout, transfer_ret);
    }
    else if((p_data = malloc(w_len)) != NULL)
    {
        memset(p_data, '\0', w_len);
        ret = send_usb_control_request_async(handle, bm_request_type, b_request, w_value, w_index, p_data, w_len, usb_abort_timeout, transfer_ret);
        free(p_data);
    }
    return ret;
}

char *get_usb_serial_number(usb_handle_t *handle)
{
    transfer_ret_t transfer_ret;
    uint8_t buf[UINT8_MAX];
    char *str = NULL;
    size_t i, sz;
    
    if(send_usb_control_request(handle, 0x80, 6, 1U << 8U, 0, &device_descriptor, sizeof(device_descriptor), &transfer_ret)
       && transfer_ret.ret == USB_TRANSFER_OK
       && transfer_ret.sz == sizeof(device_descriptor))
    {
        if(send_usb_control_request(handle, 0x80, 6, (3U << 8U) | device_descriptor.i_serial_number, 0x409, buf, sizeof(buf), &transfer_ret))
        {
            if(transfer_ret.ret == USB_TRANSFER_OK
               && transfer_ret.sz == buf[0]
               && (sz = buf[0] / 2) != 0
               && (str = malloc(sz)) != NULL)
            {
                for(i = 0; i < sz; ++i)
                {
                    str[i] = (char)buf[2 * (i + 1)];
                }
                str[sz - 1] = '\0';
            }
        }
    }
    return str;
}


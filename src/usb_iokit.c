#ifndef HAVE_LIBUSB
#include <openra1n.h>
#include <openra1n_private.h>
#include <common.h>

static void cf_dictionary_set_int16(CFMutableDictionaryRef dict,
                                    const void *key,
                                    uint16_t val)
{
    CFNumberRef cf_val = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt16Type, &val);
    
    if(cf_val != NULL)
    {
        CFDictionarySetValue(dict, key, cf_val);
        CFRelease(cf_val);
    }
}

static bool query_usb_interface(io_service_t serv,
                                CFUUIDRef plugin_type,
                                CFUUIDRef interface_type,
                                LPVOID *interface)
{
    IOCFPlugInInterface **plugin_interface;
    bool ret = false;
    SInt32 score;
    
    if(IOCreatePlugInInterfaceForService(serv, plugin_type, kIOCFPlugInInterfaceID, &plugin_interface, &score) == kIOReturnSuccess)
    {
        ret = (*plugin_interface)->QueryInterface(plugin_interface, CFUUIDGetUUIDBytes(interface_type), interface) == kIOReturnSuccess;
        IODestroyPlugInInterface(plugin_interface);
    }
    IOObjectRelease(serv);
    return ret;
}

static void close_usb_device(usb_handle_t *handle)
{
    CFRunLoopRemoveSource(CFRunLoopGetCurrent(), handle->async_event_source, kCFRunLoopDefaultMode);
    CFRelease(handle->async_event_source);
    (*handle->device)->USBDeviceClose(handle->device);
    (*handle->device)->Release(handle->device);
}

OPENRA1N_EXPORT void openra1n_close_usb_handle(usb_handle_t *handle)
{
    close_usb_device(handle);
}

static bool open_usb_device(io_service_t serv,
                            usb_handle_t *handle)
{
    bool ret = false;
    
    if(query_usb_interface(serv, kIOUSBDeviceUserClientTypeID, kIOUSBDeviceInterfaceID320, (LPVOID *)&handle->device))
    {
        if((*handle->device)->USBDeviceOpen(handle->device) == kIOReturnSuccess)
        {
            if((*handle->device)->SetConfiguration(handle->device, 1) == kIOReturnSuccess
               && (*handle->device)->CreateDeviceAsyncEventSource(handle->device, &handle->async_event_source) == kIOReturnSuccess)
            {
                CFRunLoopAddSource(CFRunLoopGetCurrent(), handle->async_event_source, kCFRunLoopDefaultMode);
                ret = true;
            }
            else
            {
                (*handle->device)->USBDeviceClose(handle->device);
            }
        }
        if(!ret)
        {
            (*handle->device)->Release(handle->device);
        }
    }
    return ret;
}

int openra1n_wait_usb_handle(usb_handle_t *handle, void *arg)
{
    CFMutableDictionaryRef matching_dict;
    const char *darwin_device_class;
    io_iterator_t iter;
    io_service_t serv;
    int cpid = 0;
    
#if TARGET_OS_IPHONE
    darwin_device_class = "IOUSBHostDevice";
#else
    darwin_device_class = kIOUSBDeviceClassName;
#endif
    while((matching_dict = IOServiceMatching(darwin_device_class)) != NULL)
    {
        cf_dictionary_set_int16(matching_dict, CFSTR(kUSBVendorID), handle->vid);
        cf_dictionary_set_int16(matching_dict, CFSTR(kUSBProductID), handle->pid);
        if(IOServiceGetMatchingServices(0, matching_dict, &iter) == kIOReturnSuccess)
        {
            while((serv = IOIteratorNext(iter)) != IO_OBJECT_NULL)
            {
                if(open_usb_device(serv, handle))
                {
                    if(cpid = openra1n_check_usb_device(handle, arg))
                    {
                        break;
                    }
                    close_usb_device(handle);
                }
            }
            IOObjectRelease(iter);
            if(cpid)
            {
                break;
            }
            openra1n_sleep_ms(usb_timeout);
        }
    }
    return cpid;
}

OPENRA1N_EXPORT void openra1n_reset_usb_handle(usb_handle_t *handle)
{
    (*handle->device)->ResetDevice(handle->device);
    (*handle->device)->USBDeviceReEnumerate(handle->device, 0);
}

static void usb_async_cb(void *refcon,
                         IOReturn ret,
                         void *arg)
{
    transfer_ret_t *transfer_ret = refcon;
    
    if(transfer_ret != NULL)
    {
        memcpy(&transfer_ret->sz, &arg, sizeof(transfer_ret->sz));
        if(ret == kIOReturnSuccess)
        {
            transfer_ret->ret = USB_TRANSFER_OK;
        }
        else if(ret == kUSBPipeStalled)
        {
            transfer_ret->ret = USB_TRANSFER_STALL;
        }
        else if(ret == kIOReturnTimeout)
        {
            transfer_ret->ret = USB_TRANSFER_TIMEOUT;
        }
        else if(ret == kIOUSBTransactionTimeout)
        {
            transfer_ret->ret = USB_TRANSFER_TIMEOUT;
        }
        else
        {
            transfer_ret->ret = USB_TRANSFER_ERROR;
        }
    }
    CFRunLoopStop(CFRunLoopGetCurrent());
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
    IOUSBDevRequestTO req;
    IOReturn ret;
    
    req.wLenDone = 0;
    req.pData = p_data;
    req.bRequest = b_request;
    req.bmRequestType = bm_request_type;
    req.wLength = OSSwapLittleToHostInt16(w_len);
    req.wValue = OSSwapLittleToHostInt16(w_value);
    req.wIndex = OSSwapLittleToHostInt16(w_index);
    req.completionTimeout = req.noDataTimeout = usb_timeout;
    ret = (*handle->device)->DeviceRequestTO(handle->device, &req);
    if(transfer_ret != NULL)
    {
        if(ret == kIOReturnSuccess)
        {
            transfer_ret->sz = req.wLenDone;
            transfer_ret->ret = USB_TRANSFER_OK;
        }
        else if(ret == kUSBPipeStalled)
        {
            transfer_ret->ret = USB_TRANSFER_STALL;
        }
        else if(ret == kIOReturnTimeout)
        {
            transfer_ret->ret = USB_TRANSFER_TIMEOUT;
        }
        else if(ret == kIOUSBTransactionTimeout)
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
    IOUSBDevRequestTO req;
    
    req.wLenDone = 0;
    req.pData = p_data;
    req.bRequest = b_request;
    req.bmRequestType = bm_request_type;
    req.wLength = OSSwapLittleToHostInt16(w_len);
    req.wValue = OSSwapLittleToHostInt16(w_value);
    req.wIndex = OSSwapLittleToHostInt16(w_index);
    req.completionTimeout = req.noDataTimeout = usb_timeout;
    if((*handle->device)->DeviceRequestAsyncTO(handle->device, &req, usb_async_cb, transfer_ret) == kIOReturnSuccess)
    {
        openra1n_sleep_ms(usb_abort_timeout);
        if((*handle->device)->USBDeviceAbortPipeZero(handle->device) == kIOReturnSuccess)
        {
            CFRunLoopRun();
            return true;
        }
    }
    return false;
}

#endif

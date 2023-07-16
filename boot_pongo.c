#include <openra1n_usb.h>
#include <boot_pongo.h>
#include <common.h>

#include <common/log.h>

#include <lz4/lz4.h>
#include <lz4/lz4hc.h>

#include <payloads/Pongo.bin.h>
#include <payloads/lz4dec.bin.h>

extern uint8_t payloads_Pongo_bin[], payloads_lz4dec_bin[];
extern unsigned payloads_Pongo_bin_len, payloads_lz4dec_bin_len;

static bool compress_pongo(void *inbuf,
                           size_t insize,
                           void** outbuf,
                           size_t* outsize)
{
    if(insize > LZ4_MAX_INPUT_SIZE)
    {
        LOG_ERROR("Input too large");
        return false;
    }
    
    size_t tmpsize = LZ4_COMPRESSBOUND(insize);
    void *tmpbuf = malloc(tmpsize);
    if(!tmpbuf)
    {
        LOG_ERROR("malloc: %s", strerror(errno));
        return false;
    }
    
    int outlen = LZ4_compress_HC(inbuf, tmpbuf, (int)insize, (int)tmpsize, LZ4HC_CLEVEL_MAX);
    if(!outlen)
    {
        LOG_ERROR("lz4 error");
        free(tmpbuf);
        return false;
    }
    
    LOG_DEBUG("Compressed pongoOS from 0x%zx to 0x%llx bytes", insize, (unsigned long long)outlen);
    
    if(outlen > (MAX_PONGOOS_SIZE - payloads_lz4dec_bin_len))
    {
        LOG_ERROR("pongoOS too large");
        free(tmpbuf);
        return false;
    }
    
    *outbuf = malloc(outlen + payloads_lz4dec_bin_len);
    if(!*outbuf)
    {
        LOG_ERROR("malloc: %s", strerror(errno));
        free(tmpbuf);
        return false;
    }
    
    LOG_DEBUG("Setting the compressed size into the shellcode");
    uint32_t* sizebuf = (uint32_t*)(payloads_lz4dec_bin + (payloads_lz4dec_bin_len - 4));
    sizebuf[0] = outlen;
    
    memcpy(*outbuf, payloads_lz4dec_bin, payloads_lz4dec_bin_len);
    memcpy(*outbuf + payloads_lz4dec_bin_len, tmpbuf, outlen);
    free(tmpbuf);
    *outsize = outlen + payloads_lz4dec_bin_len;
    return true;
}

bool checkm8_boot_pongo(usb_handle_t *handle)
{
    transfer_ret_t transfer_ret;
    LOG_INFO("Booting pongoOS");
    
    void* out = NULL;
    size_t out_len = 0;
    
    LOG_DEBUG("Compressing pongoOS");
    
    if(!compress_pongo(payloads_Pongo_bin, payloads_Pongo_bin_len, &out, &out_len))
    {
        return false;
    }
    
    {
        size_t len = 0;
        size_t size;
        while(len < out_len)
        {
        retry:
            size = ((out_len - len) > 0x800) ? 0x800 : (out_len - len);
            send_usb_control_request(handle, 0x21, DFU_DNLOAD, 0, 0, (unsigned char*)&out[len], size, &transfer_ret);
            if(transfer_ret.ret == USB_TRANSFER_TIMEOUT)
            {
                LOG_DEBUG("retrying at len = %zu", len);
                sleep_ms(100);
                goto retry;
            }
            else if(transfer_ret.sz != size || transfer_ret.ret != USB_TRANSFER_OK)
            {
                // fail
                return false;
            }
            len += size;
            LOG_DEBUG("len = %zu", len);
        }
    }
    send_usb_control_request_no_data(handle, 0x21, 4, 0, 0, 0, NULL);
    LOG_DEBUG("pongoOS sent, should be booting");
    
    if(out)
    {
        free(out);
    }
    return true;
}

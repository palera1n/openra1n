#ifndef BOOT_PONGO_H
#define BOOT_PONGO_H

#include <openra1n_usb.h>
#include <common.h>

#define MAX_PONGOOS_RAW_SIZE            (0x80000)
#define MAX_PONGOOS_COMPRESSED_SIZE     (0x40000)
extern void* custom_pongo;
extern size_t custom_pongo_len;

bool checkm8_boot_pongo(usb_handle_t *handle);

#endif

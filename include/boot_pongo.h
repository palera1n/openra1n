#ifndef BOOT_PONGO_H
#define BOOT_PONGO_H

#include <openra1n_usb.h>
#include <common.h>

#define MAX_PONGOOS_SIZE    (0x40000)

bool checkm8_boot_pongo(usb_handle_t *handle);

#endif

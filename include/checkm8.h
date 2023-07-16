#ifndef CEHCKM8_H
#define CEHCKM8_H

#include <openra1n_usb.h>
#include <common.h>

#define MAX_PONGOOS_SIZE    (0x40000)

bool checkm8_boot_pongo(usb_handle_t *handle);
bool checkm8(usb_handle_t *handle);

#endif

#ifndef OPENRA1N_H
#define OPENRA1N_H

#define OPENRA1N_EXPORT __attribute__((visibility("default")))
#define OPENRA1N_HIDDEN __attribute__((visibility("hidden")))

#if defined(OPENRA1N_INTERNAL)
#include <openra1n_private.h>
#else
typedef struct usb_handle usb_handle_t;
#endif

OPENRA1N_EXPORT bool openra1n_stage_reset(const usb_handle_t *handle);
OPENRA1N_EXPORT bool openra1n_stage_setup(const usb_handle_t *handle);
OPENRA1N_EXPORT bool openra1n_stage_patch(const usb_handle_t *handle,
                                          void *checkra1n_payload,
                                          size_t checkra1n_payload_sz);
OPENRA1N_EXPORT bool openra1n_boot_pongo(usb_handle_t *handle,
                                         void *pongo_bin,
                                         unsigned int pongo_bin_len);
OPENRA1N_EXPORT void openra1n_set_usb_timeout(unsigned int timeout);
OPENRA1N_EXPORT void openra1n_set_usb_abort_timeout_min(unsigned int timeout);
OPENRA1N_EXPORT void openra1n_sleep_ms(unsigned int ms);
OPENRA1N_EXPORT usb_handle_t *openra1n_init_usb_handle(uint16_t vid,
                                                       uint16_t pid);
OPENRA1N_EXPORT void openra1n_reset_usb_handle(usb_handle_t *handle);
OPENRA1N_EXPORT void openra1n_free_handle(usb_handle_t* handle);
OPENRA1N_EXPORT void openra1n_close_usb_handle(usb_handle_t *handle);
OPENRA1N_EXPORT void openra1n_sleep_ms(unsigned int ms);
OPENRA1N_EXPORT bool openra1n_stage_spray(const usb_handle_t *handle);
OPENRA1N_EXPORT int openra1n_wait_usb_handle(usb_handle_t *handle,
                              void *arg);

#endif

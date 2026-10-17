/* vulkan_loader.h — dlopen libvulkan, instance creation, device probe.
 * No link-time Vulkan dependency; everything resolved at runtime.
 */
#ifndef WN_VULKAN_LOADER_H
#define WN_VULKAN_LOADER_H

#include <stddef.h>
#include <stdint.h>

/* Load libvulkan and create an instance. Returns 0 on success. */
int  wn_vk_init(void);

/* 1 when the loader + instance are up. */
int  wn_vk_available(void);

/* Number of physical devices (after wn_vk_init). */
uint32_t wn_vk_physical_device_count(void);

/* Device name into out ("unknown" when idx invalid). */
void wn_vk_device_name(uint32_t idx, char *out, size_t cap);

/* Print a bench-style report to stdout. */
void wn_vk_report(void);

#endif /* WN_VULKAN_LOADER_H */

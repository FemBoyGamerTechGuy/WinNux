/* vulkan_loader.c — runtime Vulkan probe via dlopen (no link dependency).
 *
 * Creates a real instance, enumerates physical devices, and reports names.
 * This is the entry point of the hardware graphics path; surface creation
 * (vkCreateXlibSurfaceKHR) and swapchains follow in the graphics milestone.
 */
#include "wn_vulkan_loader.h"
#include "wn_log.h"

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t VkFlags;
typedef uint32_t VkBool32;
typedef uint64_t VkDeviceSize;

typedef struct { uint32_t specVersion; } VkExtensionProperties_like;
typedef struct {
    int32_t sType;            /* 0 */
    void *pNext;              /* 8 */
    uint32_t apiVersion;      /* 16 */
    uint32_t driverVersion;   /* 20 */
    uint32_t vendorID;        /* 24 */
    uint32_t deviceID;        /* 28 */
    int32_t deviceType;       /* 32 */
    char deviceName[256];     /* 36 */
    char pipelineCacheUUID[16];
    uint64_t remainder[16];   /* limits/sparse: only size matters */
} VkPhysicalDeviceProperties_like;

typedef struct {
    void *pNext;
    int32_t messageSeverity;
    int32_t messageType;
    void *pfnUserCallback;
    void *pUserData;
} VkDebugUtilsMessengerCreateInfoEXT_like;

typedef struct {
    int32_t sType;
    void *pNext;
    const char *pApplicationName;
    uint32_t applicationVersion;
    const char *pEngineName;
    uint32_t engineVersion;
    uint32_t apiVersion;
} VkApplicationInfo_like;

typedef struct {
    int32_t sType;
    void *pNext;
    uint32_t flags;
    const void *pApplicationInfo;
    const char *const *ppEnabledLayerNames;
    uint32_t enabledLayerCount;
    const char *const *ppEnabledExtensionNames;
    uint32_t enabledExtensionCount;
} VkInstanceCreateInfo_like;

#define VK_STRUCTURE_TYPE_APPLICATION_INFO 0
#define VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO 1

/* Handles used as opaque pointers. */
typedef void *VkInstance;
typedef void *VkPhysicalDevice;

static void *g_lib;
static void *(*g_gipa)(void *, const char *);  /* instance-level GPA */
static void *(*g_gpa_vk)(void *, const char *);  /* global-level GPA (instance=NULL) */
static VkInstance g_instance;
static uint32_t g_dev_count;
static char g_dev_names[8][256];
static int g_ok;

int wn_vk_init(void)
{
    if (g_ok)
        return 0;
    g_lib = dlopen("libvulkan.so.1", RTLD_LAZY | RTLD_LOCAL);
    if (!g_lib) {
        wn_log(WN_LOG_INFO, "vulkan: libvulkan.so.1 not available (%s)", dlerror());
        return -1;
    }
    g_gpa_vk = (void *(*)(void *, const char *))dlsym(g_lib, "vkGetInstanceProcAddr");
    if (!g_gpa_vk) {
        wn_log(WN_LOG_ERR, "vulkan: vkGetInstanceProcAddr missing");
        return -1;
    }
    g_gipa = (void *(*)(void *, const char *))g_gpa_vk(NULL, "vkGetInstanceProcAddr");

    int (*vkCreateInstance)(const VkInstanceCreateInfo_like *, void *, VkInstance *);
    int (*vkEnumeratePhysicalDevices)(VkInstance, uint32_t *, VkPhysicalDevice *);
    void (*vkGetPhysicalDeviceProperties)(VkPhysicalDevice, void *);

    /* Global-level resolution: only vkCreateInstance (and instance
     * enumeration helpers) are callable with a NULL instance. */
    vkCreateInstance = (void *)g_gpa_vk(NULL, "vkCreateInstance");
    if (!vkCreateInstance) {
        wn_log(WN_LOG_ERR, "vulkan: vkCreateInstance unresolvable");
        return -1;
    }

    VkApplicationInfo_like app = { 0 };
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "WinNux";
    app.applicationVersion = 1;
    app.pEngineName = "WinNux";
    app.engineVersion = 0;
    app.apiVersion = (1u << 22) | (0u << 12) | (0u << 0);   /* 1.0.0 base */

    VkInstanceCreateInfo_like ci = { 0 };
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &app;

    int rc = vkCreateInstance(&ci, NULL, &g_instance);
    if (rc != 0) {
        wn_log(WN_LOG_INFO, "vulkan: vkCreateInstance failed (%d)", rc);
        return -1;
    }
    /* Instance-level resolution once the instance exists. */
    vkEnumeratePhysicalDevices =
        (void *)g_gipa(g_instance, "vkEnumeratePhysicalDevices");
    vkGetPhysicalDeviceProperties =
        (void *)g_gipa(g_instance, "vkGetPhysicalDeviceProperties");
    if (!vkEnumeratePhysicalDevices || !vkGetPhysicalDeviceProperties) {
        wn_log(WN_LOG_ERR, "vulkan: instance-level entry points missing");
        return -1;
    }
    vkEnumeratePhysicalDevices(g_instance, &g_dev_count, NULL);
    if (g_dev_count > 8)
        g_dev_count = 8;
    VkPhysicalDevice devs[8];
    if (g_dev_count) {
        if (vkEnumeratePhysicalDevices(g_instance, &g_dev_count, devs) == 0) {
            for (uint32_t i = 0; i < g_dev_count; i++) {
                VkPhysicalDeviceProperties_like props;
                memset(&props, 0, sizeof props);
                vkGetPhysicalDeviceProperties(devs[i], &props);
                snprintf(g_dev_names[i], sizeof g_dev_names[i], "%.255s", props.deviceName);
            }
        }
    }
    g_ok = 1;
    return 0;
}

int wn_vk_available(void) { return g_ok; }

uint32_t wn_vk_physical_device_count(void)
{
    return g_ok ? g_dev_count : 0;
}

void wn_vk_device_name(uint32_t idx, char *out, size_t cap)
{
    if (!g_ok || idx >= g_dev_count || idx >= 8)
        snprintf(out, cap, "unknown");
    else
        snprintf(out, cap, "%.255s", g_dev_names[idx]);
}

void wn_vk_report(void)
{
    if (wn_vk_init() != 0) {
        printf("  vulkan:      not available (software fallback path)\n");
        return;
    }
    printf("  vulkan:      instance created, %u physical device(s)\n",
           g_dev_count);
    for (uint32_t i = 0; i < g_dev_count && i < 4; i++) {
        char name[256];
        wn_vk_device_name(i, name, sizeof name);
        printf("     [%u] %s\n", i, name);
    }
}

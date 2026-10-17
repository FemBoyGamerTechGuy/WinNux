/* stub_dlls.c — placeholder export tables for DLLs whose real
 * implementations come later (user32/gdi32 windows + ws2_32 sockets).
 * Empty tables are intentional: any import from these DLLs that is not
 * listed resolves to a loud stub that logs the call and returns failure.
 * This file shrinks as real modules land.
 */
#include "wn_dll.h"

const wn_export_entry wn_user32_exports[] = {
    { NULL, NULL },
};

const wn_export_entry wn_gdi32_exports[] = {
    { NULL, NULL },
};

const wn_export_entry wn_ws2_32_exports[] = {
    { NULL, NULL },
};

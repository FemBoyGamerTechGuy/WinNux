#include <ft2build.h>
#include FT_FREETYPE_H
#include <stdio.h>
#include <stddef.h>
int main(void) {
    printf("offsetof(FT_FaceRec, glyph)      = 0x%zx\n", offsetof(struct FT_FaceRec_, glyph));
    printf("offsetof(FT_FaceRec, size)       = 0x%zx\n", offsetof(struct FT_FaceRec_, size));
    printf("offsetof(FT_FaceRec, charmap)    = 0x%zx\n", offsetof(struct FT_FaceRec_, charmap));
    printf("sizeof(FT_FaceRec)               = 0x%zx\n", sizeof(struct FT_FaceRec_));
    printf("sizeof(FT_SizeRec)               = 0x%zx\n", sizeof(struct FT_SizeRec_));
    printf("offsetof(FT_SizeRec, metrics)    = 0x%zx\n", offsetof(struct FT_SizeRec_, metrics));
    printf("offsetof(FT_Size_Metrics, ascender) = 0x%zx\n", offsetof(FT_Size_Metrics, ascender));
    printf("sizeof(FT_GlyphSlotRec)          = 0x%zx\n", sizeof(struct FT_GlyphSlotRec_));
    printf("offsetof(FT_GlyphSlotRec, advance)  = 0x%zx\n", offsetof(struct FT_GlyphSlotRec_, advance));
    printf("offsetof(FT_GlyphSlotRec, format)   = 0x%zx\n", offsetof(struct FT_GlyphSlotRec_, format));
    printf("offsetof(FT_GlyphSlotRec, bitmap)   = 0x%zx\n", offsetof(struct FT_GlyphSlotRec_, bitmap));
    printf("offsetof(FT_GlyphSlotRec, bitmap_left)  = 0x%zx\n", offsetof(struct FT_GlyphSlotRec_, bitmap_left));
    printf("offsetof(FT_GlyphSlotRec, bitmap_top)   = 0x%zx\n", offsetof(struct FT_GlyphSlotRec_, bitmap_top));
    printf("offsetof(FT_Bitmap, buffer)      = 0x%zx\n", offsetof(struct FT_Bitmap_, buffer));
    printf("offsetof(FT_Bitmap, rows)        = 0x%zx\n", offsetof(struct FT_Bitmap_, rows));
    printf("offsetof(FT_Bitmap, width)       = 0x%zx\n", offsetof(struct FT_Bitmap_, width));
    printf("offsetof(FT_Bitmap, pitch)       = 0x%zx\n", offsetof(struct FT_Bitmap_, pitch));
    FT_Library lib; FT_Init_FreeType(&lib);
    FT_Face f; FT_New_Face(lib, "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 0, &f);
    FT_Set_Pixel_Sizes(f, 0, 16);
    FT_Load_Char(f, 'A', FT_LOAD_RENDER);
    printf("face->glyph slot = %p | glyph->advance.x = %ld | bitmap %ux%u\n",
           (void*)f->glyph, f->glyph->advance.x, f->glyph->bitmap.width, f->glyph->bitmap.rows);
    printf("size metrics: ascender=%ld descender=%ld height=%ld max_adv=%ld x_ppem=%u\n",
           f->size->metrics.ascender, f->size->metrics.descender,
           f->size->metrics.height, f->size->metrics.max_advance,
           (unsigned)f->size->metrics.x_ppem);
    return 0;
}

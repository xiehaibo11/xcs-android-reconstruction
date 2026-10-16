#ifndef XCS_GO_BYTE_PRIMITIVES_H
#define XCS_GO_BYTE_PRIMITIVES_H
#include <stddef.h>
#include <stdint.h>

/* Semantic reconstructions, not recovered original Go source.
 * The supplied non-null storage must actually span storage_size readable bytes.
 * Empty NULL storage is accepted only with size=offset=length=0.
 * Results are slice-relative. The original Go ABI byte input is zero extended.
 * Error codes are added checked-C API behavior, not original Go runtime errors.
 */
enum { XCS_OK=0, XCS_INVALID_ARGUMENT=-1, XCS_INVALID_RANGE=-2,
       XCS_NEEDS_PADDING=-3 };
int xcs_count_slice(const uint8_t *storage, size_t storage_size, size_t offset,
                    size_t length, unsigned target, uint64_t *result);
int xcs_index_slice(const uint8_t *storage, size_t storage_size, size_t offset,
                    size_t length, unsigned target, int64_t *result);
/* Same aligned-block read footprint as original ARM64 indexbytebody. Requires
 * storage to contain every 32-byte-aligned block intersecting the slice.
 * Returns XCS_NEEDS_PADDING instead of reading outside supplied storage.
 */
int xcs_index_padded_slice(const uint8_t *storage, size_t storage_size,
                          size_t offset, size_t length, unsigned target,
                          int64_t *result);
const char *xcs_byte_backend(void);
#endif

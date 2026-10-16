/* Benign, freestanding AArch64 sample: no execution is needed for inspection.
 * Exported JNI-shaped names make the sample resemble a small Android library.
 * Build instructions are in samples/README.md. No JNI headers are needed.
 */
typedef unsigned int u32;
typedef unsigned long usize;

extern int __android_log_write(int priority, const char *tag, const char *message);

__attribute__((noinline, visibility("hidden")))
int validate_quantity(int quantity) {
    if (quantity < 1) return -1;
    if (quantity > 20) return -2;
    return quantity;
}

__attribute__((noinline))
int calculate_total(int quantity, int unit_price, int member) {
    int checked = validate_quantity(quantity);
    if (checked < 0 || unit_price < 0 || unit_price > 100000) return -1;
    int total = checked * unit_price;
    if (member && total >= 1000) total -= total / 10;
    return total;
}

__attribute__((noinline))
u32 checksum_bytes(const unsigned char *bytes, usize length) {
    u32 hash = 2166136261u;
    for (usize i = 0; i < length; ++i) hash = (hash ^ bytes[i]) * 16777619u;
    return hash;
}

const char *build_label(void) { return "HexTrail demo / Android ARM64 / v0.1"; }

int Java_org_hextrail_demo_NativeBridge_quote(void *env, void *self,
                                               int quantity, int price, int member) {
    (void)env; (void)self;
    return calculate_total(quantity, price, member);
}

int Java_org_hextrail_demo_NativeBridge_logReady(void *env, void *self) {
    (void)env; (void)self;
    return __android_log_write(4, "HexTrail", "Native library ready for inspection");
}

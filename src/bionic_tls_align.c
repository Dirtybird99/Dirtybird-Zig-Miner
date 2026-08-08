#if defined(__aarch64__) && defined(__linux__)
static __thread __attribute__((aligned(64), used, retain, visibility("hidden")))
unsigned char dirtybird_bionic_tls_align_anchor;
#endif

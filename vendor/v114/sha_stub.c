#include "openssl/sha.h"
/* Stubs: the descriptor SA-build path never calls SHA (that's the hash-fused
 * path, which the Zig miner does in pure Zig). Present only to satisfy the linker. */
int SHA256_Init(SHA256_CTX* c){ (void)c; return 1; }
int SHA256_Update(SHA256_CTX* c, const void* d, size_t n){ (void)c;(void)d;(void)n; return 1; }
int SHA256_Final(unsigned char* o, SHA256_CTX* c){ (void)o;(void)c; return 1; }

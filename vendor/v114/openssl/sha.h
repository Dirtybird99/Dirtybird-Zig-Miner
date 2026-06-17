#ifndef V114_OPENSSL_SHA_STUB_H
#define V114_OPENSSL_SHA_STUB_H
#include <stdint.h>
#include <stddef.h>
typedef struct { uint8_t opaque[128]; } SHA256_CTX;
#ifdef __cplusplus
extern "C" {
#endif
int SHA256_Init(SHA256_CTX*);
int SHA256_Update(SHA256_CTX*, const void*, size_t);
int SHA256_Final(unsigned char*, SHA256_CTX*);
#ifdef __cplusplus
}
#endif
#endif

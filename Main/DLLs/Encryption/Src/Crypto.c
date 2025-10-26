/* Crypto.c
   Build example (MSVC + libsodium):
   cl /LD /DBUILDING_CRYPTO Crypto.c libsodium.lib /Fe:Crypto.dll
   Ensure libsodium include/lib paths set or use vcpkg.
*/

#define BUILDING_CRYPTO
#include "Crypto.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#define KEYBYTES crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define NONCEBYTES crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define MACBYTES crypto_aead_xchacha20poly1305_ietf_ABYTES

static int ensure_sodium() {
    static int init_done = 0;
    if (init_done) return 0;
    if (sodium_init() < 0) return -1;
    init_done = 1;
    return 0;
}

int Crypto_GenerateKey(unsigned char** out_key, int* out_len) {
    if (!out_key || !out_len) return -1;
    if (ensure_sodium() != 0) return -1;
    unsigned char* k = (unsigned char*)malloc(KEYBYTES);
    if (!k) return -1;
    randombytes_buf(k, KEYBYTES);
    *out_key = k;
    *out_len = KEYBYTES;
    return 0;
}

int Crypto_Encrypt(const unsigned char* input, int in_len,
                   unsigned char** output, int* out_len) {
    if (!input || in_len < 0 || !output || !out_len) return -1;
    if (ensure_sodium() != 0) return -1;

    /* key handling: for this simple DLL we derive a key from process-local entropy.
       In production you should supply a persistent key via secure storage or explicit API.
       Here we generate a one-time key per process invocation for demo, then free it.
    */
    unsigned char key[KEYBYTES];
    randombytes_buf(key, KEYBYTES);

    unsigned char nonce[NONCEBYTES];
    randombytes_buf(nonce, NONCEBYTES);

    size_t cipher_len = in_len + MACBYTES;
    unsigned char* cipher = (unsigned char*)malloc(NONCEBYTES + cipher_len);
    if (!cipher) return -1;

    /* place nonce at start */
    memcpy(cipher, nonce, NONCEBYTES);

    unsigned long long outlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            cipher + NONCEBYTES, &outlen,
            input, (unsigned long long)in_len,
            NULL, 0, /* no additional data */
            NULL, nonce, key) != 0) {
        free(cipher);
        sodium_memzero(key, KEYBYTES);
        return -1;
    }

    /* outlen should equal cipher_len */
    *output = cipher;
    *out_len = (int)(NONCEBYTES + outlen);

    /* wipe key from stack */
    sodium_memzero(key, KEYBYTES);
    return 0;
}

int Crypto_Decrypt(const unsigned char* input, int in_len,
                   unsigned char** output, int* out_len) {
    if (!input || in_len <= (int)NONCEBYTES || !output || !out_len) return -1;
    if (ensure_sodium() != 0) return -1;

    /* As above, this demo lacks persistent key management.
       Without a shared key decrypt will fail. In practice supply the same key used for encrypt.
       For integration with Scanner.dll you should implement Crypto_SetKey API to set a shared key.
    */
    unsigned char key[KEYBYTES];
    /* DEMO ONLY: we cannot decrypt without the original key. Return error. */
    (void)key;
    return -2; /* indicate not implemented: missing key management */
}

void Crypto_FreeBuffer(unsigned char* ptr) {
    if (!ptr) return;
    /* we do not know length; best-effort zeroing not performed here */
    free(ptr);
}

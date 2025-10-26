#pragma once

#ifdef _WIN32
  #ifdef BUILDING_CRYPTO
    #define CRYPTO_API __declspec(dllexport)
  #else
    #define CRYPTO_API __declspec(dllimport)
  #endif
#else
  #define CRYPTO_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Generate a new symmetric key.
   *out_key is malloc'd buffer (caller frees with Crypto_FreeBuffer).
   *out_len set to key length (bytes).
   Returns 0 on success, non-zero on error.
*/
CRYPTO_API int Crypto_GenerateKey(unsigned char** out_key, int* out_len);

/* Encrypt plaintext. Uses AEAD (XChaCha20-Poly1305).
   input: plaintext bytes (not null-terminated)
   in_len: plaintext length
   output: pointer set to malloc'd buffer containing [nonce(24) || ciphertext || mac]
   out_len: total length of output buffer
   Returns 0 on success.
*/
CRYPTO_API int Crypto_Encrypt(const unsigned char* input, int in_len,
                              unsigned char** output, int* out_len);

/* Decrypt buffer produced by Crypto_Encrypt.
   input: buffer produced by Crypto_Encrypt
   in_len: length of that buffer
   output: pointer set to malloc'd plaintext buffer
   out_len: plaintext length
   Returns 0 on success, non-zero on failure (auth failed, bad input).
*/
CRYPTO_API int Crypto_Decrypt(const unsigned char* input, int in_len,
                              unsigned char** output, int* out_len);

/* Free buffers returned by API (safe zeroing where applicable) */
CRYPTO_API void Crypto_FreeBuffer(unsigned char* ptr);

#ifdef __cplusplus
}
#endif

/* Scanner.c
   Build: cl /LD /DBUILDING_SCANNER Scanner.c /Fe:Scanner.dll
   - Integrates with Crypto.dll via LoadLibrary/GetProcAddress.
   - Encrypts sensitive JSON payloads using Crypto_Encrypt().
   - Encrypted data is base64-encoded before being inserted into the result JSON.
   - Replace stub detector functions with real detection logic.
*/

#define BUILDING_SCANNER
#include "shared_api.h"
#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#define MAX_SCANS 64
#define JSON_BUFFER_INCREMENT 4096

typedef struct {
    int id;
    int running; /* 1 running, 0 done, -1 stopped */
    char* result_json; /* malloc'd copy of latest JSON snapshot (may contain base64 encrypted payload) */
    CRITICAL_SECTION lock;
    HANDLE thread;
    char* target_json; /* copy of input config */
} ScanEntry;

static ScanEntry g_scans[MAX_SCANS];
static CRITICAL_SECTION g_table_lock;
static int g_initialized = 0;
static int g_next_id = 1;

/* --- Crypto.dll dynamic integration --- */
/* Expected exported functions in Crypto.dll:
   int Crypto_Encrypt(const unsigned char* input, int in_len, unsigned char** output, int* out_len);
   void Crypto_FreeBuffer(unsigned char* ptr);
*/
typedef int  (__cdecl *PFN_CRYPTO_ENCRYPT)(const unsigned char*, int, unsigned char**, int*);
typedef void (__cdecl *PFN_CRYPTO_FREE)(unsigned char*);

static HMODULE g_hCrypto = NULL;
static PFN_CRYPTO_ENCRYPT g_pfnCryptoEncrypt = NULL;
static PFN_CRYPTO_FREE g_pfnCryptoFree = NULL;
static CRITICAL_SECTION g_crypto_lock;
static int g_crypto_loaded = 0;

static int load_crypto_dll_once(void) {
    EnterCriticalSection(&g_crypto_lock);
    if(g_crypto_loaded) { LeaveCriticalSection(&g_crypto_lock); return (g_pfnCryptoEncrypt && g_pfnCryptoFree) ? 0 : -1; }
    g_hCrypto = LoadLibraryA("Crypto.dll");
    if(!g_hCrypto) {
        g_crypto_loaded = 1;
        LeaveCriticalSection(&g_crypto_lock);
        return -1;
    }
    g_pfnCryptoEncrypt = (PFN_CRYPTO_ENCRYPT)GetProcAddress(g_hCrypto, "Crypto_Encrypt");
    g_pfnCryptoFree    = (PFN_CRYPTO_FREE)GetProcAddress(g_hCrypto, "Crypto_FreeBuffer");
    g_crypto_loaded = 1;
    LeaveCriticalSection(&g_crypto_lock);
    return (g_pfnCryptoEncrypt && g_pfnCryptoFree) ? 0 : -1;
}

/* --- utility: safe strdup and json builder --- */
static char* safe_strdup(const char* s) {
    if(!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if(p) memcpy(p, s, n);
    return p;
}

static void json_append(char** buf, const char* fmt, ...) {
    if(!buf) return;
    va_list ap;
    while (1) {
        size_t cur_len = *buf ? strlen(*buf) : 0;
        size_t avail = JSON_BUFFER_INCREMENT;
        char* tmp = (char*)realloc(*buf, cur_len + avail + 1);
        if(!tmp) return;
        *buf = tmp;
        va_start(ap, fmt);
        int written = vsnprintf(*buf + cur_len, (int)avail + 1, fmt, ap);
        va_end(ap);
        if (written >= 0 && (size_t)written <= avail) break;
        /* else loop to realloc larger (increase avail via next loop) */
    }
}

/* --- base64 encode (for safe JSON embedding of binary cipher text) --- */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char* base64_encode(const unsigned char* data, int len) {
    if(!data || len <= 0) return NULL;
    int out_len = 4 * ((len + 2) / 3);
    char* out = (char*)malloc(out_len + 1);
    if(!out) return NULL;
    char* p = out;
    int i;
    for(i = 0; i < len - 2; i += 3) {
        *p++ = b64_table[(data[i] >> 2) & 0x3F];
        *p++ = b64_table[((data[i] & 0x3) << 4) | ((data[i+1] >> 4) & 0xF)];
        *p++ = b64_table[((data[i+1] & 0xF) << 2) | ((data[i+2] >> 6) & 0x3)];
        *p++ = b64_table[data[i+2] & 0x3F];
    }
    if(i < len) {
        unsigned char a = data[i++];
        unsigned char b = (i < len) ? data[i++] : 0;
        *p++ = b64_table[(a >> 2) & 0x3F];
        *p++ = b64_table[((a & 0x3) << 4) | ((b >> 4) & 0xF)];
        if(i <= len) *p++ = (i == len+1) ? '=' : b64_table[((b & 0xF) << 2)];
        else *p++ = '=';
        *p++ = '=';
    }
    *p = '\0';
    return out;
}

/* --- Stub detectors (replace with real checks) --- */
static void check_apt_indicators(const char* target_json, char** findings_json) {
    /* STUB: add sample finding */
    json_append(findings_json,
        "{\"type\":\"apt_indicator\",\"title\":\"Suspicious persistence: Unknown scheduled task\",\"desc\":\"Scheduled task 'SysUpdate' executes unsigned binary from AppData.\",\"risk\":\"high\",\"confidence\":85,\"remediation\":\"Disable task; quarantine binary; collect hashes.\"},");
}
static void check_exploit_vectors(const char* target_json, char** findings_json) {
    json_append(findings_json,
        "{\"type\":\"penetration_vector\",\"title\":\"RDP without Network Level Authentication\",\"desc\":\"RDP enabled without NLA.\",\"risk\":\"medium\",\"confidence\":80,\"remediation\":\"Require NLA; firewall restrict.\"},");
}
static void check_config_misconfig(const char* target_json, char** findings_json) {
    json_append(findings_json,
        "{\"type\":\"misconfiguration\",\"title\":\"SMB share writable by Everyone\",\"desc\":\"Share 'Public' allows Everyone:FullControl.\",\"risk\":\"high\",\"confidence\":90,\"remediation\":\"Restrict share permissions.\"},");
}
static void check_signs_of_credential_theft(const char* target_json, char** findings_json) {
    /* leave empty for variety */
}

/* Build the result JSON snapshot from findings list.
   If encryption succeeds, the "findings" field contains {"encrypted": "<base64>"}.
   Otherwise it contains the plaintext findings array.
*/
static char* build_result_json_maybe_encrypted(int scan_id, const char* status, const char* target_json, char* findings_concat) {
    char* plain = NULL;
    json_append(&plain, "{");
    json_append(&plain, "\"id\":%d,", scan_id);
    json_append(&plain, "\"status\":\"%s\",", status ? status : "unknown");
    json_append(&plain, "\"targets\":%s,", target_json ? target_json : "null");
    json_append(&plain, "\"timestamp\":%llu,", (unsigned long long) GetTickCount64());
    /* append findings array as plaintext first */
    json_append(&plain, "\"findings\":[");
    if(findings_concat && strlen(findings_concat) > 0) {
        size_t len = strlen(findings_concat);
        if(findings_concat[len-1] == ',') findings_concat[len-1] = '\0';
        json_append(&plain, "%s", findings_concat);
    }
    json_append(&plain, "]");
    json_append(&plain, "}");
    /* Try encrypting the findings array only to protect sensitive details */
    /* Find the substring for "findings":[ ... ] and encrypt only its contents */
    /* For simplicity, encrypt the entire plain JSON payload; Crypto.dll users can decrypt the whole blob */
    /* Use Crypto.dll if available */
    if(load_crypto_dll_once() == 0 && g_pfnCryptoEncrypt) {
        unsigned char* out_buf = NULL;
        int out_len = 0;
        int ok = g_pfnCryptoEncrypt((const unsigned char*)plain, (int)strlen(plain), &out_buf, &out_len);
        if(ok == 0 && out_buf && out_len > 0) {
            char* b64 = base64_encode(out_buf, out_len);
            /* build JSON containing encrypted base64 */
            char* encjson = NULL;
            json_append(&encjson, "{");
            json_append(&encjson, "\"id\":%d,", scan_id);
            json_append(&encjson, "\"status\":\"%s\",", status ? status : "unknown");
            json_append(&encjson, "\"targets\":%s,", target_json ? target_json : "null");
            json_append(&encjson, "\"timestamp\":%llu,", (unsigned long long) GetTickCount64());
            json_append(&encjson, "\"findings\":{\"encrypted\":1,\"blob\":\"%s\"}", b64 ? b64 : "");
            json_append(&encjson, "}");
            if(b64) free(b64);
            g_pfnCryptoFree(out_buf);
            free(plain);
            return encjson;
        }
        /* fallback: encryption failed -> return plaintext */
        if(out_buf) g_pfnCryptoFree(out_buf);
    }
    return plain;
}

/* Worker thread */
static unsigned __stdcall scan_thread_func(void* arg) {
    ScanEntry* e = (ScanEntry*)arg;
    if(!e) return 0;
    EnterCriticalSection(&e->lock);
    e->running = 1;
    if(e->result_json) { free(e->result_json); e->result_json = NULL; }
    LeaveCriticalSection(&e->lock);

    char* findings = NULL;

    /* Run detectors */
    check_apt_indicators(e->target_json, &findings);
    check_exploit_vectors(e->target_json, &findings);
    check_config_misconfig(e->target_json, &findings);
    check_signs_of_credential_theft(e->target_json, &findings);

    /* simulate scan time */
    Sleep(1000);

    char* final = build_result_json_maybe_encrypted(e->id, "done", e->target_json, findings);

    EnterCriticalSection(&e->lock);
    if(e->result_json) free(e->result_json);
    e->result_json = final;
    e->running = 0;
    LeaveCriticalSection(&e->lock);

    if(findings) free(findings);
    return 0;
}

/* Initialize table once */
static void ensure_initialized() {
    if(g_initialized) return;
    InitializeCriticalSection(&g_table_lock);
    InitializeCriticalSection(&g_crypto_lock);
    for(int i=0;i<MAX_SCANS;i++) {
        g_scans[i].id = 0;
        g_scans[i].running = 0;
        g_scans[i].result_json = NULL;
        g_scans[i].target_json = NULL;
        InitializeCriticalSection(&g_scans[i].lock);
        g_scans[i].thread = NULL;
    }
    g_initialized = 1;
}

/* Find empty slot */
static int allocate_slot() {
    EnterCriticalSection(&g_table_lock);
    for(int i=0;i<MAX_SCANS;i++) {
        if(g_scans[i].id == 0) {
            int id = g_next_id++;
            g_scans[i].id = id;
            LeaveCriticalSection(&g_table_lock);
            return i;
        }
    }
    LeaveCriticalSection(&g_table_lock);
    return -1;
}

/* Public API implementations */

int Scanner_StartScan(const char* target_json) {
    ensure_initialized();
    int slot = allocate_slot();
    if(slot < 0) return -1;
    ScanEntry* e = &g_scans[slot];
    EnterCriticalSection(&e->lock);
    e->running = 1;
    e->target_json = safe_strdup(target_json ? target_json : "{}");
    if(e->result_json) { free(e->result_json); e->result_json = NULL; }
    unsigned threadID;
    e->thread = (HANDLE)_beginthreadex(NULL, 0, scan_thread_func, e, 0, &threadID);
    if(!e->thread) {
        free(e->target_json); e->target_json = NULL;
        e->id = 0;
        e->running = 0;
        LeaveCriticalSection(&e->lock);
        return -1;
    }
    int id = e->id;
    LeaveCriticalSection(&e->lock);
    return id;
}

int Scanner_StopScan(int scan_id) {
    ensure_initialized();
    for(int i=0;i<MAX_SCANS;i++) {
        ScanEntry* e = &g_scans[i];
        EnterCriticalSection(&e->lock);
        if(e->id == scan_id) {
            if(e->running == 1) {
                /* cooperative stop: mark stopped */
                e->running = -1;
            }
            LeaveCriticalSection(&e->lock);
            return 0;
        }
        LeaveCriticalSection(&e->lock);
    }
    return -1;
}

char* Scanner_GetResult(int scan_id) {
    ensure_initialized();
    for(int i=0;i<MAX_SCANS;i++) {
        ScanEntry* e = &g_scans[i];
        EnterCriticalSection(&e->lock);
        if(e->id == scan_id) {
            if(e->result_json) {
                char* copy = safe_strdup(e->result_json);
                LeaveCriticalSection(&e->lock);
                return copy;
            } else {
                char* interim = NULL;
                json_append(&interim, "{\"id\":%d,\"status\":\"%s\"}", e->id, e->running==1? "running" : (e->running==-1? "stopped":"unknown"));
                LeaveCriticalSection(&e->lock);
                return interim;
            }
        }
        LeaveCriticalSection(&e->lock);
    }
    return NULL;
}

void Scanner_FreeResult(char* ptr) {
    if(ptr) free(ptr);
}

int Scanner_SetOption(const char* key, const char* value) {
    (void)key; (void)value;
    return 0;
}

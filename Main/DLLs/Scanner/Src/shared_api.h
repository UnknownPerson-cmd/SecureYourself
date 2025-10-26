#pragma once

#ifdef _WIN32
  #ifdef BUILDING_SCANNER
    #define SCAN_API __declspec(dllexport)
  #else
    #define SCAN_API __declspec(dllimport)
  #endif
#else
  #define SCAN_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Start a scan. target_json is UTF-8 JSON describing what to scan.
   Returns scan_id (>0) or -1 on error. */
SCAN_API int Scanner_StartScan(const char* target_json);

/* Stop an ongoing scan. Returns 0 on success, -1 if not found. */
SCAN_API int Scanner_StopScan(int scan_id);

SCAN_API char* Scanner_GetResult(int scan_id);

/* Free a result buffer returned by Scanner_GetResult */
SCAN_API void Scanner_FreeResult(char* ptr);

/* Optional config setter (key,value). Returns 0 on success. */
SCAN_API int Scanner_SetOption(const char* key, const char* value);

#ifdef __cplusplus
}
#endif

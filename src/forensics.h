#ifndef FORENSICS_H
#define FORENSICS_H

#include <stddef.h>

// Progress callback: fraction goes from 0.0 to 1.0
typedef void (*progress_cb)(double fraction, const char *status_text, void *user_data);

// Callback when a carved file is found and written
typedef void (*carve_found_cb)(const char *filename, long long offset, size_t size, void *user_data);

// Callback when a text signature / password / key is found
typedef void (*search_found_cb)(const char *match_type, const char *matched_text, long long offset, void *user_data);

/**
 * Dump partition from src_device (e.g., /dev/sdb1) to dest_path
 * Returns 0 on success, non-zero on failure.
 */
int dump_partition(const char *src_device, const char *dest_path, progress_cb callback, void *user_data, volatile int *cancel_flag);

/**
 * Carve files from a raw image dump
 * Returns 0 on success, non-zero on failure.
 */
int carve_files(const char *image_path, const char *output_dir,
                int carve_jpg, int carve_png, int carve_pdf, int carve_zip,
                progress_cb p_callback, carve_found_cb f_callback, void *user_data, volatile int *cancel_flag);

/**
 * Search image dump for passwords, keys, encryption keys, and emails
 * Returns 0 on success, non-zero on failure.
 */
int search_signatures(const char *image_path, const char *custom_search_term,
                      int search_keys, int search_emails, int search_passwords,
                      progress_cb p_callback, search_found_cb s_callback, void *user_data, volatile int *cancel_flag);

#endif // FORENSICS_H

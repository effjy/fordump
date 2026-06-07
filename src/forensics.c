#include "forensics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#define CHUNK_SIZE (1024 * 1024) // 1MB chunks
#define OVERLAP_SIZE (4096)      // 4KB overlap
#define MAX_SIG_LEN (8)         // Longest magic signature length
#define MAX_TEXT_LEN (65536)     // Maximum text segment length

// Recursively create directories (like mkdir -p)
static int ensure_dir(const char *path) {
    if (!path) return -1;
    struct stat st = {0};
    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode) ? 0 : -1;
    }
    char *tmp = strdup(path);
    if (!tmp) return -1;
    char *p = tmp;
    if (*p == '/') p++;
    while (*p) {
        if (*p == '/') {
            *p = '\0';
            if (stat(tmp, &st) == -1) {
                if (mkdir(tmp, 0755) == -1) {
                    free(tmp);
                    return -1;
                }
            }
            *p = '/';
        }
        p++;
    }
    int ret = 0;
    if (stat(tmp, &st) == -1) {
        ret = mkdir(tmp, 0755);
    }
    free(tmp);
    return ret;
}

// Helper to determine file size (supporting both regular files and block devices)
static long long get_file_size(const char *path) {
    if (!path) return -1;
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    if (st.st_size > 0) return st.st_size;

    // For block devices or special files where st.st_size might be 0, try ioctl/lseek
    int fd = open(path, O_RDONLY);
    if (fd < 0) return st.st_size; // fallback to stat size

    long long size = -1;
    unsigned long long dev_size = 0;
    if (ioctl(fd, BLKGETSIZE64, &dev_size) == 0) {
        size = (long long)dev_size;
    } else {
        size = lseek(fd, 0, SEEK_END);
    }
    close(fd);
    return size;
}

// Helper to write all bytes, retrying on partial writes
static ssize_t write_fully(int fd, const void *buf, size_t count) {
    const char *ptr = (const char *)buf;
    size_t remaining = count;
    while (remaining > 0) {
        ssize_t written = write(fd, ptr, remaining);
        if (written < 0) return -1;
        if (written == 0) return (ssize_t)(count - remaining);
        ptr += written;
        remaining -= written;
    }
    return (ssize_t)count;
}

// Dump partition logic
int dump_partition(const char *src_device, const char *dest_path, progress_cb callback, void *user_data, volatile int *cancel_flag) {
    int src_fd = open(src_device, O_RDONLY);
    if (src_fd < 0) {
        if (callback) {
            callback(0.0, "Error: Could not open source device (requires root/sudo?)", user_data);
        }
        return -1;
    }

    int dest_fd = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dest_fd < 0) {
        close(src_fd);
        if (callback) {
            callback(0.0, "Error: Could not open/create destination file", user_data);
        }
        return -2;
    }

    // Attempt to get source size via ioctl (works for block devices)
    long long total_size = -1;
    unsigned long long dev_size = 0;
    if (ioctl(src_fd, BLKGETSIZE64, &dev_size) == 0) {
        total_size = (long long)dev_size;
    } else {
        // Fallback to lseek for regular files
        total_size = lseek(src_fd, 0, SEEK_END);
        lseek(src_fd, 0, SEEK_SET);
    }

    char *buffer = malloc(CHUNK_SIZE);
    if (!buffer) {
        if (callback) callback(0.0, "Error: Memory allocation failed", user_data);
        close(src_fd);
        close(dest_fd);
        return -3;
    }

    long long bytes_copied = 0;
    ssize_t bytes_read;

    while (!(cancel_flag && *cancel_flag) && (bytes_read = read(src_fd, buffer, CHUNK_SIZE)) > 0) {
        ssize_t bytes_written = write_fully(dest_fd, buffer, bytes_read);
        if (bytes_written != bytes_read) {
            if (callback) {
                callback((double)bytes_copied / (total_size > 0 ? total_size : 1), "Error writing to destination dump file", user_data);
            }
            free(buffer);
            close(src_fd);
            close(dest_fd);
            return -4;
        }

        bytes_copied += bytes_read;
        if (callback) {
            double fraction = 0.0;
            char msg[128];
            if (total_size > 0) {
                fraction = (double)bytes_copied / total_size;
                snprintf(msg, sizeof(msg), "Acquiring: %.1f MB / %.1f MB (%.1f%%)",
                         (double)bytes_copied / (1024*1024),
                         (double)total_size / (1024*1024),
                         fraction * 100.0);
            } else {
                snprintf(msg, sizeof(msg), "Acquiring: %.1f MB copied (size unknown)",
                         (double)bytes_copied / (1024*1024));
            }
            callback(fraction, msg, user_data);
        }
    }

    if (cancel_flag && *cancel_flag) {
        if (callback) callback(0.0, "Acquisition cancelled by user.", user_data);
        free(buffer);
        close(src_fd);
        close(dest_fd);
        return -5;
    }

    free(buffer);
    close(src_fd);
    close(dest_fd);

    if (callback) {
        callback(1.0, "Dump acquired successfully", user_data);
    }
    return 0;
}

// Magic bytes signatures
// JPEG
static const unsigned char JPEG_START[] = {0xFF, 0xD8, 0xFF};
static const unsigned char JPEG_END[] = {0xFF, 0xD9};
// PNG
static const unsigned char PNG_START[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
static const unsigned char PNG_END[] = {0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82};
// PDF
static const unsigned char PDF_START[] = {0x25, 0x50, 0x44, 0x46}; // %PDF
static const unsigned char PDF_END[] = {0x25, 0x25, 0x45, 0x4F, 0x46}; // %%EOF
// ZIP
static const unsigned char ZIP_START[] = {0x50, 0x4B, 0x03, 0x04}; // PK..
static const unsigned char ZIP_END[] = {0x50, 0x4B, 0x05, 0x06}; // End of central directory signature

// Find signature offset helper — opens its own fd to avoid corrupting caller's fd position
static long long find_signature_offset(const char *image_path, long long start_offset, const unsigned char *sig, size_t sig_len, long long max_search) {
    int fd = open(image_path, O_RDONLY);
    if (fd < 0) return -1;

    if (lseek(fd, start_offset, SEEK_SET) == -1) {
        close(fd);
        return -1;
    }

    unsigned char temp_buf[8192];
    size_t carry = 0;
    long long scanned = 0;

    while (scanned < max_search) {
        ssize_t to_read = (ssize_t)(sizeof(temp_buf) - carry);
        ssize_t t_read = read(fd, temp_buf + carry, to_read);
        if (t_read <= 0) break;

        size_t active_bytes = carry + t_read;

        for (size_t j = 0; j + sig_len <= active_bytes; ++j) {
            if (memcmp(temp_buf + j, sig, sig_len) == 0) {
                long long match_offset = start_offset + scanned - (long long)carry + (long long)j;
                close(fd);
                return match_offset;
            }
        }

        // Keep last sig_len-1 bytes for cross-boundary matches
        carry = (active_bytes >= sig_len) ? sig_len - 1 : active_bytes;
        memmove(temp_buf, temp_buf + active_bytes - carry, carry);
        scanned += t_read;
    }

    close(fd);
    return -1;
}

// Match helper
static int matches(const unsigned char *buf, size_t buf_len, size_t offset, const unsigned char *sig, size_t sig_len, size_t carry) {
    if (offset + sig_len > buf_len) return 0;
    if (offset < carry && offset + sig_len <= carry) return 0;
    return memcmp(buf + offset, sig, sig_len) == 0;
}

// Carve a file block
static void carve_and_save(const char *image_path, long long start_offset, long long end_offset,
                           const char *ext, const char *output_dir, carve_found_cb f_callback, void *user_data) {
    long long size = end_offset - start_offset;
    if (size <= 0 || size > 50 * 1024 * 1024) return; // Limit to 50MB for carved files to avoid junk carving

    int src_fd = open(image_path, O_RDONLY);
    if (src_fd < 0) return;

    if (lseek(src_fd, start_offset, SEEK_SET) == -1) {
        close(src_fd);
        return;
    }

    ensure_dir(output_dir);

    char out_path[512];
    snprintf(out_path, sizeof(out_path), "%s/carved_%lld.%s", output_dir, start_offset, ext);

    int out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        close(src_fd);
        return;
    }

    char *buf = malloc(65536);
    if (!buf) {
        close(src_fd);
        close(out_fd);
        return;
    }

    long long remaining = size;
    while (remaining > 0) {
        long long chunk = (remaining > 65536) ? 65536 : remaining;
        ssize_t bytes_read = read(src_fd, buf, chunk);
        if (bytes_read <= 0) break;
        ssize_t bytes_written = write_fully(out_fd, buf, bytes_read);
        if (bytes_written != bytes_read) break;
        remaining -= bytes_read;
    }

    free(buf);
    close(out_fd);
    close(src_fd);

    if (f_callback) {
        char filename[256];
        snprintf(filename, sizeof(filename), "carved_%lld.%s", start_offset, ext);
        f_callback(filename, start_offset, size, user_data);
    }
}

// Carving files entrypoint
int carve_files(const char *image_path, const char *output_dir,
                int carve_jpg, int carve_png, int carve_pdf, int carve_zip,
                progress_cb p_callback, carve_found_cb f_callback, void *user_data, volatile int *cancel_flag) {

    long long file_size = get_file_size(image_path);
    if (file_size <= 0) {
        if (p_callback) p_callback(0.0, "Error: Invalid or empty image file", user_data);
        return -1;
    }

    int fd = open(image_path, O_RDONLY);
    if (fd < 0) {
        if (p_callback) p_callback(0.0, "Error: Could not open image file for analysis", user_data);
        return -2;
    }

    // Allocate scanning buffer
    unsigned char *buffer = malloc(CHUNK_SIZE);
    if (!buffer) {
        if (p_callback) p_callback(0.0, "Error: Memory allocation failed", user_data);
        close(fd);
        return -3;
    }

    long long current_offset = 0;
    ssize_t bytes_read = 0;
    size_t active_bytes = 0;

    if (p_callback) p_callback(0.0, "Starting file carving scan...", user_data);

    while (1) {
        if (cancel_flag && *cancel_flag) break;

        // Carry over overlap if not the first read
        size_t carry = 0;
        if (current_offset > 0) {
            carry = (active_bytes > OVERLAP_SIZE) ? OVERLAP_SIZE : active_bytes;
            memmove(buffer, buffer + active_bytes - carry, carry);
        }

        bytes_read = read(fd, buffer + carry, CHUNK_SIZE - carry);
        if (bytes_read < 0) {
            if (p_callback) p_callback(0.0, "Error: Failed reading from image file", user_data);
            free(buffer);
            close(fd);
            return -4;
        }

        active_bytes = carry + bytes_read;
        if (active_bytes == 0) break; // EOF

        // Scan the buffer — start after carry region to avoid re-detecting
        // signatures already found on the previous pass, but go back
        // MAX_SIG_LEN bytes to catch cross-boundary signatures.
        size_t scan_start = 0;
        if (current_offset > 0 && carry > 0) {
            scan_start = (carry > (MAX_SIG_LEN - 1)) ? carry - (MAX_SIG_LEN - 1) : 0;
        }

        for (size_t i = scan_start; i < active_bytes; ++i) {
            long long abs_offset = current_offset + i - carry;
            if (abs_offset < 0) abs_offset = 0;

            // Check JPEG
            if (carve_jpg && matches(buffer, active_bytes, i, JPEG_START, sizeof(JPEG_START), carry)) {
                long long sig_offset = find_signature_offset(image_path, abs_offset + sizeof(JPEG_START), JPEG_END, sizeof(JPEG_END), 10*1024*1024);
                if (sig_offset != -1) {
                    long long end_pos = sig_offset + sizeof(JPEG_END);
                    carve_and_save(image_path, abs_offset, end_pos, "jpg", output_dir, f_callback, user_data);
                }
            }
            // Check PNG
            else if (carve_png && matches(buffer, active_bytes, i, PNG_START, sizeof(PNG_START), carry)) {
                long long sig_offset = find_signature_offset(image_path, abs_offset + sizeof(PNG_START), PNG_END, sizeof(PNG_END), 20*1024*1024);
                if (sig_offset != -1) {
                    long long end_pos = sig_offset + sizeof(PNG_END);
                    carve_and_save(image_path, abs_offset, end_pos, "png", output_dir, f_callback, user_data);
                }
            }
            // Check PDF
            else if (carve_pdf && matches(buffer, active_bytes, i, PDF_START, sizeof(PDF_START), carry)) {
                long long sig_offset = find_signature_offset(image_path, abs_offset + sizeof(PDF_START), PDF_END, sizeof(PDF_END), 30*1024*1024);
                if (sig_offset != -1) {
                    long long end_pos = sig_offset + sizeof(PDF_END);
                    carve_and_save(image_path, abs_offset, end_pos, "pdf", output_dir, f_callback, user_data);
                }
            }
            // Check ZIP
            else if (carve_zip && matches(buffer, active_bytes, i, ZIP_START, sizeof(ZIP_START), carry)) {
                long long sig_offset = find_signature_offset(image_path, abs_offset + sizeof(ZIP_START), ZIP_END, sizeof(ZIP_END), 50*1024*1024);
                if (sig_offset != -1) {
                    // Read EOCD comment length to find true end
                    long long end_pos = sig_offset + 22; // minimum EOCD size
                    int eocd_fd = open(image_path, O_RDONLY);
                    if (eocd_fd >= 0) {
                        unsigned char comment_len_buf[2];
                        if (lseek(eocd_fd, sig_offset + 20, SEEK_SET) != -1 &&
                            read(eocd_fd, comment_len_buf, 2) == 2) {
                            unsigned int comment_len = comment_len_buf[0] | (comment_len_buf[1] << 8);
                            end_pos = sig_offset + 22 + comment_len;
                        }
                        close(eocd_fd);
                    }
                    carve_and_save(image_path, abs_offset, end_pos, "zip", output_dir, f_callback, user_data);
                }
            }
        }

        current_offset += bytes_read;

        if (p_callback) {
            double fraction = (double)current_offset / file_size;
            char msg[128];
            snprintf(msg, sizeof(msg), "Carving: %.1f%% (%.1f MB / %.1f MB)",
                     fraction * 100.0,
                     (double)current_offset / (1024*1024),
                     (double)file_size / (1024*1024));
            p_callback(fraction, msg, user_data);
        }

        if (bytes_read < (ssize_t)(CHUNK_SIZE - carry)) {
            // EOF reached
            break;
        }
    }

    free(buffer);
    close(fd);

    if (cancel_flag && *cancel_flag) {
        if (p_callback) p_callback(0.0, "Carving cancelled by user.", user_data);
    } else {
        if (p_callback) p_callback(1.0, "Carving scan completed.", user_data);
    }
    return 0;
}

// Password criteria checking: does the string look like a password or private key?
static int looks_like_password(const char *str) {
    size_t len = strlen(str);
    if (len < 8 || len > 64) return 0;
    
    // Check entropy/variety of characters
    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    for (size_t i = 0; i < len; ++i) {
        if (isupper((unsigned char)str[i])) has_upper = 1;
        else if (islower((unsigned char)str[i])) has_lower = 1;
        else if (isdigit((unsigned char)str[i])) has_digit = 1;
        else if (ispunct((unsigned char)str[i])) has_special = 1;
    }
    // High-entropy or dynamic complexity password guess:
    if (has_upper && has_lower && has_digit && len >= 8) return 1;
    if ((has_upper || has_lower) && has_digit && has_special && len >= 8) return 1;
    
    // Check if it matches typical credentials terms
    if (strcasestr(str, "password") || strcasestr(str, "passwd") || strcasestr(str, "secret") || strcasestr(str, "api_key")) {
        return 1;
    }
    return 0;
}

// Helper to check for email pattern
static int looks_like_email(const char *str) {
    size_t len = strlen(str);
    if (len < 5 || len > 80) return 0;
    const char *at = strchr(str, '@');
    if (!at || at == str || at == str + len - 1) return 0;
    const char *dot = strchr(at, '.');
    if (!dot || dot == at + 1 || dot == str + len - 1) return 0;
    
    // Check characters are valid
    for (size_t i = 0; i < len; ++i) {
        char c = str[i];
        if (isalnum((unsigned char)c) || c == '@' || c == '.' || c == '_' || c == '-' || c == '+') {
            continue;
        }
        return 0;
    }
    return 1;
}

// Analyze a text segment for forensic signatures/keywords
static void analyze_text_segment(const unsigned char *buffer, size_t text_start, size_t text_len,
                                 size_t carry, long long current_offset,
                                 const char *custom_search_term, int search_keys,
                                 int search_emails, int search_passwords,
                                 search_found_cb s_callback, void *user_data) {
    if (text_len < 5 || text_len >= MAX_TEXT_LEN) return;

    char *text_str = malloc(text_len + 1);
    if (!text_str) return;
    memcpy(text_str, buffer + text_start, text_len);
    text_str[text_len] = '\0';

    long long abs_offset = current_offset + text_start - carry;
    if (abs_offset < 0) abs_offset = 0;

    // 1. Custom search term
    if (custom_search_term && strlen(custom_search_term) > 0) {
        if (strcasestr(text_str, custom_search_term) != NULL) {
            if (s_callback) {
                s_callback("Custom Keyword Match", text_str, abs_offset, user_data);
            }
        }
    }

    // 2. SSH/PEM Private Key signatures
    if (search_keys) {
        if (strstr(text_str, "-----BEGIN") != NULL) {
            if (s_callback) {
                s_callback("Crypto Private Key Header", text_str, abs_offset, user_data);
            }
        }
    }

    // 3. Email signatures
    if (search_emails) {
        if (looks_like_email(text_str)) {
            if (s_callback) {
                s_callback("Email Address", text_str, abs_offset, user_data);
            }
        } else {
            // Search for substrings matching email
            char *saveptr = NULL;
            char *token = strtok_r(text_str, " \t\r\n():;,<>", &saveptr);
            while (token != NULL) {
                if (looks_like_email(token)) {
                    if (s_callback) {
                        s_callback("Email Address", token, abs_offset + (token - text_str), user_data);
                    }
                }
                token = strtok_r(NULL, " \t\r\n():;,<>", &saveptr);
            }
        }
        // strtok_r may have modified text_str; restore it for subsequent checks
        memcpy(text_str, buffer + text_start, text_len);
        text_str[text_len] = '\0';
    }

    // 4. Password / High-entropy strings
    if (search_passwords) {
        if (looks_like_password(text_str)) {
            if (s_callback) {
                s_callback("Potential Password/Credentials", text_str, abs_offset, user_data);
            }
        }
    }

    free(text_str);
}

// Search image dump logic
int search_signatures(const char *image_path, const char *custom_search_term,
                      int search_keys, int search_emails, int search_passwords,
                      progress_cb p_callback, search_found_cb s_callback, void *user_data, volatile int *cancel_flag) {

    long long file_size = get_file_size(image_path);
    if (file_size <= 0) {
        if (p_callback) p_callback(0.0, "Error: Invalid or empty image file", user_data);
        return -1;
    }

    int fd = open(image_path, O_RDONLY);
    if (fd < 0) {
        if (p_callback) p_callback(0.0, "Error: Could not open image file for searching", user_data);
        return -2;
    }

    unsigned char *buffer = malloc(CHUNK_SIZE);
    if (!buffer) {
        if (p_callback) p_callback(0.0, "Error: Memory allocation failed", user_data);
        close(fd);
        return -3;
    }

    long long current_offset = 0;
    ssize_t bytes_read = 0;
    size_t active_bytes = 0;

    if (p_callback) p_callback(0.0, "Starting forensic search scan...", user_data);

    while (1) {
        if (cancel_flag && *cancel_flag) break;

        size_t carry = 0;
        if (current_offset > 0) {
            carry = (active_bytes > OVERLAP_SIZE) ? OVERLAP_SIZE : active_bytes;
            memmove(buffer, buffer + active_bytes - carry, carry);
        }

        bytes_read = read(fd, buffer + carry, CHUNK_SIZE - carry);
        if (bytes_read < 0) {
            if (p_callback) p_callback(0.0, "Error: Failed reading from image file", user_data);
            free(buffer);
            close(fd);
            return -4;
        }

        active_bytes = carry + bytes_read;
        if (active_bytes == 0) break; // EOF

        // Scan for strings / keywords / patterns
        // Start scanning at index 0 to ensure that text spanning the boundary is scanned in the context of the new chunk.
        size_t scan_start = 0;
        size_t text_start = scan_start;
        int in_text = 0;

        for (size_t i = scan_start; i < active_bytes; ++i) {
            char c = buffer[i];
            int is_printable = (c >= 32 && c <= 126) || c == '\t' || c == '\n' || c == '\r';

            if (is_printable) {
                if (!in_text) {
                    text_start = i;
                    in_text = 1;
                }
            } else {
                if (in_text) {
                    size_t text_len = i - text_start;
                    // To avoid duplicates, only process if the segment ends at/after the carry boundary (i >= carry)
                    if (i >= carry) {
                        analyze_text_segment(buffer, text_start, text_len, carry, current_offset,
                                             custom_search_term, search_keys, search_emails, search_passwords,
                                             s_callback, user_data);
                    }
                    in_text = 0;
                }
            }
        }

        // Post-loop flush of trailing text segment
        if (in_text) {
            size_t text_len = active_bytes - text_start;
            // The segment ends at active_bytes, which is always >= carry
            analyze_text_segment(buffer, text_start, text_len, carry, current_offset,
                                 custom_search_term, search_keys, search_emails, search_passwords,
                                 s_callback, user_data);
            in_text = 0;
        }

        current_offset += bytes_read;

        if (p_callback) {
            double fraction = (double)current_offset / file_size;
            char msg[128];
            snprintf(msg, sizeof(msg), "Searching: %.1f%% (%.1f MB / %.1f MB)",
                     fraction * 100.0,
                     (double)current_offset / (1024*1024),
                     (double)file_size / (1024*1024));
            p_callback(fraction, msg, user_data);
        }

        if (bytes_read < (ssize_t)(CHUNK_SIZE - carry)) {
            break;
        }
    }

    free(buffer);
    close(fd);

    if (cancel_flag && *cancel_flag) {
        if (p_callback) p_callback(0.0, "Forensic search cancelled by user.", user_data);
    } else {
        if (p_callback) p_callback(1.0, "Forensic search completed.", user_data);
    }
    return 0;
}

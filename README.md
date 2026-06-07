# 🔍 Forensic Dump v2.0.2

[![C](https://img.shields.io/badge/Language-C-00599C.svg?style=for-the-badge&logo=c)](https://en.wikipedia.org/wiki/C_(programming_language))
[![GTK+3](https://img.shields.io/badge/GUI-GTK%2B3-7FE719.svg?style=for-the-badge&logo=gtk)](https://www.gtk.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)

**Forensic Dump** is a high-performance C and GTK3-based graphical application designed for digital forensics investigators and cybersecurity analysts. It enables multi-threaded, block-level partition acquisition, magic-byte file carving, and credentials/signature detection inside disk dump images.

---

## 🖥️ User Interface

Below is the **Credential / Key Search** interface showcasing found forensic signatures inside a target memory dump:

![Forensic Dump Screenshot](screenshot.png)

---

## ✨ Features

- **📂 Acquire (Dump Partition)**: Copy block devices (e.g., `/dev/sda1`, `/dev/sdb2`) byte-by-byte to flat raw image files (`.img`).
  - Utilizes Linux-specific `ioctl(BLKGETSIZE64)` for precise block size detection.
  - Sequentially streams data through a 1MB double-buffered chunk queue.
- **🎨 File Carving**: Reconstruct and extract orphaned or deleted files without filesystem allocation metadata.
  - Supports **JPEG** (`.jpg`), **PNG** (`.png`), **PDF** (`.pdf`), and **ZIP** (`.zip` / `.docx` / `.xlsx`) parsing.
  - Implements a 4KB sliding overlap boundary scan to detect files straddling block sectors.
  - Parses EOCD comments dynamically to find the true end offset of ZIP archives.
- **🔎 Credential & Signature Search**: Scans image sectors for target patterns:
  - **Private Keys**: Matches PEM cryptographic structures (`-----BEGIN PRIVATE KEY-----`).
  - **Emails**: Identifies addresses via state-machine syntax checking.
  - **Credentials**: Heuristically scores printable strings for entropy/complexity.
  - **Custom Search**: Case-insensitive substring keywords.

---

## 🛠️ Prerequisites & Compilation

### Requirements
You must install GCC, GNU Make, GTK+3 development files, GLib, and Pkg-config:

```bash
sudo apt-get update
sudo apt-get install build-essential libgtk-3-dev pkg-config libglib2.0-dev
```

### Build
To compile the standalone `forensic-tool` binary, run:

```bash
make
```

---

## ⚙️ Installation & Desktop Launcher

To install the application globally (making it available in your desktop menus and system paths):

```bash
sudo make install
```

This will deploy:
1. Binary to `/usr/local/bin/forensic-tool`
2. Desktop shortcut launcher to `/usr/share/applications/forensic-tool.desktop`
3. Application icons to `/usr/share/icons/hicolor/scalable/apps/forensic-tool.png`

To remove all installed assets and database configs:

```bash
sudo make uninstall
```

---

## 📖 Usage Guide

1. **Start Application**: Run `forensic-tool` or launch "Forensic Dump v2.0.2" from your desktop launcher. *Note: Acquiring raw partitions requires administrative privileges (`sudo forensic-tool`).*
2. **Duplicating a Disk Partition**:
   - Provide a source device path (e.g. `/dev/sdb1` or click **Browse / Dev**).
   - Specify the output destination file (e.g. `dump.img`).
   - Click **Start Acquisition**.
3. **Extracting Deleted Files**:
   - Select the target `.img` file.
   - Choose a directory to save the carved files.
   - Select file formats to extract and click **Start File Carving**.
4. **Credential Scanning**:
   - Select the target dump image.
   - Toggle filters for Private Keys, Email Addresses, or Passwords.
   - Provide custom search terms if desired, and click **Start Search**.

---

## ⚡ Technical Architecture & Safety

- **POSIX Multi-Threading**: Core duplication and parsing loops are offloaded to background threads via the `pthread` API, keeping the GUI responsive.
- **GUI Telemetry Sync**: Telemetry parameters are packed and queued in the GLib main thread scheduler via `g_idle_add()`, avoiding race conditions and visual freezes.
- **Memory Safety**: Strict boundary-crossing validations (`offset < carry && offset + sig_len <= carry`) prevent duplicate findings and double-carving.
- **Robust Exception Handling**: Immediate status updates propagate back to the GUI on memory allocation (`malloc`) and system `read` failures.

---

## 📜 Changelog

### v2.0.2
- **Boundary Handling Improvements**: Fixed a bug where text signatures straddling 1MB chunk boundaries were split or truncated. The carry region is now scanned from index 0 inside `search_signatures`.
- **EOF Text Segment Flushing**: Added a post-loop flush to process text segments running up to the end of files or chunks.
- **PEM/SSH Key Support**: Increased the maximum text segment length cap to 65536 bytes (64KB) to avoid excluding large PEM/SSH keys.
- **Boundary Duplicate Carving**: Refactored signature matching to dynamically ignore signature occurrences lying completely within the carry overlap region, preventing duplicate file carving.
- **Error Callback Propagation**: Added progress status callback reporting on memory allocation and reading failures to resolve GUI "stuck running" states.
- **Block Device Size Support**: Robustified size queries for block devices (e.g., `/dev/sdb1`) in `get_file_size` using `ioctl(BLKGETSIZE64)` and `lseek` fallbacks.
- **GUI Thread Synchronization**: Restructured state changes to run exclusively in the main GTK GUI thread, preventing worker thread data races.

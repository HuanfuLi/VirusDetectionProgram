# Virus Detection Program

This project implements a C program designed to monitor a specified downloads directory for newly created files, analyze them for potential threats, and manage their details. The program integrates several functionalities including file system monitoring, cryptographic hashing, virus scanning via a third-party API, and file permission management.

## Features

  * **Real-time File Monitoring**: Continuously monitors a designated downloads directory for new file creations using `inotify`.
  * **SHA256 Hashing**: Calculates the SHA256 hash of newly detected files to ensure integrity and for identification purposes.
  * **Virus Scanning**: Uploads files to a virus scanning API (Cloudmersive by default, with a mention of VirusTotal in `uploadfile.c`) to determine if they are safe or malicious.
  * **Permission Management**: Automatically sets malicious files to read-only permissions (`S_IRUSR | S_IRGRP | S_IROTH`) for safety, restricting execution and modification. Safe files are noted as safe to open.
  * **File Metadata Storage**: Stores details of all processed files, including file name, file path, hash value, and scan result, in a linked list structure.
  * **Interactive User Interface**: Allows users to continue monitoring, print details of scanned files, or exit the program via command-line input.

## How It Works

1.  **Monitor Downloads**: The `monitor_downloads` function uses `inotify` to detect when a new file is created in the specified directory (e.g., `/home/dmpatil/Downloads`).
2.  **Hash File**: Once a new file is detected, its SHA256 hash is computed using OpenSSL's `EVP` interface.
3.  **Upload for Scanning**: The file is then uploaded to a virus scanning API (Cloudmersive API is used in `all_functions.c` and `final_code.c`; `uploadfile.c` suggests VirusTotal) for analysis. The API response indicates whether the file is malicious or safe.
      * **Note**: An API key (`07e1a67b-56c4-4645-8f81-5ac1794b690a` in `all_functions.c` and `final_code.c`, or `654b195cb28da51655e9777e2e97a45c915acea84524f209070b610825e8621b` in `uploadfile.c`) is required for the scanning service. This needs to be replaced with your actual API key.
4.  **Set Permissions**: Based on the scan result, the `setPermission` function adjusts the file's permissions. If the file is malicious, it is set to read-only.
5.  **Store Data**: The file's metadata (name, path, hash, and scan result) is stored in a dynamically managed linked list for record-keeping and display.

## Project Structure

The project consists of several C source files:

  * `final_code.c`: The main comprehensive file integrating all functionalities, including file monitoring, hashing, uploading, permission setting, and linked list management. This is the primary executable source.
  * `main_function.c`: Contains the main loop and user interaction logic, demonstrating how file processing and linked list operations are integrated.
  * `all_functions.c`: Contains the implementations for `monitor_downloads`, `hash_file`, `print_hash`, `uploadFile`, and `setPermission`, along with the `WriteMemoryCallback` function.
  * `setPermission.c`: Provides a standalone implementation and test driver for the `setPermission` function.
  * `uploadfile.c`: Offers an alternative implementation for uploading files, specifically referencing the VirusTotal API.

## Dependencies

This program requires the following libraries:

  * `stdio.h`: Standard input/output.
  * `stdlib.h`: Standard library for memory allocation (`malloc`, `realloc`, `free`, `exit`).
  * `sys/inotify.h`: For file system event monitoring.
  * `unistd.h`: For `read`, `close`, `perror`.
  * `limits.h`: For `PATH_MAX` and `NAME_MAX`.
  * `string.h`: For string manipulation (`strcpy`, `strlen`, `strncpy`, `strstr`, `memcpy`).
  * `openssl/evp.h`: For SHA256 hashing.
  * `curl/curl.h`: For HTTP requests and file uploads.
  * `sys/stat.h`: For changing file permissions (`chmod`, `S_IRUSR`, `S_IRGRP`, `S_IROTH`).
  * `stdbool.h`: For boolean data type.

## Compilation

To compile this project, you will need a C compiler (like GCC) and the development libraries for `inotify`, `OpenSSL`, and `libcurl`.

Example compilation command (may vary depending on your system and library paths):

```bash
gcc final_code.c -o virus_detector -linotify -lcrypto -lcurl -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -Wall
```

## Usage

1.  **Compile the program**: Follow the compilation instructions above.
2.  **Run the executable**:
    ```bash
    ./virus_detector
    ```
3.  **Monitor Files**: The program will start monitoring the `/home/dmpatil/Downloads` directory (or the path specified in `final_code.c`).
4.  **Interact**:
      * Enter `1` to continue monitoring for new files.
      * Enter `2` to print the details of all scanned files.
      * Enter `3` to exit the program.

## Group Members

  * Chris Park
  * Andy T
  * Dhanish Patil
  * Poomin P
  * Huanfu L

**Note**: AI was used to troubleshoot/fix parts of the program but was not used to generate the whole code.

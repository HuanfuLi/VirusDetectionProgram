#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <stdbool.h>
#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

// Callback function to write response data to a buffer
size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t totalSize = size * nmemb;
    char **response_ptr = (char **)userp;
    static size_t response_size = 0;

    // Reallocate memory to fit the new data
    char *temp = realloc(*response_ptr, response_size + totalSize + 1);
    if (temp == NULL) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    *response_ptr = temp;
    memcpy(&((*response_ptr)[response_size]), contents, totalSize);
    response_size += totalSize;
    (*response_ptr)[response_size] = 0;  // Null-terminate

    return totalSize;
}

int main() {
    char *monitor_downloads(char *);
    unsigned char* hash_file(const char *);
    char *uploadFile(char *);
    int setPermission(bool, char *);
    bool result = false;
    void print_hash(unsigned char *);
    char *path = "/home/dmpatil/Downloads";
    char filepath[500];
    char *filename = monitor_downloads(path); 
    sprintf(filepath, "/home/dmpatil/Downloads/%s", filename);
    unsigned char *file_hash = hash_file(filepath);
    print_hash(file_hash);
    char *response = uploadFile(filepath);
    printf("%s", response);  
    if (strstr(response, "true") != NULL)
    {
    	result = true;
    }
    if (strstr(response, "false") != NULL)
    {
    	result = false;
    }
    printf("\nResult: %s\n", result ? "true" : "false");
    setPermission(result, filepath);
    free(response); // Free the response after use
    free(file_hash);
    free(filename);  // Free the filename allocated in monitor_downloads
    return 0;
}

char *monitor_downloads(char *path) 
{
    int fd, wd;
    char buffer[EVENT_BUF_LEN];
    char *new_file_name = NULL;
    fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        exit(EXIT_FAILURE);
    }
    wd = inotify_add_watch(fd, path, IN_CREATE);
    if (wd == -1) {
        perror("inotify_add_watch");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("Monitoring directory: %s\n", path);

    while (1) {
        int length = read(fd, buffer, EVENT_BUF_LEN);
        if (length < 0) {
            perror("read");
            break;
        }
        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len && (event->mask & IN_CREATE)) {
                new_file_name = malloc(NAME_MAX);
                if (new_file_name == NULL) {
                    perror("malloc");
                    inotify_rm_watch(fd, wd);
                    close(fd);
                    return NULL;
                }
                strcpy(new_file_name, event->name);
                printf("File created: %s\n", new_file_name);
                inotify_rm_watch(fd, wd);
                close(fd);
                return new_file_name;
            }
            i += EVENT_SIZE + event->len;
        }
    }
    inotify_rm_watch(fd, wd);
    close(fd);
}

unsigned char* hash_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("File opening failed");
        return NULL;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fclose(file);
        return NULL;
    }

    const EVP_MD *sha256 = EVP_get_digestbyname("sha256");
    if (sha256 == NULL) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return NULL;
    }

    if (EVP_DigestInit_ex(mdctx, sha256, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return NULL;
    }

    unsigned char buffer[1024];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return NULL;
        }
    }

    fclose(file);

    unsigned char *hash = malloc(EVP_MD_size(sha256));
    if (hash != NULL) {
        if (EVP_DigestFinal_ex(mdctx, hash, NULL) != 1) {
            free(hash);
            hash = NULL;
        }
    }

    EVP_MD_CTX_free(mdctx);  
    
    return hash;
}

void print_hash(unsigned char *hash) 
{
    for (int i = 0; i < EVP_MD_size(EVP_get_digestbyname("sha256")); i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

char* uploadFile(char* filepath) {
    CURL *curl;
    CURLcode res;
    char *response = NULL;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.cloudmersive.com/virus/scan/file");
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: multipart/form-data");
        headers = curl_slist_append(headers, "Apikey: 07e1a67b-56c4-4645-8f81-5ac1794b690a"); // Replace with your API key
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_mime *mime = curl_mime_init(curl);
        curl_mimepart *part = curl_mime_addpart(mime);
        curl_mime_name(part, "inputFile");
        curl_mime_filedata(part, filepath);  
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        curl_mime_free(mime);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    return response;
}

int setPermission(bool result, char *filePath) {  
    if (!result) {
        if (chmod(filePath, S_IRUSR | S_IRGRP | S_IROTH) == -1) {
            perror("Failed to change file permission");
            return 1;
        }
        printf("This file is malicious, and permission is set to read-only for safety. Please contact your administrator!\n");
    } else {
        printf("This file is safe to open!\n");
    }
    return 0;
}


#include <stdio.h>
#include <stdlib.h>
#include <curl.h>


// API KEY HERE : 654b195cb28da51655e9777e2e97a45c915acea84524f209070b610825e8621b


int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <file_path> <API_key>\n", argv[0]);
        return 1;
    }

    const char *file_path = argv[1];
    const char *api_key = argv[2];

    CURL *hnd = curl_easy_init();
    if (!hnd) {
        fprintf(stderr, "Failed to initialize CURL\n");
        return 1;
    }

    // Set the URL for VirusTotal API file upload
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/files");
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");

    // Set headers including API key and content type
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    
    // Construct the authorization header with the API key
    char auth_header[256];
    snprintf(auth_header, sizeof(auth_header), "x-apikey: %s", api_key);
    headers = curl_slist_append(headers, auth_header);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    // Set the file to upload
    curl_mime *mime;
    curl_mimepart *part;

    mime = curl_mime_init(hnd);
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_filedata(part, file_path);
    curl_easy_setopt(hnd, CURLOPT_MIMEPOST, mime);

    // Set to write the response to stdout
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);

    // Perform the request
    CURLcode ret = curl_easy_perform(hnd);

    // Cleanup
    if (ret != CURLE_OK) {
        fprintf(stderr, "Error: %s\n", curl_easy_strerror(ret));
    }
    curl_easy_cleanup(hnd);
    curl_slist_free_all(headers);
    curl_mime_free(mime);

    return ret == CURLE_OK ? 0 : 1;
}

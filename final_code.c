//Description: This program is designed to monitor a the downloads directory for newly created files, analyze them, and manage their details. When a new file is detected, the program calculates its SHA256 hash, uploads the file to a virus scanning API (cloudmersive), and determines whether the file is safe or malicious based on the API's response. If the file is deemed malicious, its permissions are set to read-only for safety. All processed files are stored in a linked list, which contains details such as the file name, file path, hash value, and scan result.
//Group names: Chris Park, Andy T, Dhanish Patil, Poomin P, Huanfu L
//AI was used to troubleshoot/fix the program but was not used to generate the whole code below.
//Imported the following libraries 
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h> //to monitor a specific folder
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <openssl/evp.h> // for hashing the file 
#include <curl/curl.h> // use curl to upload file
#include <sys/stat.h>
#include <stdbool.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))
#define FULL_STRING_LENGTH 100

/* Functional Prototype: */
// Declare functions used for monitoring downloads, hashing files, uploading files,  managing file permissions, memory, and a linked list structure
char *monitor_downloads(char *);
unsigned char* hash_file(const char *);
char *uploadFile(char *);
char *print_hash(unsigned char *);
int setPermission(bool, char *);
void free_memory(unsigned char*, char*);
struct listofFiles {
    char *fileName;
    char *filePath;
    char *hash_of_file;
    bool resultPass;
    struct listofFiles* next;
};
struct listofFiles* createNode(char*, char*, char*, bool);
void addNode(struct listofFiles**, char*, char*, char*, bool);

// Main function is the function that organised the use of other functions like to monitor file creation, hash the file, upload it for scanning, set appropriate permissions based on results, and store data in a linked list.
int main() {
    int usr_input = 1;
    int counter_var = 0;
    char *path = "/home/dmpatil/Downloads";
    struct listofFiles *head = NULL; // Pointer to the first element of the list
     
    do {
        if (usr_input == 1) {
            
            /*
             * - 
             * - Uploading it for malware scanning
             * - Setting permissions based on scan results
             * - Adding its metadata to a linked list.
             */
             
            char *temp_filePath = malloc(PATH_MAX * sizeof(char));
    	    char *temp_fileName = monitor_downloads(path); //Monitor the directory for new files and if found it will save the file's name in this variable
            printf("%s", temp_fileName);
            snprintf(temp_filePath, PATH_MAX, "%s/%s", path, temp_fileName);
            printf("%s", temp_filePath);
            unsigned char *hash = hash_file(temp_filePath); //calcluates the hash and saves the hash value in binary
            char *temp_hash = print_hash(hash); // valves the hash value as hexadecimal string
            printf("%s", temp_hash);
            bool result = false;
            char *response = uploadFile(temp_filePath);
            printf("%s", response); //Saves the http response in this variable
            if (strstr(response, "true") != NULL) {
                result = true;
            } else if (strstr(response, "false") != NULL) {
                result = false;
            }
            setPermission(result, temp_filePath); // used to set teh permission of the file after scanning
            addNode(&head, temp_fileName , temp_filePath, temp_hash, result);// adds all the collected information into a node and adds it to the single link list
            counter_var++;
            free_memory(NULL, NULL);  
	    
        } else if (usr_input == 2) {
            /*
             * Print the details of all files processed, including their names,
             * paths, hashes, and scan results.
             */
            struct listofFiles* current = head;
            while (current != NULL) {
                printf("\nFile Name: %s", current->fileName);
                printf("\nFile Path: %s", current->filePath);
                printf("\nHash: %s", current->hash_of_file);
                printf("\nResult Passed?: %s\n", current->resultPass ? "true" : "false");
                current = current->next;
            }
       }else {
       /* Handle invalid user input */
            printf("\nWrong user input! Please type in the response accordingly.\n");
        }
	/* Ask user whether to continue, print results, or exit */
        printf("Do you want to continue running the program?\nEnter 1 to continue.\nEnter 2 to print the result.\nEnter 3 to exit\n");
        scanf("%i", &usr_input);
    } while (usr_input != 3);

    printf("\nGood bye!\n%d times have been iterated.\n", counter_var);

    return 0;
}
// Callback function for processing HTTP response data
size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    // Handles appending response data to a dynamic buffer for processing
    size_t totalSize = size * nmemb;
    char **response_ptr = (char **)userp;
    char *temp = realloc(*response_ptr, (totalSize + 1));
    if (temp == NULL) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    *response_ptr = temp;
    memcpy(*response_ptr, contents, totalSize);
    (*response_ptr)[totalSize] = '\0';
    return totalSize;
}

char *monitor_downloads(char *path) {
   // Uses inotify to monitor a directory for file creation events.
    
    int fd, wd;
    char buffer[EVENT_BUF_LEN];
    char *new_file_name = NULL;
 //Waits for a new file to be created in the specified directory.
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
                /*
                 * A new file is detected. Allocate memory for its name and return it.
                 */
                printf("Event received: %s\n", event->name); // Debugging output
                size_t name_len = strlen(event->name);
                new_file_name = malloc(name_len + 1); // Allocate memory for the file name
                if (new_file_name == NULL) {
                    perror("malloc");
                    inotify_rm_watch(fd, wd);
                    close(fd);
                    return NULL;
                }

                strncpy(new_file_name, event->name, name_len); // Copy the file name
                new_file_name[name_len] = '\0'; // Ensure null-termination

                printf("File created: %s\n", new_file_name);
                inotify_rm_watch(fd, wd);
                close(fd);
                //Returns the name of the newly created file.
                return new_file_name;
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
    return NULL;
}


unsigned char* hash_file(const char *filename) {
// Computes the SHA256 hash of a given file using OpenSSL's EVP interface.
    //Error handling if the file doesnot open or exists. 
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("File opening failed");
        return NULL;
    }

    // Initialize the EVP context for SHA256
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fclose(file);
        return NULL;
    }

    // Use EVP_Digest to select SHA256 algorithm dynamically
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

    // Read file in chunks and update the hash
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return NULL;
        }
    }

    fclose(file);

    // Allocate memory for the hash and finalize
    unsigned char *hash = malloc(EVP_MD_size(sha256));
    if (hash != NULL) {
        if (EVP_DigestFinal_ex(mdctx, hash, NULL) != 1) {
            free(hash);
            hash = NULL;
        }
    }

    EVP_MD_CTX_free(mdctx);  // Clean up EVP context
    return hash;
}

char *print_hash(unsigned char *hash) {
    //Converts the binary hash value to a readable hexadecimal string.
    char *hash_string = malloc(EVP_MD_size(EVP_get_digestbyname("sha256")) * 2 + 1);

    if (hash_string == NULL) {
        return NULL;
    }

    for (int i = 0; i < EVP_MD_size(EVP_get_digestbyname("sha256")); i++) {
        sprintf(&hash_string[i * 2], "%02x", hash[i]);
    }
    return hash_string;
}

void free_memory(unsigned char *hash, char *hash_string) {
//Frees allocated memory for the hash and hash string.

    if (hash != NULL) {
        free(hash);  // Free the allocated memory for the hash
    }
    if (hash_string != NULL) {
        free(hash_string);  // Free the allocated memory for the hash string 
    }
}

char* uploadFile(char* filepath) {
// Uploads a file to a virus scanning API using libcurl.
  

	CURL *curl;
	CURLcode res;
	char *response = NULL;

	curl = curl_easy_init();
	if (curl) {
    	
    	//Handles API authentication and file upload via multipart form-data.
    	curl_easy_setopt(curl, CURLOPT_URL, "https://api.cloudmersive.com/virus/scan/file");
    	struct curl_slist *headers = NULL;
    	headers = curl_slist_append(headers, "Content-Type: multipart/form-data");
    	
    	headers = curl_slist_append(headers, "Apikey: 07e1a67b-56c4-4645-8f81-5ac1794b690a"); // Replace with your API key
    	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    	curl_mime *mime = curl_mime_init(curl);
    	curl_mimepart *part = curl_mime_addpart(mime);
    	curl_mime_name(part, "inputFile");
    	//Uploads a file to a virus scanning API 
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
//Returns the API's response as a string or NULL if an error occurs.
	return response;
}

int setPermission(bool result, char *filePath) {  
// Sets the file's permissions based on the scan result.
	if (!result) {
    	//Files marked malicious are set to read-only.
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

struct listofFiles* createNode(char *fileName_temp, char *filePath_temp, char *hash_temp, bool resultPass_temp) {
	// function to create a node with the aquired data 
	struct listofFiles* newNode = (struct listofFiles*)malloc(sizeof(struct listofFiles));
	if (newNode == NULL) {
    	printf("Memory allocation failed\n");
    	exit(1);
	}
	//Populates the node with file metadata: name, path, hash, and scan result.
	newNode->fileName = fileName_temp;
	newNode->filePath = filePath_temp;
	newNode->hash_of_file = hash_temp;
	newNode->resultPass = resultPass_temp;
	newNode->next = NULL;
	return newNode;
}


void addNode(struct listofFiles** head, char *fileName_temp, char *filePath_temp, char 
*hash_temp, bool resultPass_temp) {
// Function to add a node to the beginning of the list
	struct listofFiles* newNode = createNode(fileName_temp, filePath_temp, hash_temp, resultPass_temp);
	newNode->next = *head;
	*head = newNode;
}




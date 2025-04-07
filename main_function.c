#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define FULL_STRING_LENGTH 100

struct listofFiles {
        char fileName;
        int filePath;
        char fileID;
        char hash;
        char dateScanned;
        bool resultPass;
        struct Node* next;
    };

// Function to create a new node
struct Node* createNode(char fileName_temp, int filePath_temp, char fileID_temp, char hash_temp, char dateScanned_temp, bool resultPass_temp) {
    struct listofFiles* newNode = (struct Node*)malloc(sizeof(struct listofFiles));
    if (newNode == NULL) {
        printf("Memory allocation failed\n");
        exit(1);
    }
    newNode->fileName = fileName_temp;
    newNode->filePath = filePath_temp;
    newNode->fileID = fileID_temp;
    newNode->hash = hash_temp;
    newNode->dateScanned = dateScanned_temp;
    newNode->resultPass = resultPass_temp;
    newNode->next = NULL;
    return newNode;
}

// Function to add a node to the beginning of the list
void addNode(struct Node** head, char fileName_temp, int filePath_temp, char fileID_temp, char hash_temp, char dateScanned_temp, bool resultPass_temp) {
    struct listofFiles* newNode = createNode(fileName_temp, filePath_temp, fileID_temp, hash_temp, dateScanned_temp, resultPass_temp);
    newNode->next = *head;
    *head = newNode;
}

/*
// Function to modify a node's data
void modifyNode(struct listofFiles* node, const char* newFileName, const char* newFilePath,
                const char* newFileID, const char* newHash, const char* newDateScanned,
                bool newResultPass) {
    if (node == NULL) {
        printf("Node is NULL\n");
        return;
    }

    setField(&node->fileName, newFileName);
    setField(&node->filePath, newFilePath);
    setField(&node->fileID, newFileID);
    setField(&node->hash, newHash);
    setField(&node->dateScanned, newDateScanned);
    node->resultPass = newResultPass;
}
*/

int main() {
    int usr_input = 1;
    int counter_var = 0;
    struct listofFiles *head = NULL; //Needed to start the pointer to the first element of the list

    do {
        if (usr_input == 1) {
            char temp_fileName;
            int temp_filePath;
            char temp_fileID;
            char temp_hash;
            char temp_dateScanned;
            bool temp_resultPass;
            bool result_pass_from_node; //for testing purposes

            //Have all the codes

            addNode(&head, temp_fileName, temp_filePath, temp_fileID, temp_hash, temp_dateScanned, temp_resultPass);

            result_pass_from_node = head->resultPass; //how to retrieve the data from the node


            counter_var += 1;
        }
        else if (usr_input == 2 ) {
            //print command

        }
        else if (usr_input) {
            //Goodbye and state how many time it has run

        }
        else {
            printf("\nWrong user input! Please type in the response accordingly.\n");
        }

        printf("Do you want to continue running the program?\nEnter 1 to continue.\nEnter 2 to print the result.\nEnter 3 to exit\n");
        scanf("%i", usr_input);
    }
    while (usr_input != 3);


    //addNode(&temp_node,temp_fileName, temp_filePath, temp_fileID, temp_hash, temp_dateScanned, temp_resultPass);

    }
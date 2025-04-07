#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdbool.h>

//Below is drive code only for individual test.
int setPermission(bool result, char *filePath);
int main()
{
    const char *filePath = "example.txt";
    bool result = true;
    setPermission(true, "example.txt");
    return 1;
}
//Above is drive code only for individual test.



int setPermission(bool result, char *filePath)
{  
//Change the permission based on the result:
    if (result == true)
    {
        if(chmod(filePath, S_IRUSR | S_IRGRP | S_IROTH) == -1)                           //Set permission to read only to owner/group/others.
        {
            perror("Failed to change file permission");               //Handle exceptions.
            return 1;
        }
        printf("This file is malicious, and permission is set to read only for safety. Please contact your administrator!");
    }
    if (result == false)
    {
        printf("This file is safe to open!");
        return 1;
    }
}

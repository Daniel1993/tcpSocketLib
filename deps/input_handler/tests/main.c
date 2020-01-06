#include "input_handler.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    input_parse(argc, argv);

    if (input_exists("INPUT")) {
        printf("INPUT=%li\n", input_getLong("INPUT"));
    } else {
        printf("INPUT not found\n");
    }


    return EXIT_SUCCESS;
}


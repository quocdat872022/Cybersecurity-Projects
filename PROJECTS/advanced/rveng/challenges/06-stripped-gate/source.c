#include <stdio.h>
#include <stdlib.h>

int check(int n) {
    if (n == 1337) {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    char *secret = "the_flag_is_here";
    int n = 0;
    if (argc > 1) {
        n = atoi(argv[1]);
    }
    if (check(n)) {
        printf("unlocked: %s\n", secret);
    } else {
        printf("wrong number\n");
    }
    return 0;
}

#include <stdio.h>

void b(void) {
    printf("in b\n");
}

void a(void) {
    b();
}

void c(void) {
    printf("in c\n");
}

int main(void) {
    a();
    c();
    return 0;
}

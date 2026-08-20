#include <stdio.h>
#include <unistd.h>

volatile int counter = 0;

int compute(int x) {
    int y = x * 2 + 1;
    return y;
}

int main(void) {
    for (int i = 0; i < 5; i++) {
        counter = compute(i);
        printf("iteration %d -> counter=%d\n", i, counter);
        fflush(stdout);
        usleep(10000);
    }
    return 0;
}

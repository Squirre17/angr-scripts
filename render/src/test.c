#include <stdlib.h>
#include <unistd.h>

int outside(int a) {
    return a + 3;
}

void test() {

    int b = outside('A');// outside edge
    if(b > 0)
        goto tmp;// direct jmp
    int c = b + 3;
tmp:
    write(1, &b, 4);// fake return edge

}


int main() {
    test();
    return 0;
}
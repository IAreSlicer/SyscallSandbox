// Skeleton Syscall User Dispatch sandbox
#include <iostream>
#include <cstrdlib>

void __attribute__((constructor)) init() {
    std::cout << "Hello World" << std::endl; 
}
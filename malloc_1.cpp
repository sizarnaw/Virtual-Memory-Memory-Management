//
// Created by student on 1/22/22.
//
#include <cstdio>
#include <unistd.h>
void* smalloc(size_t size){
    if(size == 0 || size > 1e8)
        return nullptr;
    void* res = sbrk(size);
    if((void*) -1 == res)
        return nullptr;

    return res;
}


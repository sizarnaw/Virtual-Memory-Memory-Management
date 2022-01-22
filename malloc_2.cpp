
#include <cstdio>
#include <unistd.h>
#include <cstring>
struct metaData{
    size_t size;
    bool is_free;
    metaData* next;
    metaData* prev;
};
metaData* head= nullptr;
metaData* tail = nullptr;


void insertInOrder(metaData* head,metaData* node){
    metaData* temp = head;
    while(temp->next){
        if(temp )
    }
}
void* smalloc(size_t size){
    if(size == 0 || size > 1e8 )
        return nullptr;

    metaData* itr = head;
    while(itr){
        if(itr->is_free && itr->size > sizeof(metaData)+ size){
            itr->is_free = false;
            if(itr->size - size - sizeof(metaData) > sizeof(metaData)){
                metaData* temp;
                temp->is_free = true;
                temp->size = itr->size - size - 2*sizeof(metaData);
                tail->next = temp;
                temp->prev = tail;
                tail = temp;
                tail->next = nullptr;

            }
            return itr+sizeof(metaData);
        }
        itr = itr->next;
    }
    void* res = sbrk(size);
    if((void*) -1 == res)
        return nullptr;
    metaData* temp;
    temp->is_free= false;
    temp->size = size;
    temp->next = nullptr;
    temp->prev = nullptr;
    if(!head) {
        head = temp;
        tail = temp;
    }else{
        tail->next = temp;
        temp->prev = tail;
        tail = temp;
        tail->next = nullptr;
    }
    return res;
}

void* scalloc(size_t num,size_t size){
    if(size == 0 || size * num > 1e8)
        return nullptr;
    void* ptr = smalloc(num*size);
    if(!ptr)
        return nullptr;
    return memset(ptr,0,num*size);
}

void sfree (void* p){
    if(!p)
        return;
    metaData* ptr = (metaData*)p- sizeof(metaData);
    if(ptr->is_free)
        return;
    ptr->is_free = true;
}
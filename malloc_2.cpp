
#include <cstdio>
#include <unistd.h>
#include <cstring>
struct metaData{
    size_t size;
    bool is_free;
    metaData* next;
    metaData* prev;
    metaData* prev1;
    metaData* prev11;
};
metaData* head= nullptr;
metaData* tail = nullptr;


void insertInOrder(metaData* node){
    metaData* temp = head;
    if(head > node){
        node ->next = head;
        head->prev = node;
        head = node;
        return;
    }
    while(temp->next){
        if(temp < node && temp->next >= node  ){
            break;
        }
        temp = temp->next;
    }
    if(temp->next) {
        node->next = temp->next;
        temp->next = node;
        node->prev = temp;
        node->next->prev = node;
    }else{
        tail->next = node;
        node ->next = nullptr;
        node->prev = tail;
        tail = node;
    }

}

void* smalloc(size_t size){
    if(size == 0 || size > 1e8 )
        return nullptr;

    metaData* itr = head;
    while(itr){
        if(itr->is_free && itr->size > size){
            itr->is_free = false;
            return itr+sizeof(metaData);
        }
        itr = itr->next;
    }
    void* res = sbrk(size + sizeof(metaData));
    if((void*) -1 == res)
        return nullptr;
    metaData* temp = new metaData();
    temp->is_free= false;
    temp->size = size;
    temp->next = nullptr;
    temp->prev = nullptr;
    if(!head) {
        head = temp;
        tail = temp;
    }else{
        insertInOrder(temp);
    }
    return (metaData*)res+sizeof(metaData);
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

void* srealloc(void* oldp,size_t size){
    if(size == 0 || size > 1e8)
        return nullptr;
    if(!oldp){
        return smalloc(size);
    }
    metaData* ptr = (metaData*)oldp- sizeof(metaData);
    if(size > ptr->size ){
        void* newptr = smalloc(size);
        if(!newptr)
            return nullptr;

        memcpy(newptr,oldp,ptr->size);
        sfree(oldp);
        return newptr;
    }
    return oldp;
}

size_t _num_free_blocks(){
    size_t counter = 0;

    metaData* ptr = head;
    while(ptr){
        counter += ptr->is_free;
        ptr = ptr->next;
    }
    return counter;
}

size_t _num_free_bytes(){
    size_t free_bytes=0;
    metaData* ptr = head;
    while(ptr){
        free_bytes += (ptr->is_free)* ptr->size;
        ptr = ptr->next;
    }
    return free_bytes;
}

size_t _num_allocated_blocks(){
    size_t counter = 0;
    metaData* ptr = head;

    while(ptr){
        counter ++;
        ptr = ptr->next;
    }
    return counter;
}

size_t _num_meta_data_bytes(){
    size_t counter = 0;
    metaData* ptr = head;
    while(ptr){
        counter ++;
        ptr = ptr->next;
    }
    return counter*sizeof(metaData);
}

size_t _size_meta_data(){
    return (size_t)sizeof(metaData);
}
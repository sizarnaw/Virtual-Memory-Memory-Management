
#include <cstdio>
#include <unistd.h>
#include <cstring>
#include <sys/mman.h>
struct metaData {
    size_t size;
    bool is_free;
    metaData *next;
    metaData *prev;
    metaData *nextInHeap;
    metaData *prevInHeap;
};

metaData *bins[128]; //sorted by size
metaData *heap; //sorted by address

metaData* mmapHead = nullptr;
metaData* mmapTail = nullptr;

metaData *wilderness = nullptr;

int entryIndex(size_t size) {
    return (int) size / 1024;
}

metaData *getTail(metaData *head) {
    metaData *temp = head;
    while (temp->next) {
        temp = temp->next;
    }
    return temp;
}

void insertToHeap(metaData *node) {
    if (!node)
        return;

    metaData *ptr = heap;
    while (ptr->nextInHeap) {
        if (ptr <= node && ptr->nextInHeap > node) {
            node->nextInHeap = ptr->nextInHeap;
            node->prevInHeap = ptr;
            ptr->nextInHeap->prevInHeap = node;
            ptr->nextInHeap = node;
            return;
        }
        ptr = ptr->nextInHeap;
    }
    ptr->nextInHeap = node;
    node->prevInHeap = ptr;
}

void insertInOrder(metaData *node) {
    metaData *head = bins[entryIndex(node->size)];
    metaData *temp = head;
    if (head->size > node->size) {
        node->next = bins[entryIndex(node->size)];
        bins[entryIndex(node->size)]->prev = node;
        bins[entryIndex(node->size)] = node;
        return;
    }
    while (temp->next) {
        if (temp->size < node->size && temp->next->size >= node->size) {
            break;
        }
        temp = temp->next;
    }
    if (temp->next) {
        node->next = temp->next;
        temp->next = node;
        node->prev = temp;
        node->next->prev = node;
    } else {
        metaData *tail = getTail(head);
        tail->next = node;
        node->next = nullptr;
        node->prev = tail;
        tail = node;
    }

}

void removeNodeFromHeap(metaData *node, bool del) {
    if (!node)
        return;

    if (node->prev) {
        node->prev->next = node->next;
    }
    if (node->next) {
        node->next->prev = node->prev;
    }
    if (del)
        delete node;
}

void removeNodeFromBins(metaData *node, bool del) {
    if (node == bins[entryIndex(node->size)]) {
        bins[entryIndex(node->size)] = node->next;
        if (del)
            delete node;
        return;
    }

    node->prev->next = node->next;
    if (node->next)
        node->next->prev = node->prev;
    if (del)
        delete node;
}

void removeNodeFromMMap(metaData* node, bool del){
    if(mmapHead && mmapTail && mmapHead == mmapTail){
        if(node == mmapHead){
            mmapTail = nullptr;
            mmapHead = nullptr;
            if(del)
                delete node;
            return;
        }
    }
    for(metaData* ptr = mmapHead; ptr; ptr = ptr->next){
        if(ptr == node){
            if(ptr->prev && ptr->next){
                ptr->prev->next = ptr->next;
                ptr->next->prev = ptr->prev;
                if(del)
                    delete node;
                return;
            }
            if(ptr->next){
                ptr->next->prev = nullptr;
                mmapHead = ptr->next;
                if(del)
                    delete node;
                return;
            }
            if(ptr->prev){
                ptr->prev->next = nullptr;
                mmapTail = ptr->prev;
                if(del)
                    delete node;
            }
        }
    }

}

void *merge(metaData *head, metaData *next) {
    if (head + head->size + sizeof(metaData) == next) {
        if (next == wilderness)
            wilderness = head;
        head->size += next->size + sizeof(metaData);
        removeNodeFromHeap(next, false);
        removeNodeFromBins(next, true);
        removeNodeFromBins(head, false);
        insertInOrder(head);
    }
    return head;
}

bool dataInHeap(metaData* ptr){
    return ptr->size > 128;
}

void *smalloc(size_t size) {
    if (size == 0 || size > 1e8)
        return nullptr;
    size_t bin = entryIndex(size);
    metaData *head = bins[bin];
    metaData *tail = getTail(head);

    if(bin > 127){ //use mmap
        void* p = mmap(NULL,size + sizeof(metaData), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if ((void*)-1 == p) {
            return NULL;
        }

        metaData* data = (metaData*)p;
        data->size = size;
        data->is_free = false;

        if(mmapTail){
            mmapTail->next = data;
            data->prev = mmapTail;
        }
        mmapTail = data;

        if(!mmapHead){
            mmapHead = data;
        }

        return data + sizeof(metaData);
    }
    for(; bin < 128; bin++){
        metaData* itr = bins[bin];
        while (itr) {
            if (itr->is_free && itr->size > size) {
                itr->is_free = false;
                if (itr->size > size + sizeof(metaData) + 128) {
                    removeNodeFromBins(itr, false);
                    size_t origSize = itr->size;
                    itr->size = size;
                    insertInOrder(itr);
                    metaData *new_meta = (metaData *) (itr->size + sizeof(metaData));
                    new_meta->size = origSize - size - sizeof(metaData);
                    new_meta->is_free = true;
                    insertInOrder(new_meta);
                    insertToHeap(new_meta);
                }
                return itr + sizeof(metaData);
            }
            itr = itr->next;
        }
    }

    if (wilderness && wilderness->is_free) {
        if (wilderness->size > size + sizeof(metaData) + 128) {
            //split
            removeNodeFromBins(wilderness, false);
            size_t origSize = wilderness->size;
            wilderness->size = size;
            wilderness->is_free = false;
            insertInOrder(wilderness);
            metaData *meta = (metaData *) (wilderness + wilderness->size + sizeof(metaData));
            meta->size = origSize - size - sizeof(metaData);
            insertToHeap(meta);
            insertInOrder(meta);
            wilderness = meta;
            return wilderness + sizeof(metaData);
        } else {
            if(size > wilderness->size)
                if((void*)-1 == sbrk(size - wilderness->size))
                    return nullptr;
            wilderness->size = size;
        }
        return wilderness + sizeof(metaData);
    }
    metaData *res = (metaData *) sbrk(size + sizeof(metaData));
    if ((void *) -1 == res)
        return nullptr;
    res->is_free = false;
    res->size = size;
    res->next = nullptr;
    res->prev = nullptr;
    res->prevInHeap = nullptr;
    res->nextInHeap = nullptr;

    wilderness = res;

    if (!head) {
        head = res;
        tail = res;
    } else {
        insertInOrder(res);
    }
    if (!heap) {
        heap = res;
    } else {
        insertToHeap(res);
    }
    return (metaData *) res + sizeof(metaData);
}

void *scalloc(size_t num, size_t size) {
    if (size == 0 || size * num > 1e8)
        return nullptr;
    void *ptr = smalloc(num * size);
    if (!ptr)
        return nullptr;
    return memset(ptr, 0, num * size);
}

void sfree(void *p) {
    if (!p)
        return;
    metaData *ptr = (metaData *) p - sizeof(metaData);
    if (ptr->is_free)
        return;
    ptr->is_free = true;
    if(dataInHeap(ptr)){
        merge(ptr->prevInHeap, (metaData *) merge(ptr, ptr->nextInHeap));
    } else
    {
        removeNodeFromMMap(ptr, false);
        if (munmap((void *)ptr, ptr->size + sizeof(metaData)) == 1)
        {
            perror("Munmap Failed:");
        }
    }
}

void* allocDataAndSplit(metaData* node, size_t size){
    size_t origSize = node->size;
    removeNodeFromBins(node, false);
    node->size = size;
    node->is_free = false;
    if(origSize >= node->size + sizeof(metaData) + 128){
        //split
        metaData *meta = (metaData *) (node + node->size + sizeof(metaData));
        meta->size = origSize - size - sizeof(metaData);
        meta->is_free = true;
        insertInOrder(meta);
        insertToHeap(meta);
        if(wilderness == node)
            wilderness = meta;

    }
    insertInOrder(node);
    return node;
}

void *srealloc(void *oldp, size_t size) {
    if (size == 0 || size > 1e8)
        return nullptr;
    if (!oldp) {
        return smalloc(size);
    }
    metaData *ptr = (metaData *) oldp - sizeof(metaData);
    if(!dataInHeap(ptr)){
        if(ptr->size == size)
            return oldp;
        void* temp = smalloc(size);
        if(!temp)
            return NULL;

        size_t minSize = ptr->size > size ? size : ptr->size;
        memcpy(temp, oldp, minSize);
        sfree(oldp);
        return temp; //todo: maybe + sizeof(metaData);
    }

    if (size > ptr->size) {
        if(ptr->prevInHeap && ptr->prevInHeap->size + ptr->size >= size){
            metaData* temp = ptr->prevInHeap;
            if(((metaData*)merge(ptr->prevInHeap, ptr))->size >= size){
                return allocDataAndSplit(temp, size);
            }
        } else if(ptr->nextInHeap && ptr->nextInHeap->size + ptr->size >= size) {
            metaData* temp = ptr;
            if(((metaData*)merge(ptr, ptr->next))->size >= size){
                return allocDataAndSplit(temp, size);
            }
        } else if (ptr->prevInHeap && ptr->nextInHeap && ptr->prevInHeap->size + ptr->nextInHeap->size + ptr->size >= size){
            metaData* temp = ptr->prevInHeap;
            if(((metaData*)merge(ptr->prevInHeap, (metaData*)merge(ptr, ptr->nextInHeap)))->size >= size){
                return allocDataAndSplit(temp, size);
            }
        }

        void *newptr = smalloc(size);
        if (!newptr)
            return nullptr;

        memcpy(newptr, oldp, ptr->size);
        sfree(oldp);
        return newptr;
    } else {
        //should split
        if (ptr->size > size + sizeof(metaData) + 128){
            bool updateWild = wilderness == ptr;

            size_t origSize = ptr->size;
            removeNodeFromBins(ptr, false);
            ptr->size = size;
            insertInOrder(ptr);
            metaData *meta = (metaData *) (ptr + ptr->size + sizeof(metaData));
            meta->size = origSize - size - sizeof(metaData);
            insertToHeap(meta);
            insertInOrder(meta);
            if(updateWild)
                wilderness = meta;

            merge(meta, meta->next);
            return ptr + sizeof(metaData);
        }
    }
    return oldp;
}

void* getHeapHead(){
    metaData* res = wilderness;
    while(res->prev){
        res = res->prev;
    }
    return res;
}

size_t _num_free_blocks(){
    size_t c = 0;
    metaData* ptr = (metaData*)getHeapHead();
    while(ptr){
        c += ptr->is_free;
        ptr = ptr->nextInHeap;
    }
    return c;
}

size_t _num_free_bytes(){
    size_t c = 0;
    metaData* ptr = (metaData*)getHeapHead();
    while(ptr){
        c += ptr->is_free * ptr->size;
        ptr = ptr->nextInHeap;
    }
    return c;
}

size_t _num_allocated_blocks(){
    metaData* ptr = (metaData*)getHeapHead();
    size_t heapSize = 0, mmapSize = 0;
    while(ptr){
        ptr = ptr->next;
        heapSize++;
    }
    ptr = mmapHead;
    while(ptr){
        ptr = ptr->next;
        mmapSize++;
    }
    return mmapSize + heapSize;
}

size_t _num_allocated_bytes(){
    metaData* ptr = (metaData*)getHeapHead();
    size_t heapSize = 0, mmapSize = 0;
    while(ptr){
        heapSize += ptr->size;
        ptr = ptr->next;
    }
    ptr = mmapHead;
    while(ptr){
        mmapSize += ptr->size;
        ptr = ptr->next;
    }
    return mmapSize + heapSize;
}

size_t _size_meta_data() {
    return (size_t) sizeof(metaData);
}

size_t _num_meta_data_bytes(){
    return _size_meta_data() * _num_allocated_blocks();
}

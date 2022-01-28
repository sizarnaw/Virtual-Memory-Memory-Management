#include <cstdio>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sys/mman.h>
#include "malloc_3.h"
#include "assert.h"

#define MAX_KB 128*1024
bool debug = false;
struct metaData {
    size_t size;
    bool is_free;
    metaData *nextInHeap;
    metaData *prevInHeap;
    metaData *next;
    metaData *prev;
};

metaData *bins[128]; //sorted by size
metaData *heap; //sorted by address

metaData *mmapHead = nullptr;
metaData *mmapTail = nullptr;

metaData *wilderness = nullptr;

int entryIndex(size_t size) {
    return (int) size / 1024;
}

metaData *getTail(metaData *head) {
    metaData *temp = head;
    while (temp && temp->next) {
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

}
bool existInBins(metaData* node){
    //expect that head is not nullptr.
    metaData* temp = bins[entryIndex(node->size)];
    while(temp){
        if(temp == node)
            return true;
        temp = temp->next;
    }
    return false;
}
void removeNodeFromBins(metaData *node) {
    if (node == bins[entryIndex(node->size)]) {
        bins[entryIndex(node->size)] = node->next;
        return;
    }
    if(node->size > MAX_KB)
        return;
    //if(!existInBins(node))
    //    return;
    node->prev->next = node->next;
    if (node->next)
        node->next->prev = node->prev;

}

void removeNodeFromMMap(metaData *node, bool del) {
    if (mmapHead && mmapTail && mmapHead == mmapTail) {
        if (node == mmapHead) {
            mmapTail = nullptr;
            mmapHead = nullptr;

            return;
        }
    }
    for (metaData *ptr = mmapHead; ptr; ptr = ptr->next) {
        if (ptr == node) {
            if (ptr->prev && ptr->next) {
                ptr->prev->next = ptr->next;
                ptr->next->prev = ptr->prev;
                return;
            }
            if (ptr->next) {
                ptr->next->prev = nullptr;
                mmapHead = ptr->next;
                return;
            }
            if (ptr->prev) {
                ptr->prev->next = nullptr;
                mmapTail = ptr->prev;
            }
        }
    }

}

void *merge(metaData *head, metaData *next) {
    if (!head && next) {
        return next;
    } else if (head && !next) {
        return head;
    } else if (!head && !next) {
        return nullptr;
    }
    if (!next->is_free || !head->is_free) {
        return head;
    }
    //if (head + head->size + sizeof(metaData) == next) {
    if (next == wilderness)
        wilderness = head;
    head->size += next->size + sizeof(metaData);
    removeNodeFromHeap(next, false);
    removeNodeFromBins(next);
    removeNodeFromBins(head);
    insertInOrder(head);
    //}
    return head;
}

bool dataInHeap(metaData *ptr) {
    return ptr->size < 128 * 1024;
}

void *smalloc(size_t size) {
    if (debug)
        std::cout << "\n***********size in malloc: " << size << std::endl;
    if (size == 0 || size > 100000000)
        return nullptr;
    size_t bin = entryIndex(size);
    //metaData *head = bins[bin];
    //metaData *tail = getTail(head);

    if (bin > 127) { //use mmap
        void *p = mmap(NULL, size + sizeof(metaData), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if ((void *) -1 == p) {
            return NULL;
        }

        metaData *data = (metaData *) p;
        data->size = size;
        data->is_free = false;

        if (mmapTail) {
            mmapTail->next = data;
            data->prev = mmapTail;
        }
        mmapTail = data;

        if (!mmapHead) {
            mmapHead = data;
        }

        unsigned long long temp = (unsigned long long) data;
        temp += sizeof(metaData);
        return (void *) temp;

        return data + sizeof(metaData);
    }
    for (int i = bin; i < 128; i++) {
        metaData *itr = bins[i];
        while (itr) {
            if (itr->is_free && itr->size >= size) {
                itr->is_free = false;
                if (itr->size > size + sizeof(metaData) + 128) {
                    removeNodeFromBins(itr);
                    size_t origSize = itr->size;
                    itr->size = size;
                    if(bins[entryIndex(itr->size)]) {
                        insertInOrder(itr);
                    }
                    else {
                        bins[entryIndex(itr->size)] = itr;
                        itr->prev = nullptr;
                    }
                    unsigned long long temp = (unsigned long long) itr;
                    temp += (itr->size + sizeof(metaData));
                    metaData *new_meta = (metaData *) temp;
                    new_meta->size = origSize - size - sizeof(metaData);
                    new_meta->is_free = true;
                    if(bins[entryIndex(new_meta->size)]) {
                        insertInOrder(new_meta);
                    }
                    else {
                        bins[entryIndex(new_meta->size)] = new_meta;
                        new_meta->prev = nullptr;
                    }
                    insertToHeap(new_meta);
                }
                unsigned long long temp = (unsigned long long) itr;
                temp += sizeof(metaData);
                return (void *) temp;

                return itr + sizeof(metaData);
            }
            itr = itr->next;
        }
    }

    if (wilderness && wilderness->is_free) {
        if (wilderness->size > size + sizeof(metaData) + 128) {
            //split
            removeNodeFromBins(wilderness);
            size_t origSize = wilderness->size;
            wilderness->size = size;
            wilderness->is_free = false;
            insertInOrder(wilderness);
            metaData *meta = (metaData *) (wilderness + wilderness->size + sizeof(metaData));
            meta->size = origSize - size - sizeof(metaData);
            insertToHeap(meta);
            insertInOrder(meta);
            wilderness = meta;
            unsigned long long temp = (unsigned long long) wilderness;
            temp += sizeof(metaData);
            return (void *) temp;

            return wilderness + sizeof(metaData);
        } else {
            if (size > wilderness->size)
                if ((void *) -1 == sbrk(size - wilderness->size))
                    return nullptr;
            removeNodeFromBins(wilderness);
            wilderness->size = size;
            wilderness->is_free = false;
            if(bins[entryIndex(wilderness->size)]) {
                insertInOrder(wilderness);
            }
            else {
                bins[entryIndex(wilderness->size)] = wilderness;
                wilderness->prev = nullptr;
            }

        }
        unsigned long long temp = (unsigned long long) wilderness;
        temp += sizeof(metaData);
        return (void *) temp;
        //return wilderness + sizeof(metaData);
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
    metaData *head = bins[bin];
    metaData *tail = getTail(head);

    if (!head) {
        bins[entryIndex(size)] = res;
        tail = res;
    } else {
        insertInOrder(res);
    }
    if (!heap) {
        heap = res;
    } else {
        insertToHeap(res);
    }
    unsigned long long temp = (unsigned long long) res;
    temp += _size_meta_data();
    return (void *) temp;
    //return (metaData *) res + sizeof(metaData);
}

void *scalloc(size_t num, size_t size) {
    if (debug)
        std::cout << "\n***********size in scalloc: " << size << std::endl;

    if (size == 0 || size * num > 100000000)
        return nullptr;
    void *ptr = smalloc(num * size);
    if (!ptr)
        return nullptr;
    return memset(ptr, 0, num * size);
}

metaData *mergePrev(metaData *p) {
    if (!p)
        return nullptr;
    if (!p->prevInHeap)
        return p;

    metaData *prev = p->prevInHeap;

    if (prev->is_free) {
        bool updateWilderness = p == wilderness;
        prev->nextInHeap = p->nextInHeap;
        if (p->nextInHeap)
            p->nextInHeap->prevInHeap = prev;
        removeNodeFromBins(prev);
        prev->size += (sizeof(metaData) + p->size);
        //todo: re insert prev to bins
        //insertInOrder(prev);
        if (updateWilderness)
            wilderness = prev;
        return prev;
    }
    return p;
}

metaData *mergeNext(metaData *p) {
    if (!p)
        return nullptr;
    if (!p->nextInHeap)
        return p;

    metaData *next = p->nextInHeap;
    if (next->is_free) {
        bool updateWilderness = next == wilderness;
        p->nextInHeap = next->nextInHeap;
        //if (next->nextInHeap)
        //    next->nextInHeap->prevInHeap = p;
        removeNodeFromBins(next);
        p->size += (sizeof(metaData) + next->size);
        if (updateWilderness)
            wilderness = p;
    }
    return p;
}


void sfree(void *p) {
    if (!p)
        return;
    metaData *ptr = (metaData *) p;// - sizeof(metaData);
    ptr--;
    if (debug)
        std::cout << "***********freeing: " << ptr->size << std::endl;
    //std::cout << "\nfree " << ptr->size << std::endl;
    if (ptr->is_free)
        return;
    ptr->is_free = true;
    if (dataInHeap(ptr)) {
        removeNodeFromBins(ptr);
        metaData *temp = mergePrev(ptr);
        mergeNext(temp);
        if(bins[entryIndex(temp->size)]) {
            insertInOrder(temp);
            //bins[entryIndex(temp->size)] = temp;
        }
        else {
            bins[entryIndex(temp->size)] = temp;
            temp->prev = nullptr;
        }
        //merge(ptr->prevInHeap, (metaData *) merge(ptr, ptr->nextInHeap));//todo:seperate
        //removeNodeFromMMap(ptr, true);
    } else {
        removeNodeFromMMap(ptr, false);
        if (ptr->size >= 128 && munmap((void *) ptr, ptr->size + sizeof(metaData)) == 1) {
            perror("Munmap Failed:");
        }
    }
}

void *allocDataAndSplit(metaData *node, size_t size) {
    if(!node)
        return nullptr;
    size_t origSize = node->size;
    removeNodeFromBins(node); //todo: delete because we use this function(allocData) after merge that have removeNode.
    node->is_free = false;
    if (origSize >= size + sizeof(metaData) + 128) {
        node->size = size;
        //split
        //todo: check when i put long long it returns errors.
        //todo: it supposed to be long long but it return errors . TAKE CARE NAJIB!!!!.
        unsigned long long temp = (unsigned long long) node;
        temp += sizeof(metaData) + node->size;
        metaData* meta = (metaData*)(temp);
        //metaData *meta = (metaData *) (temp + node->size);
        //metaData *meta = (metaData *) (node+node->size+ sizeof(metaData));

        meta->size = origSize - size - sizeof(metaData);
        meta->is_free = true;
        insertInOrder(meta);
        insertToHeap(meta);
        if (wilderness == node)
            wilderness = meta;

    }
    if(bins[entryIndex(node->size)]) {
        insertInOrder(node);
    }
    else {
        bins[entryIndex(node->size)] = node;
        node->prev = nullptr;
    }

    unsigned long long temp = (unsigned long long) node;
    temp += sizeof(metaData);
    return (void*)temp;
}

void *reallocFilter(metaData *node, size_t size) {
    if (node->nextInHeap == nullptr) {
        sbrk(size - node->size);
        node->size = size;
        return node;
    }
    return nullptr;
}

metaData *reallocHelperB(metaData *ptr) {
    if (!ptr->prevInHeap)
        return ptr;
    if (!ptr->prevInHeap->is_free)
        return ptr;
    return mergePrev(ptr);
}

metaData *reallocHelperC(metaData *ptr) {
    if (!ptr->nextInHeap)
        return ptr;
    if (!ptr->nextInHeap->is_free)
        return ptr;
    return mergeNext(ptr);
}

int checkPriority(metaData *ptr, size_t size) {

    if (ptr->size >= size)
        return 1; // A
    if (ptr->prevInHeap && ptr->prevInHeap->is_free && (ptr->size + ptr->prevInHeap->size >= size))
        return 2; // B
    if (ptr->nextInHeap && ptr->nextInHeap->is_free && (ptr->size + ptr->nextInHeap->size >= size)) {
        return 3; // C
    }
    if(ptr->nextInHeap && ptr->prevInHeap &&
    ptr->nextInHeap->is_free && ptr->prevInHeap->is_free &&
    ((ptr->size + ptr->nextInHeap->size + ptr->prevInHeap->size) >= size))
        return 4;

    return 0;

}

void *srealloc(void *oldp, size_t size) {
    if (size == 0 || size > 100000000)
        return nullptr;
    if (!oldp)
        return smalloc(size);
    metaData *ptr = (metaData *) oldp;
    ptr--;

    int res = checkPriority(ptr,size);
    if(size > MAX_KB){
        void* ret = smalloc(size);
        if(!ret)
            return nullptr;
        metaData* meta = (metaData*) ret;
        memcpy(meta,oldp,size);
        unsigned long long temp = (unsigned long long) meta;
        temp += sizeof(metaData);
        sfree(oldp);
        return (void *) temp;
    }
    if(res == 0){
        ptr->is_free = true;
        void *temp = smalloc(size);
        if (!temp)
            return nullptr;
        memcpy(temp, oldp, size);
        if(temp != oldp)
            sfree(oldp);

        return temp;
    }
    if(res == 1){
        allocDataAndSplit(ptr, size);
        mergeNext(ptr->next);
        return oldp;
    }
    if(res == 2){
        metaData* ret = reallocHelperB(ptr);
        allocDataAndSplit(ret,size);
        mergeNext(ret->next);
        ret++;
        memcpy(ret, oldp, size);
        ret--;
        unsigned long long temp = (unsigned long long) ret;
        temp += sizeof(metaData);
        return (void *) temp;
    }
    if(res == 3){
        metaData* ret = reallocHelperC(ptr);
        allocDataAndSplit(ret,size);
        mergeNext(ret->next);
        ret++;
        memcpy(ret, oldp, size);
        ret--;
        unsigned long long temp = (unsigned long long) ret;
        temp += sizeof(metaData);
        return (void *) temp;
    }
    if(res == 4 ){
        metaData* sex = ptr->prevInHeap;
        allocDataAndSplit(sex,size);
        mergeNext(sex->next);
        sex++;
        memcpy(sex, oldp, size);
        sfree(oldp);
        unsigned long long temp = (unsigned long long) sex;
        temp += sizeof(metaData);
        return (void *) temp;
    }

    int najib = 0;
    assert ( najib != 0 );
    return nullptr;
}

/*void *srealloc(void *oldp, size_t size) {
    if (debug)
        std::cout << "1111111111111111111111111read " << size << std::endl;
    if (size == 0 || size > 100000000)
        return nullptr;
    if (!oldp) {
        return smalloc(size);
    }
    metaData *ptr = (metaData *) oldp;
    ptr--;
    if (!dataInHeap(ptr)) {
        if (ptr->size == size)
            return oldp;
        void *temp = smalloc(size);
        if (!temp)
            return NULL;
        size_t minSize = ptr->size > size ? size : ptr->size;
        memcpy(temp, oldp, minSize);
        sfree(oldp);
        return temp; //todo: maybe + sizeof(metaData);
    }
    if (size > ptr->size) {
        void *res = reallocFilter(ptr, size);
        if (res)
            return oldp;
        if (ptr->prevInHeap && ptr->prevInHeap->size + ptr->size >= size) {
            metaData *temp = ptr->prevInHeap;
            if (((metaData *) merge(ptr->prevInHeap, ptr))->size >= size) {
                return allocDataAndSplit(temp, size);
            }
        } else if (ptr->nextInHeap && ptr->nextInHeap->size + ptr->size >= size) {
            metaData *temp = ptr;
            if (((metaData *) merge(ptr, ptr->next))->size >= size) {
                return allocDataAndSplit(temp, size);
            }
        } else if (ptr->prevInHeap && ptr->nextInHeap &&
                   ptr->prevInHeap->size + ptr->nextInHeap->size + ptr->size >= size) {
            metaData *temp = ptr->prevInHeap;
            if (((metaData *) merge(ptr->prevInHeap, (metaData *) merge(ptr, ptr->nextInHeap)))->size >= size) {
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
        if (ptr->size > size + sizeof(metaData) + 128) {
            bool updateWild = wilderness == ptr;
            size_t origSize = ptr->size;
            removeNodeFromBins(ptr);
            ptr->size = size;
            insertInOrder(ptr);
            metaData *meta = (metaData *) (ptr + ptr->size + sizeof(metaData));
            meta->size = origSize - size - sizeof(metaData);
            insertToHeap(meta);
            insertInOrder(meta);
            if (updateWild)
                wilderness = meta;
            merge(meta, meta->next);
            return ptr + sizeof(metaData);
        }
    }
    return oldp;
}*/

void *getHeapHead() {
    metaData *res = wilderness;
    while (res->prevInHeap) {
        res = res->prevInHeap;
    }
    return res;
}

size_t _num_free_blocks() {
    size_t c = 0;
    metaData *ptr = (metaData *) getHeapHead();
    while (ptr) {
        c += ptr->is_free;
        ptr = ptr->nextInHeap;
    }
    return c;
}

size_t _num_free_bytes() {
    size_t c = 0;
    metaData *ptr = (metaData *) getHeapHead();
    while (ptr) {
        c += ptr->is_free * ptr->size;
        ptr = ptr->nextInHeap;
    }
    return c;
}

int in = 0;

size_t _num_allocated_blocks() {
    if (debug)
        std::cout << "sex: " << in++ << std::endl;
    metaData *ptr = (metaData *) getHeapHead();
    size_t heapSize = 0, mmapSize = 0;
    while (ptr) {
        heapSize++;
        ptr = ptr->nextInHeap;
    }
    ptr = mmapHead;
    while (ptr) {
        ptr = ptr->next;
        mmapSize++;
    }
    return mmapSize + heapSize;
}

size_t _num_allocated_bytes() {
    metaData *ptr = (metaData *) getHeapHead();
    size_t heapSize = 0, mmapSize = 0;
    while (ptr) {
        heapSize += ptr->size;
        ptr = ptr->nextInHeap;
    }
    ptr = mmapHead;
    while (ptr) {
        mmapSize += ptr->size;
        ptr = ptr->next;
    }
    return mmapSize + heapSize;
}

size_t _size_meta_data() {
    return (size_t) sizeof(metaData);
}

size_t _num_meta_data_bytes() {
    return _size_meta_data() * (_num_allocated_blocks());
}

#include <cstdio>
#include <unistd.h>
#include <cstring>

struct metaData {
    size_t size;
    bool is_free;
    metaData *next;
    metaData *prev;
};

metaData *bins[128];

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

void removeNode(metaData *node) {
    if (node == bins[entryIndex(node->size)]) {
        bins[entryIndex(node->size)] = node->next;
        delete node;
        return;
    }

    node->prev->next = node->next;
    if (node->next)
        node->next->prev = node->prev;
    delete node;
}

void merge(metaData *head, metaData *next) {
    head->size += next->size + sizeof(metaData);
    removeNode(next);
}

void *smalloc(size_t size) {
    if (size == 0 || size > 1e8)
        return nullptr;
    metaData *head = bins[entryIndex(size)];
    metaData *tail = getTail(head);
    metaData *itr = head;
    while (itr) {
        if (itr->is_free && itr->size > size) {
            itr->is_free = false;
            if (itr->size > size + sizeof(metaData) + 128) {
                removeNode(itr);
                metaData *usedData = new metaData();
                usedData->size = size;
                usedData->is_free = false;
                insertInOrder(usedData);
                metaData *new_meta = new metaData();
                new_meta->size = itr->size - size - sizeof(metaData);
                new_meta->is_free = true;
                insertInOrder(new_meta);

                return usedData + sizeof(metaData);
            }
            return itr + sizeof(metaData);
        }
        itr = itr->next;
    }
    void *res = sbrk(size + sizeof(metaData));
    if ((void *) -1 == res)
        return nullptr;
    metaData *temp = new metaData();
    temp->is_free = false;
    temp->size = size;
    temp->next = nullptr;
    temp->prev = nullptr;
    if (!head) {
        head = temp;
        tail = temp;
    } else {
        insertInOrder(temp);
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

    if (ptr->next && ptr->next->is_free) {
        merge(ptr, ptr->next);
    }
    if (ptr->prev && ptr->prev->is_free) {
        merge(ptr->prev, ptr);
        metaData *new_ptr = new metaData();
        new_ptr->size = ptr->prev->size;
        new_ptr->is_free = ptr->prev->is_free;
        insertInOrder(new_ptr);
        removeNode(ptr->prev);
        return;
    }
    metaData *new_ptr = new metaData();
    new_ptr->size = ptr->size;
    new_ptr->is_free = ptr->is_free;
    insertInOrder(ptr);
    removeNode(ptr);

}

void *srealloc(void *oldp, size_t size) {
    if (size == 0 || size > 1e8)
        return nullptr;
    if (!oldp) {
        return smalloc(size);
    }
    metaData *ptr = (metaData *) oldp - sizeof(metaData);
    if (size > ptr->size) {
        void *newptr = smalloc(size);
        if (!newptr)
            return nullptr;

        memcpy(newptr, oldp, ptr->size);
        sfree(oldp);
        return newptr;
    }
    return oldp;
}

size_t _num_free_blocks() {
    size_t counter = 0;

    metaData *ptr = head;
    while (ptr) {
        counter += ptr->is_free;
        ptr = ptr->next;
    }
    return counter;
}

size_t _num_free_bytes() {
    size_t free_bytes = 0;
    metaData *ptr = head;
    while (ptr) {
        free_bytes += (ptr->is_free) * ptr->size;
        ptr = ptr->next;
    }
    return free_bytes;
}

size_t _num_allocated_blocks() {
    size_t counter = 0;
    metaData *ptr = head;

    while (ptr) {
        counter++;
        ptr = ptr->next;
    }
    return counter;
}

size_t _num_meta_data_bytes() {
    size_t counter = 0;
    metaData *ptr = head;
    while (ptr) {
        counter++;
        ptr = ptr->next;
    }
    return counter * sizeof(metaData);
}

size_t _size_meta_data() {
    return (size_t) sizeof(metaData);
}
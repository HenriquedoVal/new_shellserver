#pragma once

#include <stdbool.h>
#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>


#ifdef DYNARR_SCOPE_DLLEXPORT
#   define DA_SCOPE   __declspec( dllexport )
#endif

#ifdef DYNARR_SCOPE_STATIC
#   define DA_SCOPE   static
#endif

#ifndef DA_SCOPE
#   define DA_SCOPE
#endif


#ifndef DYNARR_INIT_SIZE
#   define DYNARR_INIT_SIZE 512
#endif

#ifndef DYNARR_GROW_FACTOR
#   define DYNARR_GROW_FACTOR 2
#endif

// PERF: `count` and `_element_size` could be 32bit or less
typedef struct {
    size_t count;
    size_t _element_size;
    size_t _capacity;
    void *_data;
} DynArr;


DynArr DA_SCOPE  dynarr_init         (size_t element_size);
void   DA_SCOPE *dynarr_alloc        (DynArr *da, size_t size);
void   DA_SCOPE *dynarr_append       (DynArr *da, void *var);
void   DA_SCOPE *dynarr_append_str   (DynArr *da, char *str, int len);
void   DA_SCOPE *dynarr_append_zeroed(DynArr *da);
void   DA_SCOPE *dynarr_at           (DynArr *da, size_t idx);
void   DA_SCOPE *dynarr_pop          (DynArr *da);

bool   DA_SCOPE  dynarr_remove       (DynArr *da, size_t idx);

void   DA_SCOPE  dynarr_reset        (DynArr *da);
void   DA_SCOPE  dynarr_shift_append (DynArr *da, void *var);
void   DA_SCOPE  dynarr_free         (DynArr *da);

#ifdef DYNARR_IMPLEMENTATION


void _dynarr_grow(DynArr *da, size_t size)
{
    HANDLE heap = GetProcessHeap();
    if (!heap) abort();

    bool needs_to_grow = false;
    while (da->_capacity < da->count * da->_element_size + size) {
        needs_to_grow = true;
        da->_capacity *= DYNARR_GROW_FACTOR;
    }

    if (needs_to_grow) {
        void *nptr = HeapReAlloc(heap, 0, da->_data, da->_capacity);
        if (nptr == NULL) abort();
        da->_data = nptr;
    }
}


DynArr dynarr_init(size_t element_size)
{
    HANDLE heap = GetProcessHeap();
    if (!heap) abort();

    DynArr da = {
        ._capacity = DYNARR_INIT_SIZE,
        ._element_size = element_size,
        ._data = HeapAlloc(heap, 0, DYNARR_INIT_SIZE),
    };

    if (da._data == NULL) abort();

    return da;
}


// TODO: remove this and add proper str funcs
void *dynarr_alloc(DynArr *da, size_t size)
{
    void *ptr = (char *)da->_data + da->count * da->_element_size;
    _dynarr_grow(da, size);
    da->count += size;

    return ptr;
}


void *dynarr_append(DynArr *da, void *var)
{
    _dynarr_grow(da, da->_element_size);

    void *ptr_to_save = (char *)da->_data + da->count * da->_element_size;
    memcpy(ptr_to_save, var, da->_element_size);

    da->count++;

    return ptr_to_save;
}


void *dynarr_append_str(DynArr *da, char *str, int len)
{
    if (len < 0) len = (int)strlen(str);

    _dynarr_grow(da, len);

    void *ptr_to_save = (char *)da->_data + da->count * da->_element_size;
    memcpy(ptr_to_save, str, len);
    da->count += len;

    return ptr_to_save;
}


void *dynarr_append_zeroed(DynArr *da) {
    _dynarr_grow(da, da->_element_size);

    void *ptr_to_save = (char *)da->_data + da->count * da->_element_size;
    memset(ptr_to_save, 0, da->_element_size);

    da->count++;

    return ptr_to_save;
}


void *dynarr_at(DynArr *da, size_t idx)
{
    if (idx >= da->count) return NULL;
    return (char *)da->_data + (da->_element_size * idx);
}


void *dynarr_pop(DynArr *da)
{
    if (!da->count) return NULL;
    da->count--;
    return (char *)da->_data + (da->_element_size * da->count);
}


bool dynarr_remove(DynArr *da, size_t idx) {
    if (!da->count || idx >= da->count) return false;

    da->count--;

    for (size_t i = idx; i < da->count; ++i) {
        memcpy(
                (char *)da->_data + i * da->_element_size,
                (char *)da->_data + (i + 1) * da->_element_size,
                da->_element_size
        );
    }
    return true;
}

void dynarr_reset(DynArr *da)
{
    da->count = 0;
}


void dynarr_shift_append(DynArr *da, void *var)
{
    if (!da->count) {
        dynarr_append(da, var);
        return;
    }

    // It would take 131072PB of memory for `i` to overflow if _element_size == 1
    for (size_t i = 1; i < da->count; ++i) {
        memcpy(
                (char *)da->_data + (i - 1) * da->_element_size,
                (char *)da->_data + i * da->_element_size,
                da->_element_size
        );
    }
    memcpy((char *)da->_data + (da->count - 1) * da->_element_size, var, da->_element_size);
}


void dynarr_free(DynArr *da)
{
    HANDLE heap = GetProcessHeap();
    if (!heap) abort();
    bool ret = HeapFree(heap, 0, da->_data);
    if (!ret) abort();
    *da = (DynArr){0};
}
#endif  // DYNARR_IMPLEMENTATION

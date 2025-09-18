#pragma once

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>


#ifdef DYNARR_SCOPE_DLLEXPORT
#   define DA_SCOPE   __declspec(dllexport)
#endif

#ifdef DYNARR_SCOPE_STATIC
#   define DA_SCOPE   static
#endif

#ifndef DA_SCOPE
#   define DA_SCOPE
#endif


#ifndef DYNARR_INIT_COUNT
#   define DYNARR_INIT_COUNT 5
#endif

#ifndef DYNARR_GROW_FACTOR
#   define DYNARR_GROW_FACTOR 2
#endif


typedef struct {
    uint32_t count;

    uint32_t _max_count;
    uint16_t _element_size;

    uint16_t _upad1;
    uint32_t _upad2;

    void *_data;
} DynArr;


DynArr DA_SCOPE  dynarr_init         (uint16_t element_size);
DynArr DA_SCOPE  dynarr_init_ex      (uint16_t element_size, uint32_t count);
DynArr DA_SCOPE  dynarr_dup          (DynArr da);

void   DA_SCOPE *dynarr_append       (DynArr *da, const void *var);
void   DA_SCOPE *dynarr_append_zeroed(DynArr *da);
void   DA_SCOPE *dynarr_at           (const DynArr *da, uint32_t idx);
void   DA_SCOPE *dynarr_pop          (DynArr *da);
void   DA_SCOPE *dynarr_set_append   (DynArr *da, const void *var);
void   DA_SCOPE *dynarr_shift_append (DynArr *da, const void *var);

bool   DA_SCOPE  dynarr_remove       (DynArr *da, uint32_t idx);

void   DA_SCOPE  dynarr_free         (DynArr *da);


#ifdef DYNARR_IMPLEMENTATION


static void _dynarr_grow(DynArr *da, uint32_t count)
{
    if (count + da->count <= da->_max_count) return;

    HANDLE heap = GetProcessHeap();
    if (!heap) abort();

    da->_max_count *= DYNARR_GROW_FACTOR;
    size_t size = da->_max_count * da->_element_size;

    void *nptr = HeapReAlloc(heap, 0, da->_data, size);
    if (nptr == NULL) abort();

    da->_data = nptr;
}


DynArr dynarr_init_ex(uint16_t element_size, uint32_t count)
{
    HANDLE heap = GetProcessHeap();
    if (!heap) abort();

    size_t size = count * element_size;
    DynArr da = {
        ._max_count = count,
        ._element_size = element_size,
        ._data = HeapAlloc(heap, 0, size),
    };

    if (da._data == NULL) abort();

    return da;
}


DynArr dynarr_dup(DynArr da)
{
    HANDLE heap = GetProcessHeap();
    if (!heap) abort();

    size_t size = da._max_count * da._element_size;
    void *data = HeapAlloc(heap, 0, size);
    if (!data) abort();

    memcpy(data, da._data, da.count * da._element_size);

    DynArr ret = da;
    ret._data = data;

    return ret;
}


DynArr dynarr_init(uint16_t element_size)
{
    return dynarr_init_ex(element_size, DYNARR_INIT_COUNT);
}


void *dynarr_append(DynArr *da, const void *var)
{
    _dynarr_grow(da, 1);

    void *ptr_to_save = (char *)da->_data + da->count * da->_element_size;
    memcpy(ptr_to_save, var, da->_element_size);

    da->count++;

    return ptr_to_save;
}


void *dynarr_append_zeroed(DynArr *da) {
    _dynarr_grow(da, 1);

    void *ptr_to_save = (char *)da->_data + da->count * da->_element_size;
    memset(ptr_to_save, 0, da->_element_size);

    da->count++;

    return ptr_to_save;
}


void *dynarr_at(const DynArr *da, uint32_t idx)
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


// Append if not already there
void *dynarr_set_append(DynArr *da, const void *var)
{
    for (size_t i = 0; i < da->count; ++i) {
        char *test = (char *)da->_data + i * da->_element_size;
        if (memcmp(test, var, da->_element_size) == 0) return NULL;
    }

    return dynarr_append(da, var);
}


bool dynarr_remove(DynArr *da, uint32_t idx) {
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

void *dynarr_shift_append(DynArr *da, const void *var)
{
    if (!da->count) {
        return dynarr_append(da, var);
    }

    for (size_t i = 1; i < da->count; ++i) {
        memcpy(
                (char *)da->_data + (i - 1) * da->_element_size,
                (char *)da->_data + i * da->_element_size,
                da->_element_size
        );
    }

    void *ptr = (char *)da->_data + (da->count - 1) * da->_element_size;
    memcpy(ptr, var, da->_element_size);
    return ptr;
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

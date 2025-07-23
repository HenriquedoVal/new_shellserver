#pragma once

#include <assert.h>
#include <stdio.h>
#include <stdbool.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#ifdef ARENA_SCOPE_DLLEXPORT
#   define ARENA_SCOPE   __declspec( dllexport )
#endif

#ifdef ARENA_SCOPE_STATIC
#   define ARENA_SCOPE   static
#endif

#ifndef ARENA_SCOPE
#   define ARENA_SCOPE
#endif

typedef struct BUFFER {
    char *data;
    size_t capacity;
    size_t offset;
    size_t size;
    HANDLE heap;
    struct BUFFER *next;
} ArenaBuffer;


typedef struct {
    ArenaBuffer *first;
    ArenaBuffer *current;
    struct {
        size_t total_alloc;
        size_t total_freed;
    } info;
} Arena;


typedef struct {
    Arena *arena;
    ArenaBuffer *current;
    size_t offset;
} ArenaMark;


void      ARENA_SCOPE *arena_alloc     (Arena *a, size_t size);
void      ARENA_SCOPE  arena_free      (Arena *a);
ArenaMark ARENA_SCOPE  arena_mark      (Arena *a);
void      ARENA_SCOPE  arena_mark_reset(Arena *a, ArenaMark m);
void      ARENA_SCOPE *arena_realloc   (Arena *a, void *ptr, size_t size, size_t prev_size);
void      ARENA_SCOPE  arena_reset     (Arena *a);
char      ARENA_SCOPE *arena_strdup    (Arena *a, const char *str);


// #define ARENA_NO_ZERO_MEMORY
// #define ARENA_IMPLEMENTATION

#ifdef ARENA_IMPLEMENTATION

#ifndef ARENA_PAGE_MUL
    #define ARENA_PAGE_MUL 8  // 32kb if pf = 4kb
#else
    #if ARENA_PAGE_MUL <= 0
    #error "ARENA_PAGE_MUL must be bigger than 0"
    #endif
#endif

//
// Private functions
//


static ArenaBuffer *_create_buffer(size_t size) {
    static unsigned page_size = 0;
    if (page_size == 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        page_size = si.dwPageSize;
    }

    HANDLE heap = GetProcessHeap();
    assert(heap != NULL);

    ArenaBuffer *buffer = HeapAlloc(heap, 0, sizeof(ArenaBuffer));
    assert(buffer != NULL);

    size_t req_size = size > page_size * ARENA_PAGE_MUL 
                    ? size
                    : page_size * ARENA_PAGE_MUL;

    buffer->heap = HeapCreate(HEAP_NO_SERIALIZE, req_size, 0);
    assert(buffer->heap != NULL);
    
    buffer->size = req_size;
    buffer->data = HeapAlloc(buffer->heap, 0, req_size);
    assert(buffer->data != NULL);

    buffer->capacity = req_size;
    buffer->offset = 0;
    buffer->next = NULL;

    return buffer;
}


static void _free_buffer(ArenaBuffer *buffer) {
    HANDLE heap = GetProcessHeap();
    assert(heap != NULL);
    int ret = HeapDestroy(buffer->heap);
    assert(ret);
    ret = HeapFree(heap, 0, buffer);
    assert(ret);
}


//
// Public functions
//


static void *arena_alloc(Arena *a, size_t size)
{
    if (a == NULL)
        return NULL;

    ArenaBuffer *buffer = a->current;
    bool append = true;

    // if (size % 8 != 0)
    //     size += 8 - (size & 7);
    size += !!(size % 8) * (8 - (size & 7));

    assert(size % 8 == 0);

    if (buffer == NULL) {
        buffer = _create_buffer(size);
        a->info.total_alloc += buffer->size;

    } else if (size <= buffer->capacity - buffer->offset) {
        append = false;

    } else if (buffer->next == NULL) {
        buffer = _create_buffer(size);
        a->info.total_alloc += buffer->size;

    } else {
        append = false;

        ArenaBuffer *prev = buffer;
        buffer = buffer->next;

        size_t available = buffer->capacity - buffer->offset;

        if (available < size) {
            ArenaBuffer *post = buffer->next;

            a->info.total_alloc -= buffer->size;
            _free_buffer(buffer);

            buffer = _create_buffer(size);
            a->info.total_alloc += buffer->size;

            prev->next = buffer;
            buffer->next = post;
        }

        a->current = buffer;
    }

    if (append) {
        if (a->first == NULL) {
            a->first = buffer;
            a->current = buffer;
        } else {
            a->current->next = buffer;
            a->current = buffer;
        }
    }

    void *ret_ptr = &buffer->data[buffer->offset];
#ifndef ARENA_NO_ZERO_MEMORY
    memset(ret_ptr, 0, size);
#endif
    buffer->offset += size;

    return ret_ptr;
}


static void arena_reset(Arena *a)
{
    ArenaBuffer *current = a->first;
    while (current != NULL) {
        current->offset = 0;
        current = current->next;
    }

    a->current = a->first;
}


static char *arena_strdup(Arena *a, const char *str)
{
    size_t size = strlen(str) + 1;
    char *p = arena_alloc(a, size);
    errno_t err = strcpy_s(p, size, str);
    assert(!err);
    return p;
}


static void *arena_realloc(Arena *a, void *ptr, size_t size, size_t prev_size)
{
    void *nptr = arena_alloc(a, size);
    memcpy_s(nptr, size, ptr, prev_size);
    return nptr;
}


static void arena_free(Arena *a)
{
    ArenaBuffer *prev, *current;

    HANDLE heap = GetProcessHeap();
    assert(heap != NULL);

    current = a->first;
    while (current != NULL) {
        prev = current;
        current = current->next;

        a->info.total_freed += prev->size;
        _free_buffer(prev);
    }

    a->first = a->current = NULL;
}


static ArenaMark arena_mark(Arena *a)
{
    ArenaMark m = { .arena = a };

    if (a == NULL)
        return m;

    if (a->first == NULL)
        return m;

    m.current = a->current;
    m.offset = m.current->offset;

    return m;
}


static void arena_mark_reset(Arena *a, ArenaMark m)
{
    assert(a == m.arena);

    ArenaBuffer *buffer = m.current->next;
    while (buffer != NULL) {
        buffer->offset = 0;
        buffer = buffer->next;
    }

    a->current = m.current;
    a->current->offset = m.offset;
}
#endif  // ARENA_IMPLEMENTATION

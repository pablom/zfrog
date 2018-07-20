// cf_coroutine.h

#ifndef __CF_COROUTINE__H_
#define __CF_COROUTINE__H_

#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#ifdef CF_USE_VALGRIND
    #include <valgrind/valgrind.h>
#endif

#ifdef __i386__
    #define CF_CO_REG_IDX_RETADDR   0
    #define CF_CO_REG_IDX_SP        1
    #define CF_CO_REG_IDX_FPU       6
#elif __x86_64__
    #define CF_CO_REG_IDX_RETADDR   4
    #define CF_CO_REG_IDX_SP        5
    #define CF_CO_REG_IDX_FPU       8
#else
    #error "platform no support yet"
#endif

#if defined(__cplusplus)
extern "C" {
#endif

typedef void (*cofuncp_t)(void);

/* Forward structure declaration */
struct cf_coroutine;

struct cf_save_stack
{
    void*  ptr;
    size_t sz;
    size_t valid_sz;

    size_t max_cpsz;   /* max copy size in bytes */
    size_t ct_save;    /* copy from share stack to this save stack */
    size_t ct_restore; /* copy from this save stack to share stack  */
};

struct cf_share_stack
{
    void*           ptr;
    size_t          sz;
    void*           align_highptr;
    void*           align_retptr;
    size_t          align_validsz;
    size_t          align_limit;

    struct cf_coroutine*   owner;

    char            guard_page_enabled;
    void*           real_ptr;
    size_t          real_sz;

#ifdef CF_USE_VALGRIND
    unsigned long valgrind_stk_id;
#endif
};

struct cf_coroutine
{
    // cpu registers' state
#ifdef __i386__
    #ifdef CF_CO_CONFIG_SHARE_FPU_MXCSR_ENV
        void*  reg[6];
    #else
        void*  reg[8];
    #endif
#elif __x86_64__
    #ifdef CF_CO_CONFIG_SHARE_FPU_MXCSR_ENV
        void*  reg[8];
    #else
        void*  reg[9];
    #endif
#else
    #error "platform no support yet"
#endif

    struct cf_coroutine* main_co; /* Main coroutine pointer */
    void*           arg;
    char            is_end;

    cofuncp_t   fp;

    struct cf_save_stack   save_stack;
    struct cf_share_stack* share_stack;
};

struct cf_coroutine* cf_coroutine_create( struct cf_coroutine*, struct cf_share_stack*,size_t, cofuncp_t, void*);
void cf_coroutine_thread_init(cofuncp_t);
void cf_coroutine_resume(struct cf_coroutine*);
void cf_coroutine_destroy(struct cf_coroutine*);
struct cf_share_stack* cf_coroutine_share_stack_new(size_t);
void cf_coroutine_share_stack_destroy(struct cf_share_stack*);

#if defined(__cplusplus)
}
#endif

#endif // __CF_COROUTINE__H_

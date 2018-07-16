// cf_coroutine.c

#include "zfrog.h"
#include "cf_coroutine.h"
#include <sys/mman.h>

/* ASM function declaration */
void* co_swapcontext(struct cf_coroutine*, struct cf_coroutine*);
void co_save_fpucw_mxcsr(void*);
void co_funcp_protector_asm(void);

/* Local static function declaration */
static struct cf_share_stack* co_share_stack_new2(size_t, char);
static void co_default_protector_last_word(void);

void co_funcp_protector(void);

#ifdef __i386__
    static __thread void* co_gtls_fpucw_mxcsr[2];
#elif  __x86_64__
    static __thread void* co_gtls_fpucw_mxcsr[1];
#else
    #error "platform no support yet"
#endif

// Coroutine's global thread local storage variable `co`
static __thread struct cf_coroutine* co_gtls;
static __thread cf_cofuncp_t co_gtls_last_word_fp = co_default_protector_last_word;

#define co_likely(x)       (__builtin_expect(!!(x), 1))
#define co_unlikely(x)     (__builtin_expect(!!(x), 0))
#define co_assert(EX)      ((co_likely(EX))?((void)0):(abort()))
#define co_assertptr(ptr)  ((co_likely((ptr) != NULL))?((void)0):(abort()))

#define co_assertalloc_bool(b)  do {  \
    if(co_unlikely(!(b))){    \
        abort();    \
    }   \
} while(0)

#define co_assertalloc_ptr(ptr)  do {  \
    if(co_unlikely((ptr) == NULL)){    \
        abort();    \
    }   \
} while(0)


#define cf_coroutine_yield() do {        \
    co_yield1(aco_gtls_co);    \
} while(0)

#define co_get_arg() (co_gtls_co->arg)


#define co_yield1(yield_co) do {             \
    co_assertptr((yield_co));                    \
    co_assertptr((yield_co)->main_co);           \
    co_swapcontext((yield_co), (yield_co)->main_co);   \
} while(0)

#define co_exit1(co) do {     \
    (co)->is_end = 1;           \
    co_assert((co)->share_stack->owner == (co)); \
    (co)->share_stack->owner = NULL; \
    (co)->share_stack->align_validsz = 0; \
    co_yield1((co));            \
    assert(0);                  \
} while(0)

#define co_exit() do {       \
    co_exit1(co_gtls_co); \
} while(0)

// Warning: dst and src must be valid address already
#define co_amd64_inline_short_aligned_memcpy_test_ok(dst, src, sz) \
    (   \
        (((uintptr_t)(src) & 0x0f) == 0) && (((uintptr_t)(dst) & 0x0f) == 0) \
        &&  \
        (((sz) & 0x0f) == 0x08) && (((sz) >> 4) >= 0) && (((sz) >> 4) <= 8) \
    )

#define co_amd64_inline_short_aligned_memcpy(dst, src, sz) do {\
    __uint128_t __xmm0,__xmm1,__xmm2,__xmm3,__xmm4,__xmm5,__xmm6,__xmm7; \
    switch((sz) >> 4){ \
    case 0:  \
        break;  \
    case 1:  \
        __xmm0 = *((__uint128_t*)(src) + 0);  \
        *((__uint128_t*)(dst) + 0) = __xmm0; \
        break;  \
    case 2:  \
        __xmm0 = *((__uint128_t*)(src) + 0);  \
        __xmm1 = *((__uint128_t*)(src) + 1);  \
        *((__uint128_t*)(dst) + 0) = __xmm0; \
        *((__uint128_t*)(dst) + 1) = __xmm1; \
        break;  \
    case 3:  \
        __xmm0 = *((__uint128_t*)(src) + 0);  \
        __xmm1 = *((__uint128_t*)(src) + 1);  \
        __xmm2 = *((__uint128_t*)(src) + 2);  \
        *((__uint128_t*)(dst) + 0) = __xmm0; \
        *((__uint128_t*)(dst) + 1) = __xmm1; \
        *((__uint128_t*)(dst) + 2) = __xmm2; \
        break;  \
    case 4:  \
        __xmm0 = *((__uint128_t*)(src) + 0);  \
        __xmm1 = *((__uint128_t*)(src) + 1);  \
        __xmm2 = *((__uint128_t*)(src) + 2);  \
        __xmm3 = *((__uint128_t*)(src) + 3);  \
        *((__uint128_t*)(dst) + 0) = __xmm0; \
        *((__uint128_t*)(dst) + 1) = __xmm1; \
        *((__uint128_t*)(dst) + 2) = __xmm2; \
        *((__uint128_t*)(dst) + 3) = __xmm3; \
        break;  \
    case 5:  \
        __xmm0 = *((__uint128_t*)(src) + 0);  \
        __xmm1 = *((__uint128_t*)(src) + 1);  \
        __xmm2 = *((__uint128_t*)(src) + 2);  \
        __xmm3 = *((__uint128_t*)(src) + 3);  \
        __xmm4 = *((__uint128_t*)(src) + 4);  \
        *((__uint128_t*)(dst) + 0) = __xmm0; \
        *((__uint128_t*)(dst) + 1) = __xmm1; \
        *((__uint128_t*)(dst) + 2) = __xmm2; \
        *((__uint128_t*)(dst) + 3) = __xmm3; \
        *((__uint128_t*)(dst) + 4) = __xmm4; \
        break;  \
    case 6:  \
        __xmm0 = *((__uint128_t*)(src) + 0);  \
        __xmm1 = *((__uint128_t*)(src) + 1);  \
        __xmm2 = *((__uint128_t*)(src) + 2);  \
        __xmm3 = *((__uint128_t*)(src) + 3);  \
        __xmm4 = *((__uint128_t*)(src) + 4);  \
        __xmm5 = *((__uint128_t*)(src) + 5);  \
        *((__uint128_t*)(dst) + 0) = __xmm0; \
        *((__uint128_t*)(dst) + 1) = __xmm1; \
        *((__uint128_t*)(dst) + 2) = __xmm2; \
        *((__uint128_t*)(dst) + 3) = __xmm3; \
        *((__uint128_t*)(dst) + 4) = __xmm4; \
        *((__uint128_t*)(dst) + 5) = __xmm5; \
        break;  \
    case 7:  \
        __xmm0 = *((__uint128_t*)(src) + 0);  \
        __xmm1 = *((__uint128_t*)(src) + 1);  \
        __xmm2 = *((__uint128_t*)(src) + 2);  \
        __xmm3 = *((__uint128_t*)(src) + 3);  \
        __xmm4 = *((__uint128_t*)(src) + 4);  \
        __xmm5 = *((__uint128_t*)(src) + 5);  \
        __xmm6 = *((__uint128_t*)(src) + 6);  \
        *((__uint128_t*)(dst) + 0) = __xmm0; \
        *((__uint128_t*)(dst) + 1) = __xmm1; \
        *((__uint128_t*)(dst) + 2) = __xmm2; \
        *((__uint128_t*)(dst) + 3) = __xmm3; \
        *((__uint128_t*)(dst) + 4) = __xmm4; \
        *((__uint128_t*)(dst) + 5) = __xmm5; \
        *((__uint128_t*)(dst) + 6) = __xmm6; \
        break;  \
    case 8:  \
        __xmm0 = *((__uint128_t*)(src) + 0);  \
        __xmm1 = *((__uint128_t*)(src) + 1);  \
        __xmm2 = *((__uint128_t*)(src) + 2);  \
        __xmm3 = *((__uint128_t*)(src) + 3);  \
        __xmm4 = *((__uint128_t*)(src) + 4);  \
        __xmm5 = *((__uint128_t*)(src) + 5);  \
        __xmm6 = *((__uint128_t*)(src) + 6);  \
        __xmm7 = *((__uint128_t*)(src) + 7);  \
        *((__uint128_t*)(dst) + 0) = __xmm0; \
        *((__uint128_t*)(dst) + 1) = __xmm1; \
        *((__uint128_t*)(dst) + 2) = __xmm2; \
        *((__uint128_t*)(dst) + 3) = __xmm3; \
        *((__uint128_t*)(dst) + 4) = __xmm4; \
        *((__uint128_t*)(dst) + 5) = __xmm5; \
        *((__uint128_t*)(dst) + 6) = __xmm6; \
        *((__uint128_t*)(dst) + 7) = __xmm7; \
        break;  \
    }\
    *((uint64_t*)((uintptr_t)(dst) + (sz) - 8)) = *((uint64_t*)((uintptr_t)(src) + (sz) - 8)); \
} while( 0 )

// Warning: dst and src must be valid address already
#define co_amd64_optimized_memcpy_drop_in(dst, src, sz) do {\
    if(co_amd64_inline_short_aligned_memcpy_test_ok((dst), (src), (sz))){ \
        co_amd64_inline_short_aligned_memcpy((dst), (src), (sz)); \
    }else{ \
        memcpy((dst), (src), (sz)); \
    } \
} while(0)

#define co_size_t_safe_add_assert(a,b) do {   \
    co_assert((a)+(b) >= (a)); \
}while(0)


void cf_coroutine_runtime_test( void );

static void co_default_protector_last_word( void )
{
   // struct cf_coroutine* co = co_gtls;
    // do some log about the offending `co`
    fprintf(stderr,"error: co_default_protector_last_word triggered\n");
 //   fprintf(stderr, "error: co:%p should call `co_exit()` instead of direct "
 //       "`return` in co_fp:%p to finish its execution\n", (void*)co,
 //           (void (*)(void)) co->fp);
    co_assert(0);
}

void cf_coroutine_runtime_test( void )
{
#ifdef __i386__
    _Static_assert(sizeof(void*) == 4, "require 'sizeof(void*) == 4'");
#elif  __x86_64__
    _Static_assert(sizeof(void*) == 8, "require 'sizeof(void*) == 8'");
    _Static_assert(sizeof(__uint128_t) == 16, "require 'sizeof(__uint128_t) == 16'");
#else
    #error "platform no support yet"
#endif
    _Static_assert(sizeof(int) >= 4, "require 'sizeof(int) >= 4'");
    co_assert(sizeof(int) >= 4);
    _Static_assert(sizeof(int) <= sizeof(size_t),"require 'sizeof(int) <= sizeof(size_t)'");
    co_assert(sizeof(int) <= sizeof(size_t));
}

void cf_coroutine_thread_init( cf_cofuncp_t last_word_co_fp )
{
    co_save_fpucw_mxcsr(co_gtls_fpucw_mxcsr);

    if( last_word_co_fp != NULL )
        co_gtls_last_word_fp = last_word_co_fp;
}


// This function `co_funcp_protector` should never be
// called. If it's been called, that means the offending
// `co` didn't call aco_exit(co) instead of `return` to
// finish its execution.
void co_funcp_protector( void )
{
    if( (void*)(co_gtls_last_word_fp) != NULL )
    {
        co_gtls_last_word_fp();
    }
    else
        co_default_protector_last_word();

    co_assert(0);
}

struct cf_share_stack* cf_coroutine_share_stack_new( size_t sz )
{
    return co_share_stack_new2(sz, 1);
}
/****************************************************************
 *  Helper function to create coroutine stack
 ****************************************************************/
static struct cf_share_stack* co_share_stack_new2(size_t sz, char guard_page_enabled)
{
    struct cf_share_stack* p = NULL;
    size_t u_pgsz = 0;

    if(sz == 0){
        sz = 1024 * 1024 * 2;
    }
    if(sz < 4096){
        sz = 4096;
    }

    co_assert(sz > 0);

    if( guard_page_enabled != 0 )
    {
        // although gcc's Built-in Functions to Perform Arithmetic with
        // Overflow Checking is better, but it would require gcc >= 5.0
        long pgsz = sysconf(_SC_PAGESIZE);
        // pgsz must be > 0 && a power of two
        co_assert(pgsz > 0 && (((pgsz - 1) & pgsz) == 0));
        u_pgsz = (size_t)((unsigned long)pgsz);
        // it should be always true in real life
        co_assert(u_pgsz == (unsigned long)pgsz && ((u_pgsz << 1) >> 1) == u_pgsz);
        if( sz <= u_pgsz )
        {
            sz = u_pgsz << 1;
        }
        else
        {
            size_t new_sz;
            if( (sz & (u_pgsz - 1)) != 0 )
            {
                new_sz = (sz & (~(u_pgsz - 1)));
                co_assert(new_sz >= u_pgsz);
                co_size_t_safe_add_assert(new_sz, (u_pgsz << 1));
                new_sz = new_sz + (u_pgsz << 1);
                co_assert(sz / u_pgsz + 2 == new_sz / u_pgsz);
            }
            else
            {
                co_size_t_safe_add_assert(sz, u_pgsz);
                new_sz = sz + u_pgsz;
                co_assert(sz / u_pgsz + 1 == new_sz / u_pgsz);
            }

            sz = new_sz;
            co_assert((sz / u_pgsz > 1) && ((sz & (u_pgsz - 1)) == 0));
        }
    }

    p = malloc(sizeof(struct cf_share_stack));
    co_assertalloc_ptr(p);
    memset(p, 0, sizeof(struct cf_share_stack));

    if( guard_page_enabled != 0 )
    {
        p->real_ptr = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        co_assertalloc_bool(p->real_ptr != MAP_FAILED);
        p->guard_page_enabled = 1;
        co_assert(0 == mprotect(p->real_ptr, u_pgsz, PROT_READ));

        p->ptr = (void*)(((uintptr_t)p->real_ptr) + u_pgsz);
        p->real_sz = sz;
        co_assert(sz >= (u_pgsz << 1));
        p->sz = sz - u_pgsz;
    }
    else
    {
        //p->guard_page_enabled = 0;
        p->sz = sz;
        p->ptr = malloc(sz);
        co_assertalloc_ptr(p->ptr);
    }

    p->owner = NULL;
#ifdef CF_USE_VALGRIND
    p->valgrind_stk_id = VALGRIND_STACK_REGISTER( p->ptr, (void*)((uintptr_t)p->ptr + p->sz) );
#endif
#if defined(__i386__) || defined(__x86_64__)
    uintptr_t u_p = (uintptr_t)(p->sz - (sizeof(void*) << 1) + (uintptr_t)p->ptr);
    u_p = (u_p >> 4) << 4;
    p->align_highptr = (void*)u_p;
    p->align_retptr  = (void*)(u_p - sizeof(void*));
    *((void**)(p->align_retptr)) = (void*)(co_funcp_protector_asm);
    co_assert(p->sz > (16 + (sizeof(void*) << 1) + sizeof(void*)));
    p->align_limit = p->sz - 16 - (sizeof(void*) << 1);
#else
    #error "platform no support yet"
#endif
    return p;
}
/****************************************************************
 *  Coroutine stack destroy function
 ****************************************************************/
void cf_coroutine_share_stack_destroy( struct cf_share_stack* sstk )
{
    co_assert(sstk != NULL && sstk->ptr != NULL);
#ifdef CF_USE_VALGRIND
    VALGRIND_STACK_DEREGISTER(sstk->valgrind_stk_id);
#endif
    if( sstk->guard_page_enabled )
    {
        co_assert(0 == munmap(sstk->real_ptr, sstk->real_sz));
        sstk->real_ptr = NULL;
        sstk->ptr = NULL;
    }
    else
    {
        free( sstk->ptr );
        sstk->ptr = NULL;
    }

    free( sstk );
}
/****************************************************************
 *  Coroutine create function
 ****************************************************************/
struct cf_coroutine* cf_coroutine_create( struct cf_coroutine* main_co, struct cf_share_stack* share_stack,
                                          size_t save_stack_sz, cf_cofuncp_t fp, void* arg )
{
    struct cf_coroutine* p = malloc(sizeof(struct cf_coroutine));
    co_assertalloc_ptr(p);
    memset(p, 0, sizeof(struct cf_coroutine));

    if( main_co != NULL )
    {
        // non-main coroutine
        co_assertptr(share_stack);
        p->share_stack = share_stack;

#ifdef __i386__
        // POSIX.1-2008 (IEEE Std 1003.1-2008) - General Information - Data Types - Pointer Types
        // http://pubs.opengroup.org/onlinepubs/9699919799.2008edition/functions/V2_chap02.html#tag_15_12_03
        p->reg[CF_CO_REG_IDX_RETADDR] = (void*)fp;
        // push retaddr
        p->reg[CO_REG_IDX_SP] = p->share_stack->align_retptr;
        #ifndef CF_CO_CONFIG_SHARE_FPU_MXCSR_ENV
            p->reg[CF_CO_REG_IDX_FPU] = co_gtls_fpucw_mxcsr[0];
            p->reg[CF_CO_REG_IDX_FPU + 1] = co_gtls_fpucw_mxcsr[1];
        #endif
#elif  __x86_64__
        p->reg[CF_CO_REG_IDX_RETADDR] = (void*)fp;
        p->reg[CF_CO_REG_IDX_SP] = p->share_stack->align_retptr;
        #ifndef CF_CO_CONFIG_SHARE_FPU_MXCSR_ENV
            p->reg[CF_CO_REG_IDX_FPU] = co_gtls_fpucw_mxcsr[0];
        #endif
#else
        #error "platform no support yet"
#endif
        p->main_co = main_co;
        p->arg = arg;
        p->fp = fp;
        if( save_stack_sz == 0 ){
            save_stack_sz = 64;
        }

        p->save_stack.ptr = malloc(save_stack_sz);
        co_assertalloc_ptr(p->save_stack.ptr);
        p->save_stack.sz = save_stack_sz;
#if defined(__i386__) || defined(__x86_64__)
        p->save_stack.valid_sz = 0;
#else
        #error "platform no support yet"
#endif
        return p;
    }
    else
    {   /* main coroutine */
        p->main_co = NULL;
        p->arg = arg;
        p->fp = fp;
        p->share_stack = NULL;
        p->save_stack.ptr = NULL;
        return p;
    }

    co_assert(0);
}
/****************************************************************
 *  Coroutine resume function
 ****************************************************************/
void cf_coroutine_resume( struct cf_coroutine* resume_co )
{
    co_assert(resume_co != NULL && resume_co->main_co != NULL && resume_co->is_end == 0);

    if( resume_co->share_stack->owner != resume_co )
    {
        if( resume_co->share_stack->owner != NULL )
        {
            struct cf_coroutine* owner_co = resume_co->share_stack->owner;
            co_assert(owner_co->share_stack == resume_co->share_stack);
#if defined(__i386__) || defined(__x86_64__)
            co_assert(
                (
                    (uintptr_t)(owner_co->share_stack->align_retptr)
                    >=
                    (uintptr_t)(owner_co->reg[CF_CO_REG_IDX_SP])
                )
                &&
                (
                    (uintptr_t)(owner_co->share_stack->align_highptr)
                    -
                    (uintptr_t)(owner_co->share_stack->align_limit)
                    <=
                    (uintptr_t)(owner_co->reg[CF_CO_REG_IDX_SP])
                )
            );
            owner_co->save_stack.valid_sz =
                (uintptr_t)(owner_co->share_stack->align_retptr)
                -
                (uintptr_t)(owner_co->reg[CF_CO_REG_IDX_SP]);

            if( owner_co->save_stack.sz < owner_co->save_stack.valid_sz )
            {
                free(owner_co->save_stack.ptr);
                owner_co->save_stack.ptr = NULL;

                while( 1 )
                {
                    owner_co->save_stack.sz = owner_co->save_stack.sz << 1;
                    co_assert(owner_co->save_stack.sz > 0);
                    if( owner_co->save_stack.sz >= owner_co->save_stack.valid_sz )
                        break;
                }

                owner_co->save_stack.ptr = malloc(owner_co->save_stack.sz);
                co_assertalloc_ptr(owner_co->save_stack.ptr);
            }
            // TODO: optimize the performance penalty of memcpy function call
            //   for very short memory span
            if( owner_co->save_stack.valid_sz > 0 )
            {
    #ifdef __x86_64__
                co_amd64_optimized_memcpy_drop_in(
                    owner_co->save_stack.ptr,
                    owner_co->reg[CF_CO_REG_IDX_SP],
                    owner_co->save_stack.valid_sz
                );
    #else
                memcpy(
                    owner_co->save_stack.ptr,
                    owner_co->reg[CF_CO_REG_IDX_SP],
                    owner_co->save_stack.valid_sz
                );
    #endif
                owner_co->save_stack.ct_save++;
            }

            if( owner_co->save_stack.valid_sz > owner_co->save_stack.max_cpsz )
                owner_co->save_stack.max_cpsz = owner_co->save_stack.valid_sz;

            owner_co->share_stack->owner = NULL;
            owner_co->share_stack->align_validsz = 0;
#else
            #error "platform no support yet"
#endif
        }
        co_assert(resume_co->share_stack->owner == NULL);
#if defined(__i386__) || defined(__x86_64__)
        co_assert( resume_co->save_stack.valid_sz <= resume_co->share_stack->align_limit - sizeof(void*) );
        // TODO: optimize the performance penalty of memcpy function call
        //   for very short memory span
        if( resume_co->save_stack.valid_sz > 0 )
        {
    #ifdef __x86_64__
            co_amd64_optimized_memcpy_drop_in(
                (void*)(
                    (uintptr_t)(resume_co->share_stack->align_retptr)
                    -
                    resume_co->save_stack.valid_sz
                ),
                resume_co->save_stack.ptr,
                resume_co->save_stack.valid_sz
            );
    #else
            memcpy(
                (void*)(
                    (uintptr_t)(resume_co->share_stack->align_retptr)
                    -
                    resume_co->save_stack.valid_sz
                ),
                resume_co->save_stack.ptr,
                resume_co->save_stack.valid_sz
            );
    #endif
            resume_co->save_stack.ct_restore++;
        }
        if(resume_co->save_stack.valid_sz > resume_co->save_stack.max_cpsz){
            resume_co->save_stack.max_cpsz = resume_co->save_stack.valid_sz;
        }
        resume_co->share_stack->align_validsz = resume_co->save_stack.valid_sz + sizeof(void*);
        resume_co->share_stack->owner = resume_co;
#else
        #error "platform no support yet"
#endif
    }

    co_gtls = resume_co;
    co_swapcontext( resume_co->main_co, resume_co );
    co_gtls = resume_co->main_co;
}
/****************************************************************
 *  Coroutine destroy function
 ****************************************************************/
void cf_coroutine_destroy( struct cf_coroutine* co )
{
    co_assertptr(co);

    if( co->main_co == NULL )
    {
        free( co );
    }
    else
    {
        if( co->share_stack->owner == co)
        {
            co->share_stack->owner = NULL;
            co->share_stack->align_validsz = 0;
        }

        free( co->save_stack.ptr );
        co->save_stack.ptr = NULL;
        free( co );
    }
}

static inline void coroutine_yield1( struct cf_coroutine* yield_co )
{
    co_assertptr((yield_co));
    co_assertptr((yield_co)->main_co);

    co_swapcontext((yield_co), (yield_co)->main_co);
}


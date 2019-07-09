#ifndef HEADER_H
#define HEADER_H
#define Z3_Get_Ref(exp) (((int*)((Z3_ast)((exp))))[2])

#if defined(GUEST_IS_64)
#define ADDR unsigned long long
#else
#define ADDR unsigned int
#endif

#define TESTCODE(code)                                                                                                         \
{                                                                                                                             \
    LARGE_INTEGER   freq = { 0 };                                                                                             \
    LARGE_INTEGER   beginPerformanceCount = { 0 };                                                                             \
    LARGE_INTEGER   closePerformanceCount = { 0 };                                                                             \
    QueryPerformanceFrequency(&freq);                                                                                         \
    QueryPerformanceCounter(&beginPerformanceCount);                                                                         \
    {code    }                                                                                                                 \
    QueryPerformanceCounter(&closePerformanceCount);                                                                         \
    double delta_seconds = (double)(closePerformanceCount.QuadPart - beginPerformanceCount.QuadPart) / freq.QuadPart;         \
    printf("%s line:%d spend %lf \n",__FILE__, __LINE__, delta_seconds);                                                     \
}

#define mem_w(addr_in, value) state->mem.Ist_Store_R((Addr64)(&(addr_in)), value);
#define reg_r(offset, Ity) state->regs.Iex_Get(offset, Ity)


#define ALIGN(Value,size) ((Value) & ~((size) - 1))

extern "C" 
{
#include "../Valgrind/pub/libvex.h";
}
extern "C" Bool vex_initdone;
extern "C" unsigned char tid2temp[0x10000];
extern "C" tid_type register_tid(unsigned int);
extern "C" tid_type unregister_tid(unsigned int);
extern "C" void tempmeminit();
extern "C" void init_threads_id();
extern "C" void vex_assert_fail(const HChar* expr,const HChar* file, Int line, const HChar* fn);
extern "C" unsigned int vex_printf(const HChar* format, ...);
extern "C" void vpanic(const HChar* str);


extern unsigned char fastalignD1[257 ];
extern unsigned char fastalign[257];
extern ULong fastMask[65];
extern ULong fastMaskI1[65];
extern ULong fastMaskB[9];
extern ULong fastMaskBI1[9];
extern ULong fastMaskReverse[65];
extern ULong fastMaskReverseI1[65];


template <int maxlength> class Register;
class State;


typedef enum :unsigned int {
    NewState = 0,
    Running,
    Fork,
    Death
}State_Tag;


typedef enum :unsigned int {
    TRMemory,TRRegister
}Storage;

typedef State_Tag(*CallBack)(State *);
typedef PyObject *(*Super)(PyObject *);
typedef struct _Hook {
    CallBack cb;
    UChar original;
}Hook_struct;

typedef struct {
    Storage kind;
    ADDR address;
    ADDR r_offset;
    IRType ty;
}Hook_Replace;

#if defined(_DEBUG)||1

#define vassert(xexpr)                                           \
  ((void) ((xexpr) ? 0 :                                         \
           (vex_assert_fail (#xexpr,                             \
                             __FILE__, __LINE__,                 \
                             __FUNCSIG__), 0)))
#else
#define vassert(...) 
#endif // _DEBUG



/* vex_traceflags values */
#define VEX_TRACE_FE     (1 << 7)  /* show conversion into IR */
#define VEX_TRACE_OPT1   (1 << 6)  /* show after initial opt */
#define VEX_TRACE_INST   (1 << 5)  /* show after instrumentation */
#define VEX_TRACE_OPT2   (1 << 4)  /* show after second opt */
#define VEX_TRACE_TREES  (1 << 3)  /* show after tree building */
#define VEX_TRACE_VCODE  (1 << 2)  /* show selected insns */
#define VEX_TRACE_RCODE  (1 << 1)  /* show after reg-alloc */
#define VEX_TRACE_ASM    (1 << 0)  /* show final assembly */


#define SET1(addr, value) *(UChar*)((addr)) = (value)
#define SET2(addr, value) *(UShort*)((addr)) = (value)
#define SET4(addr, value) *(UInt*)((addr)) = (value)
#define SET8(addr, value) *(ULong*)((addr)) = (value)
#define SET16(addr, value) *(__m128i*)((addr)) = (value)
#define SET32(addr, value) *(__m256i*)((addr)) = (value)

#define GET1(addr) (*(UChar*)((addr))) 
#define GET2(addr) (*(UShort*)((addr)))
#define GET4(addr) (*(UInt*)((addr)))
#define GET8(addr) (*(ULong*)((addr)))
#define GET16(addr) (*(__m128i*)((addr)))
#define GET32(addr) (*(__m256i*)((addr)))


#define GETS1(addr) (*(Char*)((addr))) 
#define GETS2(addr) (*(Short*)((addr)))
#define GETS4(addr) (*(Int*)((addr)))
#define GETS8(addr) (*(Long*)((addr)))
#define GETS16(addr) (*(__m128i*)((addr)))
#define GETS32(addr) (*(__m256i*)((addr)))

#define MV1(addr,fromaddr) *(UChar*)((addr))=(*(UChar*)((fromaddr))) 
#define MV2(addr,fromaddr) *(UShort*)((addr))=(*(UShort*)((fromaddr)))
#define MV4(addr,fromaddr) *(UInt*)((addr))=(*(UInt*)((fromaddr)))
#define MV8(addr,fromaddr) *(ULong*)((addr))=(*(ULong*)((fromaddr)))
#define MV16(addr,fromaddr) *(__m128i*)((addr))=(*(__m128i*)((fromaddr)))
#define MV32(addr,fromaddr) *(__m256i*)((addr))=(*(__m256i*)((fromaddr)))

typedef enum:unsigned char {
    nothing,
    symbolic,
    numreal
}memTAG;



inline __m128i _mm_not_si128(__m128i a) {
    __m128i r;
    r.m128i_u64[0] = ~a.m128i_u64[0];
    r.m128i_u64[1] = ~a.m128i_u64[1];
    return  r;
}
inline __m256i _mm256_not_si256(__m256i a) {
    __m256i r;
    r.m256i_u64[0] = ~a.m256i_u64[0];
    r.m256i_u64[1] = ~a.m256i_u64[1];
    r.m256i_u64[2] = ~a.m256i_u64[2];
    r.m256i_u64[3] = ~a.m256i_u64[3];
    return r;
}

inline Z3_ast Z3_mk_neq(Z3_context ctx, Z3_ast a, Z3_ast b) {
    auto eq = Z3_mk_eq(ctx, a, b);
    Z3_inc_ref(ctx, eq);
    auto re = Z3_mk_not(ctx, eq);
    Z3_dec_ref(ctx, eq);
    return re;
}

extern std::string replace(const char *pszSrc, const char *pszOld, const char *pszNew);
extern int eval_all(std::vector<Z3_ast> &result, z3::solver &solv, Z3_ast nia);
extern unsigned char * _n_page_mem(void *);
extern LARGE_INTEGER   freq_global;
extern LARGE_INTEGER   beginPerformanceCount_global;
extern LARGE_INTEGER   closePerformanceCount_global;
extern VexArch guest;
extern State *_states[MAX_THREADS];
extern std::vector<ADDR> avoid_branch_oep;
#define current_state() _states[temp_index()]







typedef enum :unsigned int {
    IR_eax = 8,
    IR_ax = 8,
    IR_al = 8,
    IR_ah = 9,
    IR_ecx = 12,
    IR_cx = 12,
    IR_cl = 12,
    IR_ch = 13,
    IR_edx = 16,
    IR_dx = 16,
    IR_dl = 16,
    IR_dh = 17,
    IR_ebx = 20,
    IR_bx = 20,
    IR_bl = 20,
    IR_bh = 21,
    IR_esp = 24,
    IR_sp = 24,
    IR_ebp = 28,
    IR_bp = 28,
    IR_esi = 32,
    IR_si = 32,
    IR_sil = 32,
    IR_sih = 33,
    IR_edi = 36,
    IR_di = 36,
    IR_dil = 36,
    IR_dih = 37,
    IR_cc_op = 40,
    IR_cc_dep1 = 44,
    IR_cc_dep2 = 48,
    IR_cc_ndep = 52,
    IR_d = 56,
    IR_dflag = 56,
    IR_id = 60,
    IR_idflag = 60,
    IR_ac = 64,
    IR_acflag = 64,
    IR_eip = 68,
    IR_ip = 68,
    IR_pc = 68,
    IR_fpreg = 72,
    IR_fpu_regs = 72,
    IR_mm0 = 72,
    IR_mm1 = 80,
    IR_mm2 = 88,
    IR_mm3 = 96,
    IR_mm4 = 104,
    IR_mm5 = 112,
    IR_mm6 = 120,
    IR_mm7 = 128,
    IR_fptag = 136,
    IR_fpu_tags = 136,
    IR_fpround = 144,
    IR_fc3210 = 148,
    IR_ftop = 152,
    IR_sseround = 156,
    IR_xmm0 = 160,
    IR_xmm1 = 176,
    IR_xmm2 = 192,
    IR_xmm3 = 208,
    IR_xmm4 = 224,
    IR_xmm5 = 240,
    IR_xmm6 = 256,
    IR_xmm7 = 272,
    IR_cs = 288,
    IR_ds = 290,
    IR_es = 292,
    IR_fs = 294,
    IR_gs = 296,
    IR_ss = 298,
    IR_ldt = 304,
    IR_gdt = 312,
    IR_emnote = 320,
    IR_cmstart = 324,
    IR_cmlen = 328,
    IR_nraddr = 332,
    IR_sc_class = 336,
    IR_ip_at_syscall = 340
}X86_IR_OFFSET;









#endif // HEADER_H


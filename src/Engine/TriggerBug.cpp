﻿/*++
Copyright (c) 2019 Microsoft Corporation
Module Name:
    TriggerBug.cpp: 
Abstract:
    API list;
Author:
    WXC 2019-05-31.
Revision History:
--*/
#define HOSTARCH VexArchAMD64

//#define GUEST_IS_64 

//#undef _DEBUG
#define DLL_EXPORTS
//#define INIFILENAME "C:\\Users\\bibi\\Desktop\\TriggerBug\\PythonFrontEnd\\TriggerBug-asong.xml"
#define INIFILENAME "C:/Users/bibi/Desktop/TriggerBug/PythonFrontEnd/TriggerBug-default32.xml"
#define INIFILENAME "C:/Users/bibi/Desktop/TriggerBug/PythonFrontEnd/examples/SCTF/ckm.xml"

#include "engine.hpp"
#define vpanic(...) printf("%s line %d",__FILE__,__LINE__); vpanic(__VA_ARGS__);
#include "tinyxml2/tinyxml2.h"
#include "libvex_init.hpp"
#include "Thread_Pool/ThreadPool.hpp"
#include "SimulationEngine/Variable.hpp"
#include "SimulationEngine/Register.hpp"
#include "SimulationEngine/memory.hpp"
#include "SimulationEngine/State_class_CD.hpp"
#include "Z3_Target_Call/Guest_Helper.hpp"
#include "SimulationEngine/State_class.hpp"

unsigned int    global_user;
std::mutex      global_user_mutex;
LARGE_INTEGER   freq_global = { 0 };
LARGE_INTEGER   beginPerformanceCount_global = { 0 };
LARGE_INTEGER   closePerformanceCount_global = { 0 };


/*Legal parameters are :
  ctrl_c(bool) (default: true)
  dump_benchmarks(bool) (default: false)
  dump_models(bool) (default: false)
  elim_01(bool) (default: true)
  enable_sat(bool) (default: true)
  enable_sls(bool) (default: false)
  maxlex.enable(bool) (default: true)
  maxres.add_upper_bound_block(bool) (default: false)
  maxres.hill_climb(bool) (default: true)
  maxres.max_core_size(unsigned int) (default: 3)
  maxres.max_correction_set_size(unsigned int) (default: 3)
  maxres.max_num_cores(unsigned int) (default: 4294967295)
  maxres.maximize_assignment(bool) (default: false)
  maxres.pivot_on_correction_set(bool) (default: true)
  maxres.wmax(bool) (default: false)
  maxsat_engine(symbol) (default: maxres)
  optsmt_engine(symbol) (default: basic)
  pb.compile_equality(bool) (default: false)
  pp.neat(bool) (default: true)
  priority(symbol) (default: lex)
  rlimit(unsigned int) (default: 0)
  solution_prefix(symbol) (default:)
  timeout(unsigned int) (default: 4294967295)
*/

unsigned char * _n_page_mem(void *pap) {
    return ((State*)(((Pap*)(pap))->state))->mem.get_next_page(((Pap*)(pap))->guest_addr);
}


std::string replace(const char* pszSrc, const char* pszOld, const char* pszNew)
{
    std::string strContent, strTemp;
    strContent.assign(pszSrc);
    std::string::size_type nPos = 0;
    while (true)
    {
        nPos = strContent.find(pszOld, nPos);
        strTemp = strContent.substr(nPos + strlen(pszOld), strContent.length());
        if (nPos == std::string::npos)
        {
            break;
        }
        strContent.replace(nPos, strContent.length(), pszNew);
        strContent.append(strTemp);
        nPos += strlen(pszNew) - strlen(pszOld) + 1;
    }
    return strContent;
}


inline unsigned int assumptions_check(solver& solv, int n_assumptions, Z3_ast *assumptions) {
    std::vector<Z3_model> mv;
    mv.reserve(20);
    register Z3_context ctx = solv.ctx();
    Z3_lbool b;
    try {
        b = Z3_solver_check_assumptions(ctx, solv, n_assumptions, assumptions);
    }
    catch (...) {
        Z3_error_code e = Z3_get_error_code(ctx);
        if (e != Z3_OK)
            throw (Z3_get_error_msg(ctx, e));
        throw e;
    }
    return b;
}

inline int eval_all(std::vector<Z3_ast>& result, solver& solv, Z3_ast nia) {
    //std::cout << nia << std::endl;
    //std::cout << state.solv.assertions() << std::endl;
    result.reserve(20);
    solv.push();
    std::vector<Z3_model> mv;
    mv.reserve(20);
    register Z3_context ctx = solv.ctx();
    for (int nway = 0; ; nway++) {
        Z3_lbool b = Z3_solver_check(ctx, solv);
        if (b == Z3_L_TRUE) {
            Z3_model m_model = Z3_solver_get_model(ctx, solv);
            Z3_model_inc_ref(ctx, m_model);
            mv.emplace_back(m_model);
            Z3_ast r = 0;
            bool status = Z3_model_eval(ctx, m_model, nia, /*model_completion*/false, &r);
            Z3_inc_ref(ctx, r);
            result.emplace_back(r);
            Z3_ast_kind rkind = Z3_get_ast_kind(ctx, r);
            if (rkind != Z3_NUMERAL_AST) {
                std::cout << rkind << Z3_ast_to_string(ctx, nia) << std::endl;
                std::cout << solv.assertions() << std::endl;
                vassert(0);
            }
            Z3_ast eq = Z3_mk_eq(ctx, nia, r);
            Z3_inc_ref(ctx, eq);
            Z3_ast neq = Z3_mk_not(ctx, eq);
            Z3_inc_ref(ctx, neq);
            Z3_solver_assert(ctx, solv, neq);
            Z3_dec_ref(ctx, eq);
            Z3_dec_ref(ctx, neq);
        }
        else {
#if defined(OPSTR)
            //std::cout << "     sizeof symbolic : " << result.size() ;
            for (auto s : result) std::cout << ", " << Z3_ast_to_string(ctx, s);
#endif
            solv.pop();
            for (auto m : mv) Z3_model_dec_ref(ctx, m);

            return result.size();
        }
    }
}


#define pyAndC_Def(type)                                                        \
template<class T,class toTy>                                                    \
inline PyObject* cvector2list_##type(T cvector)                                 \
{                                                                               \
    PyObject* result = PyList_New(0);                                           \
    for (auto value : cvector) {                                                \
        PyList_Append(result, PyLong_From##type((toTy)(value)));                \
    }                                                                           \
    return result;                                                              \
}                                                                               \
                                                                                \
template<class T, class Ty>                                                     \
inline void list2cvector_##type(T vector, PyObject* obj)                        \
{                                                                               \
    if (PyList_Check(obj)) {                                                    \
        for (Py_ssize_t i = 0; i < PyList_Size(obj); i++) {                     \
            PyObject *value = PyList_GetItem(obj, i);                           \
            vector.emplace_back((Ty)PyLong_As##type(value));                    \
        }                                                                       \
    }                                                                           \
}


pyAndC_Def(LongLong)
pyAndC_Def(Long)

extern "C"
{
    DLLDEMO_API State *     TB_top_state            (PyObject *base, Super superState_cb, State_Tag(*func_cb)(State *, IRJumpKind), char *filename, Addr64 oep, Bool need_record);
    DLLDEMO_API PyObject*   TB_cState2pState        (State* s);
    DLLDEMO_API State *     TB_state_fork           (PyObject *base, State * father, Addr64 oep);
    DLLDEMO_API Addr64      TB_state_guest_start    (State *s);
    DLLDEMO_API Addr64      TB_state_guest_start_ep (State *s);
    DLLDEMO_API State_Tag   TB_state_status         (State *s);
    DLLDEMO_API Z3_solver   TB_state_solver         (State *s);
    DLLDEMO_API void        TB_state_add_assert     (State *s, Z3_ast assert, Bool ToF);
    DLLDEMO_API Z3_ast      TB_state_cast           (State* s, Z3_ast value);
    DLLDEMO_API void        TB_replace_add          (State* s, Storage st, Addr64 addr, Addr64 r_offset, IRType ty);
    DLLDEMO_API void        TB_state_start          (State *s);
    DLLDEMO_API void        TB_state_compress       (State *s, Addr64 Target_Addr, State_Tag tag, PyObject* avoid);
    DLLDEMO_API PyObject*   TB_state_branch         (State *s);
    DLLDEMO_API Z3_context  TB_state_ctx            (State *s);
    DLLDEMO_API void        TB_state_delta          (State *s, Long length);
    DLLDEMO_API ULong       TB_mem_map              (State *s, Addr64 address, ULong length);
    DLLDEMO_API ULong       TB_mem_unmap            (State *s, Addr64 address, ULong length);
    DLLDEMO_API void        TB_hook_add             (State *s, Addr64 address, CallBack func);
    DLLDEMO_API HMODULE     TB_Z3_Model_Handle      ();
    DLLDEMO_API void        TB_thread_wait          ();


    
    DLLDEMO_API void regs_r_write1(State *s, UShort offset, UChar  value);
    DLLDEMO_API void regs_r_write2(State *s, UShort offset, UShort value);
    DLLDEMO_API void regs_r_write4(State *s, UShort offset, UInt   value);
    DLLDEMO_API void regs_r_write8(State *s, UShort offset, ULong  value);

    DLLDEMO_API void regs_s_write(State *s, UShort offset, Z3_ast value);

    DLLDEMO_API void regs_s_write1(State *s, UShort offset, Z3_ast value);
    DLLDEMO_API void regs_s_write2(State *s, UShort offset, Z3_ast value);
    DLLDEMO_API void regs_s_write4(State *s, UShort offset, Z3_ast value);
    DLLDEMO_API void regs_s_write8(State *s, UShort offset, Z3_ast value);

    DLLDEMO_API Z3_ast regs_read1(State *s, UChar  *result, UShort offset);
    DLLDEMO_API Z3_ast regs_read2(State *s, UShort *result, UShort offset);
    DLLDEMO_API Z3_ast regs_read4(State *s, UInt   *result, UShort offset);
    DLLDEMO_API Z3_ast regs_read8(State *s, ULong  *result, UShort offset);

    DLLDEMO_API void mem_r_r_write1(State *s, Addr64 offset, UChar  value);
    DLLDEMO_API void mem_r_r_write2(State *s, Addr64 offset, UShort value);
    DLLDEMO_API void mem_r_r_write4(State *s, Addr64 offset, UInt   value);
    DLLDEMO_API void mem_r_r_write8(State *s, Addr64 offset, ULong  value);
                                                                          
    DLLDEMO_API void mem_r_s_write1(State *s, Addr64 offset, Z3_ast value);
    DLLDEMO_API void mem_r_s_write2(State *s, Addr64 offset, Z3_ast value);
    DLLDEMO_API void mem_r_s_write4(State *s, Addr64 offset, Z3_ast value);
    DLLDEMO_API void mem_r_s_write8(State *s, Addr64 offset, Z3_ast value);
                                                                          
    DLLDEMO_API void mem_s_r_write1(State *s, Z3_ast offset, UChar  value);
    DLLDEMO_API void mem_s_r_write2(State *s, Z3_ast offset, UShort value);
    DLLDEMO_API void mem_s_r_write4(State *s, Z3_ast offset, UInt   value);
    DLLDEMO_API void mem_s_r_write8(State *s, Z3_ast offset, ULong  value);
                                                                          
    DLLDEMO_API void mem_s_s_write1(State *s, Z3_ast offset, Z3_ast value);
    DLLDEMO_API void mem_s_s_write2(State *s, Z3_ast offset, Z3_ast value);
    DLLDEMO_API void mem_s_s_write4(State *s, Z3_ast offset, Z3_ast value);
    DLLDEMO_API void mem_s_s_write8(State *s, Z3_ast offset, Z3_ast value);

    DLLDEMO_API Z3_ast mem_r_read1(State *s, UChar  *result, Addr64 addr);
    DLLDEMO_API Z3_ast mem_r_read2(State *s, UShort *result, Addr64 addr);
    DLLDEMO_API Z3_ast mem_r_read4(State *s, UInt   *result, Addr64 addr);
    DLLDEMO_API Z3_ast mem_r_read8(State *s, ULong  *result, Addr64 addr);


    DLLDEMO_API Z3_ast mem_s_read1(State *s, UChar  *result, Z3_ast addr);
    DLLDEMO_API Z3_ast mem_s_read2(State *s, UShort *result, Z3_ast addr);
    DLLDEMO_API Z3_ast mem_s_read4(State *s, UInt   *result, Z3_ast addr);
    DLLDEMO_API Z3_ast mem_s_read8(State *s, ULong  *result, Z3_ast addr);

}




State *     TB_top_state(
    PyObject *base ,
    Super superState_cb, 
    State_Tag(*func_cb)(State *, IRJumpKind),
    char *filename,
    Addr64 oep,
    Bool need_record
) {
    pState_fork = superState_cb;
    Ijk_call_back = func_cb;
    return new State(filename, oep, need_record, base);
}
HMODULE     TB_Z3_Model_Handle() { return  GetModuleHandle(TEXT("libz3.dll")); }
State *     TB_state_fork(PyObject *base, State * father, Addr64 oep) { return new State(father, oep, base); }
PyObject *  TB_cState2pState(State * s) { return s->base; }
Addr64      TB_state_guest_start(State *s) { return s->get_guest_start(); }
Addr64      TB_state_guest_start_ep(State *s) { return s->get_guest_start_ep(); }
State_Tag   TB_state_status(State *s) { return s->status; }
void        TB_state_start(State * s) {
    pool->enqueue([s] {
        s->start(True);
    });
}
void        TB_thread_wait() { pool->wait(); }
void        TB_state_delta(State *s, Long length) { s->delta = length; }
void        TB_state_compress(State * s, Addr64 Target_Addr, State_Tag tag, PyObject* avoid) {
    std::vector<State_Tag> ds;
    list2cvector_Long<std::vector<State_Tag>,State_Tag>(ds, avoid);
    s->compress(Target_Addr, tag, ds);
}
PyObject*   TB_state_branch(State *s) { return cvector2list_LongLong<std::vector<State*>,ULong>(s->branch); }
void        TB_hook_add(State *s, Addr64 addr, CallBack func) {
    if (CallBackDict.find(addr) == CallBackDict.end()) {
        auto P = s->mem.getMemPage(addr);
        CallBackDict[addr] = Hook_struct{ func ,P->unit->m_bytes[addr & 0xfff] };
        P->unit->m_bytes[addr & 0xfff] = 0xCC;
    }
    else {
        CallBackDict[addr].cb = func;
    }
}

void        TB_replace_add(State* state, Storage s, Addr64 addr, Addr64 r_offset, IRType ty) {
    if (ReplaceDict.find(addr) == ReplaceDict.end()) {
        if (CallBackDict.find(addr) == CallBackDict.end()) {
            TB_hook_add(state, addr, CallBack(0));
        }
        std::vector<Hook_Replace> v;
        v.emplace_back(Hook_Replace{ s ,addr,r_offset, ty });
        ReplaceDict[addr] = v;
    }
    else {
        ReplaceDict.find(addr)->second.emplace_back(Hook_Replace{ s ,addr, r_offset, ty });
    }
}

ULong       TB_mem_map(State *s, Addr64 address, ULong length) { return s->mem.map(address, length); }
ULong       TB_mem_unmap(State *s, Addr64 address, ULong length) { return s->mem.unmap(address, length); }
Z3_solver   TB_state_solver(State *s) { return s->solv; }
Z3_context  TB_state_ctx(State *s) { return *s; };
void        TB_state_add_assert(State *s, Z3_ast assert, Bool ToF) { s->add_assert(Vns(s->m_ctx, assert, 1), ToF); }
Z3_ast      TB_state_cast(State* s, Z3_ast value) {
    auto re = s->cast(Vns(s->m_ctx, value));
    Z3_inc_ref(s->m_ctx, re);
    return re;
};

void regs_r_write1(State *s, UShort offset, UChar     value) { s->regs.Ist_Put(offset, value); }
void regs_r_write2(State *s, UShort offset, UShort    value) { s->regs.Ist_Put(offset, value); }
void regs_r_write4(State *s, UShort offset, UInt      value) { s->regs.Ist_Put(offset, value); }
void regs_r_write8(State *s, UShort offset, ULong     value) { s->regs.Ist_Put(offset, value); }

void regs_s_write(State *s, UShort offset, Z3_ast    value)  { s->regs.Ist_Put(offset, Vns(s->m_ctx, value)); }
void regs_s_write1(State *s, UShort offset, Z3_ast    value) { s->regs.Ist_Put<8>(offset, value); }
void regs_s_write2(State *s, UShort offset, Z3_ast    value) { s->regs.Ist_Put<16>(offset, value); }
void regs_s_write4(State *s, UShort offset, Z3_ast    value) { s->regs.Ist_Put<32>(offset, value); }
void regs_s_write8(State *s, UShort offset, Z3_ast    value) { s->regs.Ist_Put<64>(offset, value); }



#define regs_read_def(nbytes,nbit,T)                                    \
Z3_ast regs_read##nbytes##(State *s, T *result, UShort offset) {        \
    Vns v = s->regs.Iex_Get(offset, Ity_I##nbit##);                     \
    if (v.real()) {                                                     \
        *result = v;                                                    \
        return NULL;                                                    \
    }                                                                   \
    else {                                                              \
        Z3_inc_ref(*s,v);                                               \
        return v;                                                       \
    }                                                                   \
}                                                                       \

regs_read_def(1,  8, UChar)
regs_read_def(2, 16, UShort)
regs_read_def(4, 32, UInt)
regs_read_def(8, 64, ULong)


void mem_r_r_write1(State *s, Addr64 offset, UChar  value) { s->mem.Ist_Store(offset, value); }
void mem_r_r_write2(State *s, Addr64 offset, UShort value) { s->mem.Ist_Store(offset, value); }
void mem_r_r_write4(State *s, Addr64 offset, UInt   value) { s->mem.Ist_Store(offset, value); }
void mem_r_r_write8(State *s, Addr64 offset, ULong  value) { s->mem.Ist_Store(offset, value); }

void mem_r_s_write1(State *s, Addr64 offset, Z3_ast value) { s->mem.Ist_Store<8>(offset, value); }
void mem_r_s_write2(State *s, Addr64 offset, Z3_ast value) { s->mem.Ist_Store<16>(offset, value); }
void mem_r_s_write4(State *s, Addr64 offset, Z3_ast value) { s->mem.Ist_Store<32>(offset, value); }
void mem_r_s_write8(State *s, Addr64 offset, Z3_ast value) { s->mem.Ist_Store<64>(offset, value); }

void mem_s_r_write1(State *s, Z3_ast offset, UChar  value) { s->mem.Ist_Store(offset, value); }
void mem_s_r_write2(State *s, Z3_ast offset, UShort value) { s->mem.Ist_Store(offset, value); }
void mem_s_r_write4(State *s, Z3_ast offset, UInt   value) { s->mem.Ist_Store(offset, value); }
void mem_s_r_write8(State *s, Z3_ast offset, ULong  value) { s->mem.Ist_Store(offset, value); }

void mem_s_s_write1(State *s, Z3_ast offset, Z3_ast value) { s->mem.Ist_Store<8>(offset, value); }
void mem_s_s_write2(State *s, Z3_ast offset, Z3_ast value) { s->mem.Ist_Store<16>(offset, value); }
void mem_s_s_write4(State *s, Z3_ast offset, Z3_ast value) { s->mem.Ist_Store<32>(offset, value); }
void mem_s_s_write8(State *s, Z3_ast offset, Z3_ast value) { s->mem.Ist_Store<64>(offset, value); }



#define mem_read_e_def(nbytes,nbit,T)                                       \
Z3_ast mem_r_read##nbytes##(State *s, T *result, Addr64 addr) {             \
    Vns v = s->mem.Iex_Load<Ity_I##nbit>(addr);                             \
    if (v.real()) {                                                         \
        *result = v;                                                        \
        return NULL;                                                        \
    }                                                                       \
    else {                                                                  \
        Z3_inc_ref(s->m_ctx,v);                                             \
        return v;                                                           \
    }                                                                       \
}

#define mem_read_s_def(nbytes,nbit,T)                                       \
Z3_ast mem_s_read##nbytes##(State *s, T *result, Z3_ast addr) {             \
    Vns v = s->mem.Iex_Load<Ity_I##nbit>(addr);                             \
    if (v.real()) {                                                         \
        *result = v;                                                        \
        return NULL;                                                        \
    }                                                                       \
    else {                                                                  \
        Z3_inc_ref(s->m_ctx,v);                                             \
        return v;                                                           \
    }                                                                       \
}                                                                           \



mem_read_e_def(1,  8, UChar)
mem_read_e_def(2, 16, UShort)
mem_read_e_def(4, 32, UInt)
mem_read_e_def(8, 64, ULong)

mem_read_s_def(1,  8, UChar)
mem_read_s_def(2, 16, UShort)
mem_read_s_def(4, 32, UInt)
mem_read_s_def(8, 64, ULong)








//}
//int eee(State *s) {
//    s->solv.push();
//    
//    if (s->solv.check() == sat) {
//        vex_printf("sat");
//        auto m = s->solv.get_model();
//        std::cout << m << std::endl;
//    }
//    else {
//        vex_printf("unsat??????????\n\n");
//    }
//
//    s->solv.pop();
//    return 300;
//}
State_Tag avoid_ret(State *s) {
    Regs::X86 reg(*s);
    Vns esi = reg.guest_ESI;
    std::cout << esi << std::endl;
    return Death;
}

State_Tag avoid_ret2(State *s) {
    Regs::X86 reg(*s);
    Vns guest_EDX = reg.guest_EDX;
    Vns guest_EBX = reg.guest_EBX;
    std::cout << guest_EDX<< guest_EBX << std::endl;
    return Death;
}



State_Tag success_ret2(State* s) {
    s->solv.push();
    auto ecx = s->regs.Iex_Get<Ity_I32>(12);
    auto edi = s->regs.Iex_Get<Ity_I32>(36);

    for (int i = 0; i < 44; i++) {
        auto al = s->mem.Iex_Load<Ity_I8>(ecx + i);
        auto bl = s->mem.Iex_Load<Ity_I8>(edi + i);
        s->add_assert_eq(s->cast(al), s->cast(bl));
    }
    vex_printf("checking\n\n");
    auto dfdfs = s->solv.check();
    if (dfdfs == sat) {
        vex_printf("sat");
        auto m = s->solv.get_model();
        std::cout << m << std::endl;
    }
    else {
        vex_printf("unsat??????????\n\n%d", dfdfs);
    }
    s->solv.pop();
    return Death;
}



State_Tag success_ret(State* s) {
    context& c = *s;
    s->solv.push();
    auto ecx = s->regs.Iex_Get<Ity_I32>(12);
    auto edi = s->regs.Iex_Get<Ity_I32>(36);
    auto rbp = s->regs.Iex_Get<Ity_I32>(28);
    auto enc_addr = s->mem.Iex_Load<Ity_I32>(rbp + 0xc);

    char right[] = { 0x9c, 0xa9, 0xdb, 0x1e, 0xc8, 0x2a, 0x0f, 0x76, 0x8d, 0x10, 0x1f, 0x75, 0x8c, 0x1d, 0xe0, 0x13, 0x30, 0x2b, 0xf8, 0x89, 0x25, 0x43, 0x04, 0xf5, 0x6d, 0x2b, 0x37, 0xf9, 0xb5, 0xe9, 0x7a, 0xea };

    for (int i = 0; i < 16; i++) {
        auto al = s->mem.Iex_Load<Ity_I8>(enc_addr + i);
        //s->add_assert_eq(s->cast(al), Vns(s->m_ctx, right[i]));
        s->add_assert_eq(al, Vns(s->m_ctx, right[i]));
    }
    vex_printf("checking\n\n");
    auto dfdfs = s->solv.check();
    if (dfdfs == sat) {
        vex_printf("sat");
        auto m = s->solv.get_model();
        std::cout << m << std::endl;

        auto size = s->from.size();
        for (int idx = size - 1; idx >= 0; idx--) {
            Z3_model_inc_ref(s->m_ctx, m);
            Vns d = m.eval(expr(s->m_ctx, s->to[idx]));

            for (unsigned i = 0; i < m.size(); i++) {
                func_decl v = m[i];
                // this problem contains only constants
                assert(v.arity() == 0);
                expr e(c, Z3_mk_const(c, v.name(), v.range()));
                std::cout  << e << " = " << m.get_const_interp(v) << "\n";
                Vns l = m.get_const_interp(v);
                Vns r = e;
                s->add_assert_eq(l, r);
            }


            //s->add_assert_eq(d, s->from[idx]);

             auto dfdfs = s->solv.check();
             std::cout << dfdfs << std::endl;
             m = s->solv.get_model();
             std::cout << m << std::endl;
        }

        auto dfdfs = s->solv.check();
        std::cout << m << std::endl;
    }
    else {
        vex_printf("unsat??????????\n\n%d", dfdfs);
    }
    s->solv.pop();
    return Death;
}



//#include "Engine/Z3_Target_Call/Guest_Helper.hpp"

Vns flag_limit(Vns &flag) {
    char flags_char[] = "@_-{}1:() ^";
    Vns re = Vns(flag, flags_char[0]) == flag;
    for (int i = 1; i < sizeof(flags_char); i++) {
        re = re || (Vns(flag, flags_char[i]) == flag);
    }
    auto ao1 = flag >= 'a' && flag <= 'z';
    auto ao2 = flag >= 'A' && flag <= 'Z';
    auto ao3 = flag >= '0' && flag <= '9';
    return re || ao1 || ao2 || ao3;
}


#include "example.hpp"

int dfdfdfsdx = 0;
State_Tag sub_401070(State* s) {
    auto rbp = s->regs.Iex_Get<Ity_I32>(28);
    auto enc_addr = s->mem.Iex_Load<Ity_I32>(rbp + 0xc);

    for (int i = 0; i < 16; i++) {
        std::stringstream x_name;
        x_name << "idx_" << dfdfdfsdx++;
        z3::context& ctx = *s;
        auto fgf = (Vns)ctx.bv_const(x_name.str().c_str(), 8);
        s->mem.Ist_Store(enc_addr + i, fgf);
    }
    s->delta = 5;
    return Running;
}




int main() {

    State state(INIFILENAME, NULL, True);
    context& c = state; 
    /*
    TB_replace_add(&state, TRRegister, 0x401249, IR_ebx, Ity_I32);
    TB_replace_add(&state, TRRegister, 0x401249, IR_ecx, Ity_I32);
    TB_replace_add(&state, TRRegister, 0x401249, IR_edx, Ity_I32);
    TB_replace_add(&state, TRRegister, 0x401249, IR_eax, Ity_I32);*/


/*
    expr flag = c.bv_const("flag", 8);
    expr x = c.bv_const("x", 8);
    expr y = c.bv_const("y", 8);
    expr z = c.bv_const("z", 8);
    x = flag * flag ^ flag;
    expr crypto = 0x5 + (z * x ^ 45);

    state.from.emplace_back(x);
    state.to.emplace_back(z);

    state.cast(crypto);*/





   //testz3();


    //Regs::AMD64 reg(state);
    Regs::X86 reg(state);
    auto eax = reg.guest_EAX;

     for (int i = 0; i < 16; i++) {
        char buff[20];
        sprintf_s(buff, sizeof(buff), "flag%d", i);
        Vns FLAG = ((context&)state).bv_const(buff, 8);
        state.mem.Ist_Store(eax + i , FLAG);

        auto ao2 = FLAG >=5;
        state.add_assert(ao2, True);

        
        //state.add_assert(FLAG < 128, True);

        //state.add_assert(flag_limit(FLAG), True);
    }

    TB_hook_add(&state, 0x0040140C, success_ret);
    //TB_hook_add(&state, 0x00401165, chk);
    
    
    
    /*
    //TB_hook_add(&state, 0x0CE13EA, inceax);
    


    //helper::UChar_ fgb(state.mem, 0x0400796);
    //char vb = *fgb;

    /*SET1((P->unit->m_bytes + (0x7FFFF7DEC7B9 & 0xfff)), 0xAE);
    
    
    

    //amd64g_dirtyhelper_XSAVE_COMPONENT_0
    
    
    auto f = (Vns)state.m_ctx.bv_const("jjj", 64);

    //amd64g_dirtyhelper_XSAVE_COMPONENT_0

    /*;
    hh.guest_RAX = 89;
    Vns gfg = hh.guest_RAX;

    auto _p8 = p[8];
    auto _p = *p;*/
    

    //helper::operator_set(s.regs, p.m_point, (ULong)87);
    /*hh.guest_RAX = 87;


    = 9;
    auto jdf = *p;
    *jdf = f;

    auto dfj = (helper::UIntP)(&p[8]);
    *dfj = 9;*/

    auto sd = &state;
    //state.regs.Ist_Put(176, 00ull);


    //s.regs.Ist_Put(32, f);
    //TB_hook_add(&s, 0x7FFFF7DEC7B8, (CallBack)comp1);
    /*hook_add(&s, 0x0004081DF, (CallBack)eee);
    hook_add(&s, 0x00406A75, (CallBack)comp1);
    */
    //hook_add(&s, 0x406A75, (CallBack)comp1);
    

    /*auto P = s.mem.getMemPage(0x7ffff7dec7b8);
    SET4((P->unit->m_bytes + (0x7ffff7dec7b8 & 0xfff)), 0x90909090);
    SET1((P->unit->m_bytes + (0x7ffff7dec7b8 & 0xfff + 4)), 0x90);

    SET4((P->unit->m_bytes + (0x7FFFF7DEC7D4 & 0xfff)), 0x90909090);
    SET1((P->unit->m_bytes + (0x7FFFF7DEC7D4 & 0xfff + 4)), 0x90);*/
    pool->enqueue([sd] {
        sd->start(True);
    });
    TESTCODE(
        pool->wait();
    )

    std::cout << *sd << std::endl;

    /*gen_XSAVE_SEQUENCE*/


    //while (true)
    //{
    //    
    //    std::cout << *sd << std::endl;
    //    if (sd->status == Death) break;
    //    if (sd->branch.size()) {
    //        std::vector<State_Tag> ds;
    //        ds.emplace_back(Death);
    //        sd->compress(0x00406A75, (State_Tag)0x00406A75, ds);
    //        sd->pass_hook_once = True;
    //    }
    //    else {
    //        sd->pass_hook_once = True;
    //        sd->status = NewState;
    //    }
    //}
    //
    
    printf("OVER");
    getchar();
    return 0;
}




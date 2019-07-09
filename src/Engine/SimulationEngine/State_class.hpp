/*++
Copyright (c) 2019 Microsoft Corporation
Module Name:
    Reister.class:
Abstract:
    API list;
Author:
    WXC 2019-05-31.
Revision History:
--*/
#include "State_class_CD.hpp"
#include "../Z3_Target_Call/Z3_Target_Call.hpp"
#include "libvex_guest_x86.h"
#include "libvex_guest_amd64.h"
#include "libvex_guest_arm.h"
#include "libvex_guest_arm64.h"
#include "libvex_guest_mips32.h"
#include "libvex_guest_mips64.h"
#include "libvex_guest_ppc32.h"
#include "libvex_guest_ppc64.h"
#include "libvex_guest_s390x.h"


Vns ir_temp[MAX_THREADS][400];
ThreadPool *pool = NULL;
std::hash_map<ADDR, Hook_struct> CallBackDict;
std::hash_map<ADDR, std::vector<Hook_Replace>> ReplaceDict;
tinyxml2::XMLDocument doc;
VexArch		guest;
State*		_states[MAX_THREADS];
std::mutex global_state_mutex;
Bool TriggerBug_is_init = False;
//call back
State_Tag(*Ijk_call_back)(State *, IRJumpKind);
Super		pState_fork;


unsigned char fastalignD1[257];
unsigned char fastalign[257];
ULong fastMask[65];
ULong fastMaskI1[65];
ULong fastMaskB[9];
ULong fastMaskBI1[9];
ULong fastMaskReverse[65];
ULong fastMaskReverseI1[65];
__m256i m32_fast[33];
__m256i m32_mask_reverse[33];


Addr64 traceIrAddrress;
bool traceJmp;
bool traceState;
bool PassSigSEGV;

State::State(char *filename, Addr64 gse, Bool _need_record, PyObject *_base = NULL) :
	m_ctx(), 
	mem(*this, &m_ctx,need_record),
	regs(m_ctx, need_record), 
	solv(m_ctx),
    need_record(_need_record),
	status(NewState),
	VexGuestARCHState(NULL),
	delta(0),
	base(_base),
    unit_lock(true),
    replace_const(0)
{
    pap.state = (void*)(this);
    pap.n_page_mem = _n_page_mem;
	if (!TriggerBug_is_init) 
		Func_Map_Init();
	doc.LoadFile(filename);
	auto doc_TriggerBug = doc.FirstChildElement("TriggerBug");
	sscanf(doc_TriggerBug->FirstChildElement("VexArch")->GetText(), "%x", &guest);
	int Thread_num;
	doc_TriggerBug->FirstChildElement("MaxThreadsNum")->QueryIntText((Int*)(&Thread_num));
	assert(Thread_num <= MAX_THREADS);
	if (pool) 
		delete pool;
	pool = new ThreadPool(Thread_num);

	asserts.resize(5);
	branch.reserve(10);
	init_threads_id(); 
	tempmeminit(); 
	IR_init();
	if (!TriggerBug_is_init) {
		vassert(!vex_initdone);
		QueryPerformanceFrequency(&freq_global);
		QueryPerformanceCounter(&beginPerformanceCount_global);
		register_tid(GetCurrentThreadId());
		LibVEX_Init(&failure_exit, &vex_log_bytes, 0/*debuglevel*/, &vc);
		unregister_tid(GetCurrentThreadId());

		for (int i = 0; i < 257; i++) fastalignD1[i] = (((((i)-1)&-8) + 8) >> 3) - 1;
		for (int i = 0; i < 257; i++) fastalign[i] = (((((i)-1)&-8) + 8) >> 3);
		for (int i = 0; i <= 64; i++) fastMask[i] = (1ull << i) - 1; fastMask[64] = -1ULL;
		for (int i = 0; i <= 64; i++) fastMaskI1[i] = (1ull << (i + 1)) - 1; fastMaskI1[63] = -1ULL; fastMaskI1[64] = -1ULL;
		for (int i = 0; i <= 7; i++) fastMaskB[i] = (1ull << (i << 3)) - 1; fastMaskB[8] = -1ULL;
		for (int i = 0; i <= 7; i++) fastMaskBI1[i] = (1ull << ((i + 1) << 3)) - 1; fastMaskBI1[7] = -1ULL;
		for (int i = 0; i <= 64; i++) fastMaskReverse[i] = ~fastMask[i];
		for (int i = 0; i <= 64; i++) fastMaskReverseI1[i] = ~fastMaskI1[i];

		__m256i m32 = _mm256_setr_epi64x(0x0807060504030201, 0x100f0e0d0c0b0a09, 0x1817161514131211, 0x201f1e1d1c1b1a19);
		for (int i = 0; i <= 32; i++) {
			m32_fast[i] = m32;
			for (int j = i; j <= 32; j++) {
				m32_fast[i].m256i_i8[j] = 0;
			}
			m32_mask_reverse[i] = _mm256_setzero_si256();
			memset(&m32_mask_reverse[i].m256i_i8[i], -1ul, 32 - i);
		}
	}
	read_mem_dump(doc_TriggerBug->FirstChildElement("MemoryDumpPath")->GetText());
	if (gse)
		guest_start_ep = gse;
	else {
		if (doc_TriggerBug->FirstChildElement("GuestStartAddress")) {
			sscanf(doc_TriggerBug->FirstChildElement("GuestStartAddress")->GetText(), "%llx", &guest_start_ep);
            if (!guest_start_ep) {
                goto mem_ip;
            }
		}
		else {
mem_ip:
			Int offset;
			doc_TriggerBug->FirstChildElement("RegsIpOffset")->QueryIntText(&offset);
			guest_start_ep = regs.Iex_Get(offset,Ity_I64);
		}
	}
	guest_start = guest_start_ep;

	sscanf(doc_TriggerBug->FirstChildElement("DEBUG")->FirstChildElement("TraceIrAddrress")->GetText(), "%llx", &traceIrAddrress);
	doc_TriggerBug->FirstChildElement("DEBUG")->FirstChildElement("TraceState")->QueryBoolText(&traceState);
	doc_TriggerBug->FirstChildElement("DEBUG")->FirstChildElement("TraceJmp")->QueryBoolText(&traceJmp);
	doc_TriggerBug->FirstChildElement("PassSigSEGV")->QueryBoolText((bool*)(&PassSigSEGV));
	TriggerBug_is_init = True;
};


State::State(State *father_state, Addr64 gse, PyObject *_base = NULL) :
	m_ctx(),
	mem(*this, father_state->mem, &m_ctx, need_record),
	guest_start_ep(gse),
	guest_start(guest_start_ep), 
	solv(m_ctx, father_state->solv,  z3::solver::translate{}),
	regs(father_state->regs, m_ctx, need_record),
	need_record(father_state->need_record),
	status(NewState),
	VexGuestARCHState(NULL),
	delta(0),
	base(_base),
    unit_lock(true),
    replace_const(father_state->replace_const)
{
    pap.state = (void*)(this);
    pap.n_page_mem = _n_page_mem;
	if (!base) {
		if (father_state->base) {
			base = pState_fork(father_state->base);
			assert(base);
		}
	}
	IR_init();
};

State::~State() { 
	if (VexGuestARCHState) delete VexGuestARCHState;
    if(branch.size())
	    for (auto s : branch){
            delete s;
        }
}
	
	
inline State::operator context&() { return m_ctx; }

inline State::operator Z3_context() { return m_ctx; }

inline State::operator std::string(){
    std::string str;
    char hex[30];
    std::string strContent;
    

    str.append("\n#entry:");
    snprintf(hex, sizeof(hex),  "%llx", guest_start_ep);
    strContent.assign(hex);
    str.append(strContent);
    str.append(" end:");
    snprintf(hex, sizeof(hex),  "%llx ", guest_start);
    strContent.assign(hex);
    str.append(strContent);

    switch (status) {
	case NewState:str.append("NewState "); break;
    case Running:str.append("Running "); break;
    case Fork:str.append("Fork "); break;
    case Death:str.append("Death "); break;
	default:
		snprintf(hex, sizeof(hex),  "%d ", status);
		strContent.assign(hex);
		str.append(strContent); break;
    }

    str.append(" #child{\n");
    if (branch.empty()) {
        switch (status) {
		case NewState:str.append("NewState "); break;
        case Running:str.append("Running "); break;
        case Fork:str.append("Fork "); break;
        case Death:str.append("Death "); break;
		default:
			snprintf(hex, sizeof(hex),  "%d ", status);
			strContent.assign(hex);
			str.append(strContent); break;
        }
        snprintf(hex, sizeof(hex),  "%llx    \n}\n ", guest_start_ep);
        strContent.assign(hex);
        str.append(strContent);
        return str;
    }
    else {
        for (auto state : branch) {
            std::string child = *state;
            str.append(replace(child.c_str(), "\n", "\n   >"));
        }
    }
    str.append("\n}\n");
    
    
    return str;
}

inline Vns State::getassert(z3::context &ctx) {
	if (asserts.empty()) {
		vpanic("impossible assertions num is zero");
	}
	auto it = asserts.begin();
	auto end = asserts.end();
	auto result = *it;
	it ++;
	while (it != end) {
		result = result && *it;
		it ++;
	}
	return result.translate(ctx).simplify();
}
inline Addr64 State::get_guest_start()
{
	return guest_start;
}
inline Addr64 State::get_guest_start_ep()
{
	return guest_start_ep;
}
inline std::ostream & operator<<(std::ostream & out, State & n) {
    return out<< (std::string)n;
}

inline bool State::avoid_check(ADDR oep) {
    for (auto av : avoid_branch_oep) {
        if (oep == av) {
            return 1;
        }
    }
    return 0;
}

inline Vns State::get_int_const(UShort nbit) {
    bool xchgbv = false;
    while (!xchgbv) {
        __asm__ __volatile("xchgb %b0,%1":"=r"(xchgbv) : "m"(unit_lock), "0"(xchgbv) : "memory");
    };
    auto res = replace_const++;
    unit_lock = true;
    char buff[20];
    sprintf_s(buff, sizeof(buff), "part_%lx_%d",guest_start, res);
    return  Vns(m_ctx.bv_const(buff, nbit), nbit);
}

inline Vns State::cast(Vns data) {
    auto size = from.size();
    for (int idx = size - 1; idx >= 0; idx--) {
        Z3_ast t[] = { to[idx] };
        Z3_ast f[] = { from[idx] };
        data = Vns(m_ctx, Z3_substitute(m_ctx, data, 1, t, f));
    }
    return data;
}

inline IRSB* State::BB2IR() {
	mem.set_double_page(guest_start, pap);
	pap.start_swap       = 0;
	vta.guest_bytes      = (UChar *)(pap.t_page_addr);
	vta.guest_bytes_addr = (Addr64)((ADDR)guest_start);
	IRSB *irsb;
	if(0){
		printf("GUESTADDR %16llx   RUND:%ld CODES   ", guest_start, runed);
		TESTCODE(
			irsb = LibVEX_FrontEnd(&vta, &res, &pxControl);
		);
	}
	else {
		return LibVEX_FrontEnd(&vta, &res, &pxControl);
	}
	return irsb;
}




inline void State::add_assert(Vns & assert,Bool ToF)
{
	assert = assert.simplify();
	if(assert.is_bool()){
		if (ToF) {
			Z3_solver_assert(m_ctx, solv, assert);
			asserts.push_back(assert);
		}
		else {
			auto not = !  assert;
			Z3_solver_assert(m_ctx, solv, not);
			asserts.push_back(not);
		}
	}
	else {
        auto ass = (assert == (Bool)ToF);
        Z3_solver_assert(m_ctx, solv, ass);
        asserts.push_back(ass);
	}
}

inline void State::add_assert_eq(Vns & eqA, Vns & eqB)
{
	Vns ass = (eqA == eqB).simplify();
	Z3_solver_assert(m_ctx, solv, ass);
	asserts.push_back(ass);
}

inline void State::write_regs(int offset, void* addr, int length) { regs.write_regs(offset, addr, length); }
inline void State::read_regs(int offset, void* addr, int length) { regs.read_regs(offset, addr, length); }

inline Vns State::CCall(IRCallee *cee, IRExpr **exp_args, IRType ty)
{
	Int regparms = cee->regparms;
	UInt mcx_mask = cee->mcx_mask;
	Bool z3_mode = False;

	Vns arg0 = tIRExpr(exp_args[0]);
	if (arg0.symbolic()) z3_mode = True;
	if (!exp_args[1]) return (z3_mode) ? ((Z3_Function1)(funcDict(cee->addr)))(arg0) : Vns(m_ctx, ((Function_1)(cee->addr))(arg0));
	Vns arg1 = tIRExpr(exp_args[1]);
	if (arg1.symbolic()) z3_mode = True;
	if (!exp_args[2]) return (z3_mode) ? ((Z3_Function2)(funcDict(cee->addr)))(arg0, arg1) : Vns(m_ctx, ((Function_2)(cee->addr))(arg0, arg1));
	Vns arg2 = tIRExpr(exp_args[2]);
	if (arg2.symbolic()) z3_mode = True;
	if (!exp_args[3]) return (z3_mode) ? ((Z3_Function3)(funcDict(cee->addr)))(arg0, arg1, arg2) : Vns(m_ctx, ((Function_3)(cee->addr))(arg0, arg1, arg2));
	Vns arg3 = tIRExpr(exp_args[3]);
	if (arg3.symbolic()) z3_mode = True;
	if (!exp_args[4]) return (z3_mode) ? ((Z3_Function4)(funcDict(cee->addr)))(arg0, arg1, arg2, arg3) : Vns(m_ctx, ((Function_4)(cee->addr))(arg0, arg1, arg2, arg3));
	Vns arg4 = tIRExpr(exp_args[4]);
	if (arg4.symbolic()) z3_mode = True;
	if (!exp_args[5]) return (z3_mode) ? ((Z3_Function5)(funcDict(cee->addr)))(arg0, arg1, arg2, arg3, arg4) : Vns(m_ctx, ((Function_5)(cee->addr))(arg0, arg1, arg2, arg3, arg4));
	Vns arg5 = tIRExpr(exp_args[5]);
	if (arg5.symbolic()) z3_mode = True;
	if (!exp_args[6]) return (z3_mode) ? ((Z3_Function6)(funcDict(cee->addr)))(arg0, arg1, arg2, arg3, arg4, arg5) : Vns(m_ctx, ((Function_6)(cee->addr))(arg0, arg1, arg2, arg3, arg4, arg5));
}

Bool chase_into_ok(void *value,Addr addr) {
	std::cout << value << addr << std::endl;
	return True;
}
inline void State::thread_register()
{
	{
		std::unique_lock<std::mutex> lock(global_state_mutex);
		register_tid(GetCurrentThreadId());
	}
	if (traceState)
		std::cout << "\n+++++++++++++++ Thread ID: " << GetCurrentThreadId() << "  address: " << std::hex << guest_start << "  Started +++++++++++++++\n" << std::endl;

	auto i = temp_index();
	_states[i] = this;
	for (int j = 0; j < 400; j++) {
		ir_temp[i][j].m_kind = REAL;
	}
}
inline void State::thread_unregister()
{
	if (traceState)
		std::cout << "\n+++++++++++++++ Thread ID: " << GetCurrentThreadId() << "  address: " << std::hex << guest_start << "  OVER +++++++++++++++\n" << std::endl;
	
	auto i = temp_index();
	for (int j = 0; j < 400; j++) {
		ir_temp[i][j].~Vns();
	}
	{
		std::unique_lock<std::mutex> lock(global_state_mutex);
		unregister_tid(GetCurrentThreadId());
	}
}
void State::IR_init() {
	LibVEX_default_VexControl(&vc);
	LibVEX_default_VexArchInfo(&vai_host);
	LibVEX_default_VexArchInfo(&vai_guest);
	LibVEX_default_VexAbiInfo(&vbi);

    vc.iropt_level = 1;

	auto doc_VexControl = doc.FirstChildElement("TriggerBug")->FirstChildElement("VexControl");

	vbi.guest_amd64_assume_gs_is_const = True;
	vbi.guest_amd64_assume_fs_is_const = True;
	vc.iropt_verbosity = 0;
	doc_VexControl->FirstChildElement("iropt_level")->QueryIntText((Int*)(&vc.iropt_level));
	vc.iropt_unroll_thresh = 0;
	vc.guest_max_insns = 100;    // max instruction
	pap.guest_max_insns = 100;
	vc.guest_chase_thresh = 0;   //不许追赶

	sscanf(doc_VexControl->FirstChildElement("iropt_register_updates_default")->GetText(), "%x", &vc.iropt_register_updates_default);
	sscanf(doc_VexControl->FirstChildElement("pxControl")->GetText(), "%x", &pxControl);

	vex_hwcaps_vai(HOSTARCH, &vai_host);
	vex_hwcaps_vai(guest, &vai_guest);
	vai_host.endness = VexEndnessLE;//VexEndnessBE
	vai_guest.endness = VexEndnessLE;//VexEndnessBE

	vex_prepare_vbi(guest, &vbi);
	vta.callback_opaque = NULL;
	vta.preamble_function = NULL;
	vta.instrument1 = NULL;
	vta.instrument2 = NULL;
	vta.finaltidy = NULL;
	vta.preamble_function = NULL;

	vta.disp_cp_chain_me_to_slowEP = (void *)dispatch;
	vta.disp_cp_chain_me_to_fastEP = (void *)dispatch;
	vta.disp_cp_xindir = (void *)dispatch;
	vta.disp_cp_xassisted = (void *)dispatch;

	vta.arch_guest = guest;
	vta.archinfo_guest = vai_guest;
	vta.arch_host = HOSTARCH;
	vta.archinfo_host = vai_host;
	vta.abiinfo_both = vbi;
	vta.guest_extents = &vge;
	vta.chase_into_ok = chase_into_ok;
	vta.needs_self_check = needs_self_check;


    vta.traceflags = NULL;
    vta.traceflags = doc_VexControl->FirstChildElement("traceflags")->IntText();
    vta.pap = &pap;
}


void State::read_mem_dump(const char  *filename)
{
	struct memdump {
		unsigned long long nameoffset;
		unsigned long long address;
		unsigned long long length;
		unsigned long long dataoffset;
	}buf;
	FILE *infile;
	infile = fopen(filename, "rb");
	if (!infile) {
		printf("%s, %s", filename, "not exit/n");
		getchar();
		exit(1);
	}
	unsigned long long length, fp, err, name_start_offset, name_end_offset;
	fread(&length, 8, 1, infile);
	fseek(infile, 24, SEEK_SET);
	name_start_offset = length;
	fread(&name_end_offset, 8, 1, infile);
	length /= 32;
	char *name_buff = (char *)malloc(name_end_offset-name_start_offset);
	fseek(infile, name_start_offset, SEEK_SET);
	fread(name_buff, 1, name_end_offset - name_start_offset, infile);
	fseek(infile, 0, SEEK_SET);
	char *name;
	for (unsigned int segnum = 0; segnum < length; segnum++) {
		fread(&buf, 32, 1, infile);
		unsigned char *data = (unsigned char *)malloc(buf.length);
		fp = ftell(infile);
		fseek(infile, buf.dataoffset, SEEK_SET);
		fread(data, buf.length, 1, infile);
		name = &name_buff[buf.nameoffset - name_start_offset];
		if (GET8(name)== 0x7265747369676572) {
			printf("name:%18s address:%016llx data offset:%010llx length:%010llx\n", name, buf.address, buf.dataoffset, buf.length);
			memcpy((regs.m_bytes + buf.address), data, buf.length);
		}else {
			printf("name:%18s address:%016llx data offset:%010llx length:%010llx\n", name, buf.address, buf.dataoffset, buf.length);
			if (err = mem.map(buf.address, buf.length))
				printf("warning %s had maped before length: %llx\n", name, err);
			mem.write_bytes(buf.address, buf.length, data);
		}
		fseek(infile, fp, SEEK_SET);
		free(data);
	}
	free(name_buff);
	fclose(infile);
}

inline Vns State::ILGop(IRLoadG *lg) {
	switch (lg->cvt) {
	case ILGop_IdentV128:{ return mem.Iex_Load(tIRExpr(lg->addr), Ity_V128);			}
	case ILGop_Ident64:  { return mem.Iex_Load(tIRExpr(lg->addr), Ity_I64 );			}
	case ILGop_Ident32:  { return mem.Iex_Load(tIRExpr(lg->addr), Ity_I32 );			}
	case ILGop_16Uto32:  { return mem.Iex_Load(tIRExpr(lg->addr), Ity_I16 ).zext(16);	}
	case ILGop_16Sto32:  { return mem.Iex_Load(tIRExpr(lg->addr), Ity_I16 ).sext(16);	}
	case ILGop_8Uto32:   { return mem.Iex_Load(tIRExpr(lg->addr), Ity_I8  ).sext(8);	}
	case ILGop_8Sto32:   { return mem.Iex_Load(tIRExpr(lg->addr), Ity_I8  ).sext(8);	}
	case ILGop_INVALID:
	default: vpanic("ppIRLoadGOp");
	}
}


inline Vns State::tIRExpr(IRExpr* e)
{
	switch (e->tag) {
	case Iex_Get: { return regs.Iex_Get(e->Iex.Get.offset, e->Iex.Get.ty); }
	case Iex_RdTmp: { return ir_temp[t_index][e->Iex.RdTmp.tmp]; }
	case Iex_Unop: { return T_Unop(e->Iex.Unop.op, e->Iex.Unop.arg); }
	case Iex_Binop: { return T_Binop(e->Iex.Binop.op, e->Iex.Binop.arg1, e->Iex.Binop.arg2); }
	case Iex_Triop: { return T_Triop(e->Iex.Triop.details->op, e->Iex.Triop.details->arg1, e->Iex.Triop.details->arg2, e->Iex.Triop.details->arg3); }
	case Iex_Qop: { return T_Qop(e->Iex.Qop.details->op, e->Iex.Qop.details->arg1, e->Iex.Qop.details->arg2, e->Iex.Qop.details->arg3, e->Iex.Qop.details->arg4); }
	case Iex_Load: { return mem.Iex_Load(tIRExpr(e->Iex.Load.addr), e->Iex.Get.ty); }
	case Iex_Const: { return Vns(m_ctx, e->Iex.Const.con); }
	case Iex_ITE: {
		Vns cond = tIRExpr(e->Iex.ITE.cond);
		return (cond.real()) ?
			((UChar)cond & 0b1) ? tIRExpr(e->Iex.ITE.iftrue) : tIRExpr(e->Iex.ITE.iffalse)
			:
			Vns(m_ctx, Z3_mk_ite(m_ctx, cond.toZ3Bool(), tIRExpr(e->Iex.ITE.iftrue), tIRExpr(e->Iex.ITE.iffalse)));
	}
	case Iex_CCall: { return CCall(e->Iex.CCall.cee, e->Iex.CCall.args, e->Iex.CCall.retty); }
	case Iex_GetI: {
		auto ix = tIRExpr(e->Iex.GetI.ix);
		assert(ix.real());
		return regs.Iex_Get(e->Iex.GetI.descr->base + (((UInt)(e->Iex.GetI.bias + (int)(ix))) % e->Iex.GetI.descr->nElems)*ty2length(e->Iex.GetI.descr->elemTy), e->Iex.GetI.descr->elemTy);
	};
	case Iex_GSPTR: {
		if (!VexGuestARCHState) {
			switch (guest) {
			case VexArchX86: VexGuestARCHState = new VexGuestX86State; break;
			case VexArchAMD64: VexGuestARCHState = new Regs::AMD64(*this); break;
			case VexArchARM: VexGuestARCHState = new VexGuestARMState; break;
			case VexArchARM64: VexGuestARCHState = new VexGuestARM64State; break;
			case VexArchMIPS32: VexGuestARCHState = new VexGuestMIPS32State; break;
			case VexArchMIPS64: VexGuestARCHState = new VexGuestMIPS64State; break;
			case VexArchPPC32: VexGuestARCHState = new VexGuestPPC32State; break;
			case VexArchPPC64: VexGuestARCHState = new VexGuestPPC64State; break;
			case VexArchS390X: VexGuestARCHState = new VexGuestS390XState; break;
			default:vpanic("not support");
			}
		}
		return Vns(m_ctx, VexGuestARCHState);
	};
	case Iex_VECRET:
	case Iex_Binder:
	default:
		vex_printf("tIRExpr error:  %d", e->tag);
		vpanic("not support");
	}
}

void State::start(Bool first_bkp_pass) {
	if (status != NewState) {
		vassert(0);
	}
	Bool NEED_CHECK = False;
    auto doc_TriggerBug = doc.FirstChildElement("TriggerBug");
    doc_TriggerBug->FirstChildElement("DEBUG")->FirstChildElement("NEED_CHECK")->QueryBoolText((bool*)&NEED_CHECK);
	Bool is_first_bkp_pass = False;
	Addr64 hook_bkp = NULL;
	status = Running;
	thread_register();
	t_index=temp_index();
	
	try {
		try {
			if(first_bkp_pass)
				if ((UChar)mem.Iex_Load<Ity_I8>(guest_start) == 0xCC) {
					is_first_bkp_pass = True;
					goto bkp_pass;
				}
			for (;;) {
For_Begin:
				IRSB* irsb = BB2IR();
                //ppIRSB(irsb);
				if (traceJmp)
					vex_printf("Jmp: %llx \n",guest_start); 

For_Begin_NO_Trans:
				for (UShort i = 0; i < irsb->stmts_used; i++) {
					IRStmt *s = irsb->stmts[i];
					if (guest_start == traceIrAddrress) { 
						NEED_CHECK = True; 
					}
					if(NEED_CHECK) ppIRStmt(s);
					switch (s->tag) {
					case Ist_Put: {regs.Ist_Put(s->Ist.Put.offset, tIRExpr(s->Ist.Put.data)); break; }
					case Ist_Store: {mem.Ist_Store(tIRExpr(s->Ist.Store.addr), tIRExpr(s->Ist.Store.data)); break; }
					case Ist_WrTmp: {ir_temp[t_index][s->Ist.WrTmp.tmp] = tIRExpr(s->Ist.WrTmp.data);
						if (NEED_CHECK)std::cout << ir_temp[t_index][s->Ist.WrTmp.tmp] << std::endl;
						break;
					}
                    case Ist_CAS /*比较和交换*/: {//xchg    rax, [r10]
                        bool xchgbv = false;
                        while (!xchgbv) {
                            __asm__ __volatile("xchgb %b0,%1":"=r"(xchgbv) : "m"(unit_lock), "0"(xchgbv) : "memory");
                        }
						IRCAS cas = *(s->Ist.CAS.details);
						Vns addr = tIRExpr(cas.addr);//r10.value
						Vns expdLo = tIRExpr(cas.expdLo);
						Vns dataLo = tIRExpr(cas.dataLo);
						if ((cas.oldHi != IRTemp_INVALID) && (cas.expdHi)) {//double
							Vns expdHi = tIRExpr(cas.expdHi);
							Vns dataHi = tIRExpr(cas.dataHi);
							ir_temp[t_index][cas.oldHi] = mem.Iex_Load(addr, length2ty(expdLo.bitn));
							ir_temp[t_index][cas.oldLo] = mem.Iex_Load(addr, length2ty(expdLo.bitn));
							mem.Ist_Store(addr, dataLo);
							mem.Ist_Store(addr + (dataLo.bitn >> 3), dataHi);
						}
						else {//single
							ir_temp[t_index][cas.oldLo] = mem.Iex_Load(addr, length2ty(expdLo.bitn));
							mem.Ist_Store(addr, dataLo);
						}
                        unit_lock = true;
						break;
					}
					case Ist_Exit: {
						Vns guard = tIRExpr(s->Ist.Exit.guard);
						if (guard.real()) {
							if ((UChar)guard) {
Exit_guard_true:
								if (s->Ist.Exit.jk != Ijk_Boring
									&& s->Ist.Exit.jk != Ijk_Call
									&& s->Ist.Exit.jk != Ijk_Ret
									)
								{
									if (s->Ist.Exit.jk == Ijk_SigSEGV)
										if (PassSigSEGV) {
											vex_printf("TrggerBug: passed the Ijk_SigSEGV at: %llx\n", guest_start);
											continue;
										}
                                    if (!Ijk_call_back) { status = Death; goto EXIT; }
									status = Ijk_call_back(this, s->Ist.Exit.jk);
									if (status != Running) {
										goto EXIT;
									}
									if (delta) {
										guest_start = guest_start + delta;
										delta = 0;
										goto For_Begin;
									}
								}
								else {
									guest_start = s->Ist.Exit.dst->Ico.U64;
									hook_bkp = NULL;
									goto For_Begin;
								}
							}
							break;
						}
						else {
                            int rgurd[2];
                            std::vector<Z3_ast> guard_result;
                            int num_guard = eval_all(guard_result, solv, guard);
                            if (num_guard == 1) {
                                Z3_get_numeral_int(m_ctx, guard_result[0], &rgurd[0]);
                                Z3_dec_ref(m_ctx, guard_result[0]);
                                if (rgurd[0]) {
                                    add_assert(guard, True);
                                    goto Exit_guard_true;
                                }
                                else {
                                    add_assert(guard, False);
                                }
                            }
                            else if (num_guard == 2) {
                                Z3_dec_ref(m_ctx, guard_result[0]);
                                Z3_dec_ref(m_ctx, guard_result[1]);
                                struct _bs {
                                    ADDR addr;
                                    Z3_ast _s_addr;
                                    bool _not;
                                };
                                std::vector<_bs> bs_v;
                                bs_v.emplace_back(_bs{ s->Ist.Exit.dst->Ico.U64 ,NULL, True });
                                Vns _next = tIRExpr(irsb->next);
                                if (_next.real()) {
                                    bs_v.emplace_back(_bs{ _next ,_next, False });
                                }
                                else {
                                    std::vector<Z3_ast> next_result;
                                    eval_all(next_result, solv, _next);
                                    for (auto && re : next_result) {
                                        uint64_t r_next;
                                        Z3_get_numeral_uint64(m_ctx, re, &r_next);
                                        bs_v.emplace_back(_bs{ r_next ,_next, False });
                                    }
                                }
                                if (traceState) std::cout << "Fork at: " << std::hex << guest_start << "  {" << std::endl;
                                for (auto && _bs : bs_v) {
                                    State *state = new State(this, _bs.addr);
                                    branch.emplace_back(state);
                                    state->add_assert(guard.translate(*state), _bs._not);
                                    if (_bs._s_addr) {
                                        auto _next_a = Vns(state->m_ctx, Z3_translate(m_ctx, _bs._s_addr, *state));
                                        auto _next_b = Vns(state->m_ctx, Z3_mk_unsigned_int64(state->m_ctx, _bs.addr, Z3_get_sort(state->m_ctx, _next_a)));
                                        state->add_assert_eq(_next_a, _next_b);
                                    }
                                    if (traceState) std::cout << "    +++++++++++++++ push : " << std::hex << state->guest_start << " +++++++++++++++" << std::endl;
                                }
                                if (traceState) std::cout << " } Fork end" << std::endl;
                                status = Fork; goto EXIT;
                            }
                            else {
                                status = Death; goto EXIT;
                            }
						}
					}
					case Ist_NoOp: break;
					case Ist_IMark: guest_start = (ADDR)s->Ist.IMark.addr; break;
					case Ist_AbiHint:break; //====== AbiHint(t4, 128, 0x400936:I64) ====== call 0xxxxxxx
					case Ist_PutI: {
						//PutI(840:8xI8)[t10,-1]
						//840:arr->base
						//8x :arr->nElems
						//I8 :arr->elemTy
						//t10:ix
						//-1 :e->Iex.GetI.bias
						auto ix = tIRExpr(s->Ist.PutI.details->ix);
						if (ix.real()) {
							regs.Ist_Put(
								s->Ist.PutI.details->descr->base + (((UInt)((s->Ist.PutI.details->bias + (int)(ix)))) % s->Ist.PutI.details->descr->nElems)*ty2length(s->Ist.PutI.details->descr->elemTy),
								tIRExpr(s->Ist.PutI.details->data)
							);
						}
						else {
							vassert(0);
						}
						break;
					}
					case Ist_Dirty: {
						IRDirty *dirty = s->Ist.Dirty.details;
						auto k = CCall(dirty->cee, dirty->args, Ity_I8);
						if (dirty->tmp != -1) {
							ir_temp[t_index][dirty->tmp] = k;
						}
						break;
					}

					case Ist_LoadG: {
						IRLoadG *lg = s->Ist.LoadG.details;
						auto guard = tIRExpr(lg->guard);
						if (guard.real()) {
							ir_temp[t_index][lg->dst] = (((UChar)guard)) ? ILGop(lg) : tIRExpr(lg->alt);
						}
						else {
							ir_temp[t_index][lg->dst] = ite(guard == 1, ILGop(lg), tIRExpr(lg->alt));
						}
						if (NEED_CHECK)std::cout << ir_temp[t_index][lg->dst] << std::endl;
						break;
					}
					case Ist_StoreG: {
						IRStoreG *sg = s->Ist.StoreG.details;
						auto guard = tIRExpr(sg->guard);
						if (guard.real()) {
							if ((UChar)guard) 
								mem.Ist_Store(tIRExpr(sg->addr), tIRExpr(sg->data));
						}
						else {
							auto addr = tIRExpr(sg->addr);
							auto data = tIRExpr(sg->data);
							mem.Ist_Store(addr, ite(guard == 1, mem.Iex_Load(addr, length2ty(data.bitn)), data));
						}
						break;
					}
					case Ist_MBE   /*内存总线事件，fence/请求/释放总线锁*/:break;
					case Ist_LLSC:
					default:
						vex_printf("what ppIRStmt %d\n", s->tag);
						vpanic("what ppIRStmt");
					}
					if (NEED_CHECK)
						if (s->tag != Ist_WrTmp) { vex_printf("\n"); }
				}

				switch (irsb->jumpkind) {
				case Ijk_Boring:		break;
				case Ijk_Call:			break;
				case Ijk_Ret:           break;
				case Ijk_SigTRAP:		{
bkp_pass:
                    auto replace_where = ReplaceDict.lower_bound((ADDR)guest_start);
                    if (replace_where != ReplaceDict.end()) {
                        for(auto rep: replace_where->second){
                            if (rep.kind == TRRegister) {
                                from.emplace_back(regs.Iex_Get(rep.r_offset, rep.ty));
                                Vns rep_const = get_int_const(ty2bit(rep.ty));
                                to.emplace_back(rep_const);
                                regs.Ist_Put(rep.r_offset, rep_const);
                            }
                            else {
                                from.emplace_back(mem.Iex_Load(rep.r_offset, rep.ty));
                                Vns rep_const = get_int_const(ty2bit(rep.ty));
                                to.emplace_back(rep_const);
                                mem.Ist_Store(rep.r_offset, rep_const);
                            }
                        }
                    }
					auto _where = CallBackDict.lower_bound((ADDR)guest_start);
					if (_where != CallBackDict.end()) {
						if (hook_bkp) {
							guest_start = hook_bkp;
							hook_bkp = NULL;
							goto For_Begin;
						}
						else {
							if (!is_first_bkp_pass) {
                                if (_where->second.cb) {
                                    status = (_where->second.cb)(this);//State::delta maybe changed by callback
                                }
								if (status != Running) {
									goto EXIT;
								}
							}
							else {
								is_first_bkp_pass = False;
							}
							if (delta) {
								guest_start = guest_start + delta;
								delta = 0;
								goto For_Begin;
							}
							else {
                                __m256i m32 = mem.Iex_Load<Ity_V256>(guest_start);
                                m32.m256i_i8[0] = _where->second.original;
								pap.start_swap = 2;
								vta.guest_bytes = (UChar *)(&m32);
								vta.guest_bytes_addr = (Addr64)((ADDR)guest_start);
								auto max_insns = pap.guest_max_insns;
								pap.guest_max_insns = 1;
								irsb = LibVEX_FrontEnd(&vta, &res, &pxControl);
								ppIRSB(irsb);
								pap.guest_max_insns = max_insns;
								hook_bkp = (ADDR)guest_start + irsb->stmts[0]->Ist.IMark.len;
								irsb->jumpkind = Ijk_SigTRAP;
								goto For_Begin_NO_Trans;
							}
						}
					}
				}
				case Ijk_Sys_syscall: 
				case Ijk_NoDecode:	
				case Ijk_ClientReq:    
				case Ijk_Yield:        
				case Ijk_EmWarn:       
				case Ijk_EmFail:       
				case Ijk_MapFail:      
				case Ijk_InvalICache:  
				case Ijk_FlushDCache:  
				case Ijk_NoRedir:      
				case Ijk_SigILL:       
				case Ijk_SigSEGV:      
				case Ijk_SigBUS:       
				case Ijk_SigFPE:       
				case Ijk_SigFPE_IntDiv:
				case Ijk_SigFPE_IntOvf:
				case Ijk_Sys_int32:    
				case Ijk_Sys_int128:   
				case Ijk_Sys_int129:   
				case Ijk_Sys_int130:   
				case Ijk_Sys_int145:   
				case Ijk_Sys_int210:   
				case Ijk_Sys_sysenter:
				default:
                    if (!Ijk_call_back) { status = Death; goto EXIT; }
					status = Ijk_call_back(this, irsb->jumpkind);
					if (status != Running) {
						goto EXIT;
					}
					if (delta) {
						guest_start = guest_start + delta;
						delta = 0;
						goto For_Begin;
					}
				}
Isb_next:
				Vns next = tIRExpr(irsb->next);
				if (next.real()) {
					guest_start = next;
				}
				else {
					std::vector<Z3_ast> result;
					switch (eval_all(result, solv, next)) {
					case 0: next.~Vns(); goto EXIT;
					case 1:
                        uint64_t u64_Addr;
						Z3_get_numeral_uint64(m_ctx, result[0], &u64_Addr);
                        guest_start = u64_Addr;
						Z3_dec_ref(m_ctx, result[0]);
						break;
					default:
                        if (traceState) std::cout << "Fork at: " << std::hex << guest_start << "  {" << std::endl;
						for (auto && re : result) {
							uint64_t rgurd;
							Z3_get_numeral_uint64(m_ctx, re, &rgurd);

							State *state = new State(this, rgurd);
							branch.emplace_back(state);

							state->add_assert_eq(Vns(m_ctx, Z3_translate(m_ctx, re, *state)), next.translate(*state));
							if (traceState) std::cout << "    +++++++++++++++ push : " << std::hex << state->guest_start << " +++++++++++++++" << std::endl;
							Z3_dec_ref(m_ctx, re);
						}
						status = Fork;
						//next.~Vns();
                        if (traceState) std::cout << " } Fork end" << std::endl;
						goto EXIT;
					}
				}
			};

		}
		catch (...) {
			std::cout << "W MEM ERR at " << std::hex << guest_start << std::endl;
			status = Death;
		}
	}
	catch (exception &error) {
		vex_printf("unexpected z3 error: at %llx\n", guest_start);
		std::cout << error << std::endl;
		status = Death;
	}
	
EXIT:
    unit_lock = true;
	thread_unregister();
	for (auto son : branch) {
		pool->enqueue([son] {
			son->start(False);
		});
	}
}




#include "Compress.hpp"


#include "Unop.hpp"
#include "Binop.hpp"
#include "Triop.hpp"
#include "Qop.hpp"



#ifndef State_class_defs
#define State_class_defs


typedef struct ChangeView {
	State *elders;
	ChangeView *front;
}ChangeView;

#if defined(GUEST_IS_64)
typedef ULong(*Function_6)(ULong, ULong, ULong, ULong, ULong, ULong);
typedef ULong(*Function_5)(ULong, ULong, ULong, ULong, ULong);
typedef ULong(*Function_4)(ULong, ULong, ULong, ULong);
typedef ULong(*Function_3)(ULong, ULong, ULong);
typedef ULong(*Function_2)(ULong, ULong);
typedef ULong(*Function_1)(ULong);
#else
typedef UInt(*Function_6)(UInt, UInt, UInt, UInt, UInt, UInt);
typedef UInt(*Function_5)(UInt, UInt, UInt, UInt, UInt);
typedef UInt(*Function_4)(UInt, UInt, UInt, UInt);
typedef UInt(*Function_3)(UInt, UInt, UInt);
typedef UInt(*Function_2)(UInt, UInt);
typedef UInt(*Function_1)(UInt);
#endif

typedef Vns (*Z3_Function6)(Vns &, Vns &, Vns &, Vns &, Vns &, Vns &);
typedef Vns (*Z3_Function5)(Vns &, Vns &, Vns &, Vns &, Vns &);
typedef Vns (*Z3_Function4)(Vns &, Vns &, Vns &, Vns &);
typedef Vns (*Z3_Function3)(Vns &, Vns &, Vns &);
typedef Vns (*Z3_Function2)(Vns &, Vns &);
typedef Vns (*Z3_Function1)(Vns &);


extern std::hash_map<ADDR, Hook_struct> CallBackDict;
extern std::hash_map<ADDR, std::vector<Hook_Replace>> ReplaceDict;
extern ThreadPool *pool;
extern void* funcDict(void*);
extern __m256i m32_fast[33];
extern __m256i m32_mask_reverse[33];
extern Vns ir_temp[MAX_THREADS][400];
extern State*		_states[MAX_THREADS];
extern std::mutex global_state_mutex;
extern Bool TriggerBug_is_init ;
//call back
extern State_Tag(*Ijk_call_back)(State *, IRJumpKind);
extern Super		pState_fork;




class State {
private:
    ADDR guest_start_ep;
    ADDR guest_start;
	void *VexGuestARCHState;

public:
	PyObject *base;
	z3::context m_ctx;
	z3::solver solv;
	//std::queue< std::function<void()> > check_stack;
	Long delta;
	bool unit_lock;
    std::vector<Vns> from;
    std::vector<Vns> to;
    

protected:
	Bool need_record;

private:
	Pap pap;
    int replace_const;

	VexTranslateResult res;
	VexRegisterUpdates pxControl = VexRegUpd_INVALID;
	VexArchInfo         vai_guest, vai_host;
	VexGuestExtents     vge;
	VexTranslateArgs    vta;
	VexTranslateResult  vtr;
	VexAbiInfo	        vbi;
	VexControl          vc;

	std::vector<Vns> asserts;
	UShort t_index;


	inline Bool treeCompress(z3::context &ctx, Addr64 Target_Addr, State_Tag Target_Tag, std::vector<State_Tag> &avoid, ChangeView& change_view, std::hash_map<ULong, Vns> &change_map, std::hash_map<UShort, Vns> &regs_change_map);
	
public:
	Register<1000> regs;
	MEM mem;//多线程设置相同user，不同state设置不同user
	ULong runed = 0;
	std::vector <State*> branch;
	State_Tag status;




	State(char *filename, Addr64 gse, Bool _need_record, PyObject *_base) ;
	State(State *father_state, Addr64 gse, PyObject *_base) ;


	~State() ;
	void thread_register();
	void thread_unregister();
	void IR_init();
	inline IRSB* BB2IR();
	inline void add_assert(Vns &assert, Bool ToF);
	inline void add_assert_eq(Vns &eqA, Vns &eqB);
	void start(Bool first_bkp_pass);
	void compress(Addr64 Target_Addr, State_Tag Target_Tag, std::vector<State_Tag> &avoid);//最大化缩合状态 
	inline Vns getassert(z3::context &ctx);
	inline Addr64 get_guest_start();
	inline Addr64 get_guest_start_ep();
	inline Vns tIRExpr(IRExpr*);
	inline void write_regs(int offset, void*, int length);
	inline void read_regs(int offset, void*, int length);
	inline Vns CCall(IRCallee *cee, IRExpr **exp_args, IRType ty);
	void read_mem_dump(const char *);
	inline Vns T_Unop(IROp, IRExpr*);
	inline Vns T_Binop(IROp, IRExpr*, IRExpr*);
	inline Vns T_Triop(IROp, IRExpr*, IRExpr*, IRExpr*);
	inline Vns T_Qop(IROp, IRExpr*, IRExpr*, IRExpr*, IRExpr*);
	inline Vns ILGop(IRLoadG *lg);
    inline bool avoid_check(ADDR);
    inline Vns get_int_const(UShort nbit);
    inline Vns cast(Vns);

	inline operator context&();
	inline operator Z3_context();
	inline operator std::string();
};

#endif
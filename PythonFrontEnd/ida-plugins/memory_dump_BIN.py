# encoding:utf-8
from __future__ import print_function
import idaapi
import idc
import idautils
import sys
import struct
import time
import pyvex
import archinfo#没有pyvex则archinfo无法工作

def get_hardware_mode():
    (arch, mode) = (None, None)
    info = idaapi.get_inf_structure()
    # heuristically detect hardware setup
    info = idaapi.get_inf_structure()
    
    try:
        cpuname = info.procname.lower()
    except:
        cpuname = info.procName.lower()

    try:
        # since IDA7 beta 3 (170724) renamed inf.mf -> is_be()/set_be()
        is_be = idaapi.cvar.inf.is_be()
    except:
        # older IDA versions
        is_be = idaapi.cvar.inf.mf
    # print("Keypatch BIG_ENDIAN = %s" %is_be)
    
    if cpuname == "metapc":
        if info.is_64bit():
            arch = archinfo.ArchAMD64()
            mode = KS_MODE_64
        elif info.is_32bit():
            arch = archinfo.ArchX86()
            mode = KS_MODE_32
        else:
            arch = archinfo.ArchNotFound()
            mode = KS_MODE_16
    
    elif cpuname.startswith("ppc"):
        if info.is_64bit():
            arch = archinfo.ArchPPC64()
            mode = KS_MODE_PPC64
        else:
            arch = archinfo.ArchPPC32()
            mode = KS_MODE_PPC32
        if cpuname == "ppc":
            # do not support Little Endian mode for PPC
            mode += KS_MODE_BIG_ENDIAN
    
    elif cpuname.startswith("mips"):
        if info.is_64bit():
            arch = archinfo.ArchMIPS64()
            mode = KS_MODE_MIPS64
        else:
            arch = archinfo.ArchMIPS32()
            mode = KS_MODE_MIPS32
    elif cpuname.startswith("systemz") or cpuname.startswith("s390x"):
        arch = archinfo.ArchS390X()
        mode = KS_MODE_BIG_ENDIAN

    return (arch, mode)

#xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

def getfpround(name):
        assert(name=='fpround')
        return (idc.GetRegValue('CTRL')>>10)&0b11
        
def getSseRound(name):
    assert(name=='sseround')
    return (idc.GetRegValue('MXCSR')>>13)&0b11
    
def getftop(name):
    assert(name=='ftop')
    return (idc.GetRegValue('STAT')>>11)&0b111
    
def getfpu_tags(name):
    assert(name=='fpu_tags')
    return (idc.GetRegValue('TAGS')>>11)&0b111
    
    
def get_xmm(s):
    rv = idaapi.regval_t()
    if idaapi.get_reg_val(s, rv):
        return int(rv.bytes()[::-1].encode('hex'),16)
    raise('fk names')
    

#xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

class Dump:
    def __init__(self, arch, mode):
        self.arch=arch
        self.mode=mode
        self.method = self.Regs_method()
        self.register_names = self.Regs_register_names()
        self.registers = self.Regs_registers()
        
    def Regs_method(self):
        assert(0)
        
    def Regs_register_names(self):
        assert(0)
        
    def Regs_registers(self):
        return self.arch.registers
        
    def getRegs(self):
        values={}
        for regAddress in self.register_names:
            regName = self.register_names[regAddress]
            
            if regName in self.method:
                values[regAddress]=self.method[regName](regName)
                #print("success %-10s %x"%(regName,values[regAddress]))
            else:
                try:
                    values[regAddress]=idc.GetRegValue(regName )
                    #print("success %-10s %x"%(regName,values[regAddress]))
                except Exception as e:
                    print("filed  read regName %-10s %s"%(regName,e))
                    pass
        return values
    
    def writeMem(self, binfile):
        regs = self.getRegs()
        segm = self.init_segm_mem()
        for n in xrange(idaapi.get_segm_qty()):
            seg = idaapi.getnseg(n)
            if seg:
                count=0
                h=''
                while (idaapi.get_segm_name(seg, 0)+h) in segm.keys():
                    count+=1
                    h = str(count)
                name=idaapi.get_segm_name(seg, 0)+h
                address=seg.startEA
                length=seg.endEA-seg.startEA
                
                db_data=idaapi.dbg_read_memory(address,length)
                if db_data:
                    print('ok   ',name,seg.flags,length,'bytes',length/1024,'kb')
                    segm[name]=[address,length,db_data]
                else:
                    print('faild',name,seg.flags,length,'bytes',length/1024,'kb')
                    pass
        nameoffset_p=0
        dataoffset_p=0
        all_ab_name=0
        
        for regAddress in regs:
            INT=regs[regAddress]
            regName = self.register_names[regAddress]
            size = self.registers[regName][1]
            try:
                if size==1:
                    db_data=struct.pack("<B",INT)
                elif size==2:
                    db_data=struct.pack("<H",INT)
                elif size==4:
                    db_data=struct.pack("<I",INT)
                elif size==8:
                    db_data=struct.pack("<Q",INT)
                elif size==16:
                    db_data=struct.pack("<QQ",int(INT&0xffffffffffffffff),int(INT>>64))
                elif size==32:
                    db_data=struct.pack("<QQQQ",INT&0xffffffffffffffff,(INT>>64)&0xffffffffffffffff,(INT>>128)&0xffffffffffffffff,INT>>192)
                else:
                    continue
                segm['registers'+str(regAddress)]=[regAddress,len(db_data),db_data]
                print(" (%-10s : %-5d) (%-x) (%d)"%(regName, regAddress,(INT),len(db_data)))
            except Exception as e:
                print("--------- error:", e, regName, hex(INT), size,"--------- ")
            
        for name in segm:
            address,length,db_data=segm[name]
            ab_name=(name+'\x00').encode('utf-8')
            all_ab_name+=len(ab_name)
        for name in segm:
            address,length,db_data=segm[name]
            ab_name=(name+'\x00').encode('utf-8')
            nameoffset=len(segm)*32+nameoffset_p
            dataoffset=len(segm)*32+all_ab_name+dataoffset_p
            db1=struct.pack("<Q",nameoffset)
            db2=struct.pack("<Q",address)
            db3=struct.pack("<Q",length)
            db4=struct.pack("<Q",dataoffset)
            binfile.write(db1)
            binfile.write(db2)
            binfile.write(db3)
            binfile.write(db4)
            nameoffset_p+=len(ab_name)
            dataoffset_p+=length
        for name in segm:
            address,length,db_data=segm[name]
            ab_name=(name+'\x00').encode('utf-8')
            binfile.write(ab_name)
        for name in segm:
            address,length,db_data=segm[name]
            binfile.write(db_data)
            
    def init_segm_mem(self):
        return {}
        
class AMD64_dump(Dump):
    def __init__(self, arch, mode):
        Dump.__init__(self, arch, mode)
        
    def Regs_method(self):
        method={
        'mm0':get_xmm,
        'mm1':get_xmm,
        'mm2':get_xmm,
        'mm3':get_xmm,
        'mm4':get_xmm,
        'mm5':get_xmm,
        'mm6':get_xmm,
        'mm7':get_xmm,
        'xmm0':get_xmm,
        'xmm1':get_xmm,
        'xmm2':get_xmm,
        'xmm3':get_xmm,
        'xmm4':get_xmm,
        'xmm5':get_xmm,
        'xmm6':get_xmm,
        'xmm7':get_xmm,
        'xmm8':get_xmm,
        'xmm9':get_xmm,
        'xmm10':get_xmm,
        'xmm11':get_xmm,
        'xmm12':get_xmm,
        'xmm13':get_xmm,
        'xmm14':get_xmm,
        'xmm15':get_xmm,
        'fs': lambda name : idaapi.dbg_get_thread_sreg_base(idc.GetCurrentThreadId(),int(cpu.fs)),
        'gs': lambda name : idaapi.dbg_get_thread_sreg_base(idc.GetCurrentThreadId(),int(cpu.gs)),
        'fpround':getfpround,
        'sseround':getSseRound,
        'ftop':getftop
        # 'fpu_tags':getfpu_tags
        }
        return method
        
    def Regs_register_names(self):
        register_names = self.arch.register_names
        register_names.pop(776)
        for i in range(8):
            register_names[776+i*8]="mm%d"%i
        return register_names
        
    def Regs_registers(self):
        return self.arch.registers

def align(a):
    return a & ~(0x1000 - 1)
    

class gdt32():
    def __init__(self, GDT_ADDR_write):
        self.SegDiscriptions={}
        self.gdt=[]
        self.GDT_SIZE=0
        self.GDT_ADDR_write=GDT_ADDR_write
        
    @staticmethod
    def create_selector(idx,TI,RPL):            #TI:1 LDT 0:GDT   PRL:最高级:00  11最低级
        to_ret = RPL&0b11
        to_ret |= TI&0b1<<2
        to_ret |= (idx&0b1111111111111) << 3
        return to_ret
        
    def segReg2base(self,reg):
        value=self.uc.reg_read(reg)
        try:
            return self.SegDiscriptions[value>>3]
        except:
            return 0
            
    @staticmethod
    def create_gdt_entry(base, limit, DPL,S,TYPE, flags):
        to_ret = limit & 0xffff;                #[:16]      limit[:16]
        to_ret |= (base & 0xffffff) << 16;      #[16:40]    base[:24]
        to_ret |= (TYPE & 0xf) << 40;           #TYPE 段的类型特征和存取权限  
        to_ret |= (S & 0xb1) << 44;             #S: 如果s=0 这是一个系统段 1 是普通代码段或数据段
        to_ret |= (DPL & 0xb11) << 45;          #DPL 描述符特权级 0~3
        to_ret |= (1 & 0xb1) << 47;             #1
        to_ret |= ((limit >> 16) & 0xf) << 48;  #[48:52]    limit[16:20]: 存放段最后一个内存单元的偏移量 
        to_ret |= (flags & 0xf) << 52;          #[52:56]    flag: G<<3|D<<2|0<1|AVL (各1bit )如果G=0那么段大小为0~1MB, G=1段大小为4KB~4GB  D或B 这个我还没搞懂 以后再说只要知道32位访问为1 AVL: linux忽略这个
        to_ret |= ((base >> 24) & 0xff) << 56;  #[56:64]    base[24:32]
        return struct.pack('<Q',to_ret)

    def addSegDiscription(self,GDT_index, base, limit, DPL, S, TYPE, flags):
        seg_selector = GDT_index
        seg_selector >>= 3
        if seg_selector>=self.GDT_SIZE:
            for c in range(seg_selector-self.GDT_SIZE+1):
                self.gdt.append(None)
            self.GDT_SIZE=seg_selector
        self.gdt[seg_selector]=gdt32.create_gdt_entry(base, limit, DPL,S,TYPE, flags)
        
    def get_gdt(self):
        ret = b''
        for tab in self.gdt:
            if(tab):
                ret += tab
            else:
                ret += b"\x00\x00\x00\x00\x00\x00\x00\x00"
        return {"gdt_table":[self.GDT_ADDR_write, len(ret), ret]}
        
class X86_dump(Dump):
    def __init__(self, arch, mode):
        Dump.__init__(self, arch, mode)
        
    def Regs_method(self):
        X86_EFLAGS_CF = 1 << 0
        X86_EFLAGS_FIXED = 1 << 1
        X86_EFLAGS_PF = 1 << 2
        X86_EFLAGS_AF = 1 << 4
        X86_EFLAGS_ZF = 1 << 6
        X86_EFLAGS_SF = 1 << 7
        X86_EFLAGS_TF = 1 << 8
        X86_EFLAGS_IF = 1 << 9
        X86_EFLAGS_DF = 1 << 10
        X86_EFLAGS_OF = 1 << 11
        X86_EFLAGS_IOPL = 1 << 12
        X86_EFLAGS_IOPL_MASK = 3 << 12
        X86_EFLAGS_NT = 1 << 14
        X86_EFLAGS_RF = 1 << 16
        X86_EFLAGS_VM = 1 << 17
        X86_EFLAGS_AC = 1 << 18
        X86_EFLAGS_VIF = 1 << 19
        X86_EFLAGS_VIP = 1 << 20
        X86_EFLAGS_ID = 1 << 21
    
        method={
        'mm0':get_xmm,
        'mm1':get_xmm,
        'mm2':get_xmm,
        'mm3':get_xmm,
        'mm4':get_xmm,
        'mm5':get_xmm,
        'mm6':get_xmm,
        'mm7':get_xmm,
        'xmm0':get_xmm,
        'xmm1':get_xmm,
        'xmm2':get_xmm,
        'xmm3':get_xmm,
        'xmm4':get_xmm,
        'xmm5':get_xmm,
        'xmm6':get_xmm,
        'xmm7':get_xmm,
        'xmm8':get_xmm,
        'xmm9':get_xmm,
        'xmm10':get_xmm,
        'xmm11':get_xmm,
        'xmm12':get_xmm,
        'xmm13':get_xmm,
        'xmm14':get_xmm,
        'xmm15':get_xmm,
        'd' : lambda name : 1,
        'gdt': lambda name : 0x2333000,
        'fpround':getfpround,
        'sseround':getSseRound,
        'ftop':getftop
        # 'fpu_tags':getfpu_tags
        }
        return method
        
    def Regs_register_names(self):
        register_names = self.arch.register_names
        register_names.pop(72)
        for i in range(8):
            register_names[72+i*8]="mm%d"%i
        return register_names
        
        
    def init_segm_mem(self):
        segment = {}
        gdt = gdt32(0x2333000)
        fs_idx = idc.GetRegValue('fs')
        gs_idx = idc.GetRegValue('gs')
        fs_addr = idaapi.dbg_get_thread_sreg_base(idc.GetCurrentThreadId(),int(cpu.fs))
        gs_addr = idaapi.dbg_get_thread_sreg_base(idc.GetCurrentThreadId(),int(cpu.gs))
        G=1
        D=0
        L=1
        AVL=0
        gdt.addSegDiscription(fs_idx, fs_addr, 0x1000, 1, 0, 0, (G<<3)|(D<<2)|(L<<1)|AVL)
        gdt.addSegDiscription(gs_idx, gs_addr, 0x1000, 1, 0, 0, (G<<3)|(D<<2)|(L<<1)|AVL)
        return gdt.get_gdt()

def doit():
    arch, mode=get_hardware_mode()
    dump=None
    if isinstance(arch,archinfo.ArchX86):
        dump=X86_dump(arch,mode)
    elif isinstance(arch,archinfo.ArchAMD64):
        dump=AMD64_dump(arch,mode)
    
    bin_path=ida_loader.get_path(ida_loader.PATH_TYPE_CMD)
    bin_path=bin_path.decode("utf8")
    binfile = open(bin_path+b'.dump', 'wb+')
    dump.writeMem(binfile)
    binfile.close()
    print('dump success: ',bin_path+'.dump')
    

class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment bin"

    help = "This is help bin"
    wanted_name = "My Python plugin bin"
    wanted_hotkey = "Shift-2"

    def init(self):
        idaapi.msg("init() called!\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        doit()
        
    def term(self):
        idaapi.msg("term() called!\n")

def PLUGIN_ENTRY():
    return myplugin_t()

import re
import os

code="""(define-fun part_40136f_75 () (_ BitVec 8)
  #x0e)
(define-fun flag7 () (_ BitVec 8)
  #x80)
(define-fun flag9 () (_ BitVec 8)
  #x80)
(define-fun part_4012d1_68 () (_ BitVec 8)
  #xab)
(define-fun part_40135d_74 () (_ BitVec 8)
  #xd7)
(define-fun part_401165_50 () (_ BitVec 32)
  #x742a80a9)
(define-fun part_401221_62 () (_ BitVec 32)
  #x09004270)
(define-fun flag12 () (_ BitVec 8)
  #x80)
(define-fun part_4012ff_70 () (_ BitVec 8)
  #xd8)
(define-fun part_4013b2_78 () (_ BitVec 8)
  #x4f)
(define-fun part_40132f_72 () (_ BitVec 8)
  #x2d)
(define-fun part_40122e_63 () (_ BitVec 32)
  #x19400223)
(define-fun part_40130e_71 () (_ BitVec 8)
  #x32)
(define-fun part_4012a2_66 () (_ BitVec 8)
  #x14)
(define-fun part_401217_61 () (_ BitVec 32)
  #x4414e071)
(define-fun part_4013a7_77 () (_ BitVec 8)
  #xd2)
(define-fun flag6 () (_ BitVec 8)
  #x80)
(define-fun flag10 () (_ BitVec 8)
  #x40)
(define-fun part_4011ea_58 () (_ BitVec 32)
  #x00b465c0)
(define-fun flag3 () (_ BitVec 8)
  #x08)
(define-fun flag4 () (_ BitVec 8)
  #x80)
(define-fun flag11 () (_ BitVec 8)
  #x80)
(define-fun part_4011ce_56 () (_ BitVec 32)
  #x0e2197d8)
(define-fun part_40128b_65 () (_ BitVec 8)
  #x4e)
(define-fun part_4012b1_67 () (_ BitVec 8)
  #x92)
(define-fun flag8 () (_ BitVec 8)
  #x80)
(define-fun flag1 () (_ BitVec 8)
  #x80)
(define-fun part_401210_60 () (_ BitVec 32)
  #x628beb94)
(define-fun part_4011ae_55 () (_ BitVec 32)
  #x382b16c0)
(define-fun part_401276_64 () (_ BitVec 8)
  #xc3)
(define-fun part_4012e8_69 () (_ BitVec 8)
  #xcb)
(define-fun flag13 () (_ BitVec 8)
  #x80)
(define-fun part_4011a4_54 () (_ BitVec 32)
  #x9a200a54)
(define-fun flag0 () (_ BitVec 8)
  #x80)
(define-fun part_40116f_51 () (_ BitVec 32)
  #x11182116)
(define-fun part_40114f_48 () (_ BitVec 32)
  #x0261f0f3)
(define-fun part_4011f7_59 () (_ BitVec 32)
  #x91472542)
(define-fun part_40118e_52 () (_ BitVec 32)
  #xe815b65c)
(define-fun flag14 () (_ BitVec 8)
  #x80)
(define-fun flag5 () (_ BitVec 8)
  #x80)
(define-fun part_401346_73 () (_ BitVec 8)
  #xc7)
(define-fun part_4011d8_57 () (_ BitVec 32)
  #xeffe3483)
(define-fun part_401390_76 () (_ BitVec 8)
  #x9f)
(define-fun part_4013c4_79 () (_ BitVec 8)
  #x82)
(define-fun part_401195_53 () (_ BitVec 32)
  #xb5fe1b6a)
(define-fun flag15 () (_ BitVec 8)
  #x20)
(define-fun flag2 () (_ BitVec 8)
  #x40)
(define-fun part_401156_49 () (_ BitVec 32)
  #x9fd901cd)
"""
rea={}
for c in code.split("define-fun "):
    c=c.replace("\n","").replace("(","").replace(")","")
    regex = re.match(
                    r'(?P<name>[A-Za-z0-9_]+)[\w _]*#x'
                    r'(?P<end>[a-z0-9_]+)',
                    c
                )
    if (regex):
        data = regex.groupdict()
        rea[data["name"]]=int(data["end"],16)
    
start=[]
kdict={}
for k in rea:
    regex = re.match(r'\D+',k)
    if (regex):
        data = regex.group()
        if data not in start:
            start.append(data)
            kdict[data]={}
        kdict[data][k] = rea[k]

for s in kdict:
    if '_' in s:
        continue
    ss=sorted(kdict[s].items(),key=lambda x:int(x[0].replace(s,"")))
    
    dd = [_[1] for _ in ss] 
    string="".join([chr(_[1]) for _ in ss] )
    print(s,len(dd),string)
    sl = "".join(["0x%02x, "%(_[1]) for _ in ss])[:-2]
    print( "b = [%s]"%sl )
    print( "".join(["%02x "%(_[1]) for _ in ss] ))
    print("\n\n\n")



print('[patch_byte(addr+i,v) for i,v in enumerate(b)]')



    
 
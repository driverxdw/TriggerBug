import re
import os

code="""sat(define-fun flag1 () (_ BitVec 8)
  #x37)
(define-fun flag7 () (_ BitVec 8)
  #x6f)
(define-fun flag9 () (_ BitVec 8)
  #x34)
(define-fun flag13 () (_ BitVec 8)
  #x3b)
(define-fun flag12 () (_ BitVec 8)
  #x70)
(define-fun flag0 () (_ BitVec 8)
  #x7c)
(define-fun flag14 () (_ BitVec 8)
  #x70)
(define-fun flag5 () (_ BitVec 8)
  #x31)
(define-fun flag6 () (_ BitVec 8)
  #x44)
(define-fun flag10 () (_ BitVec 8)
  #x24)
(define-fun flag3 () (_ BitVec 8)
  #x61)
(define-fun flag4 () (_ BitVec 8)
  #x4c)
(define-fun flag11 () (_ BitVec 8)
  #x37)
(define-fun flag2 () (_ BitVec 8)
  #x40)
(define-fun flag15 () (_ BitVec 8)
  #x4b)
(define-fun flag8 () (_ BitVec 8)
  #x2a)
"""
rea={}
for c in  code.split("(define-fun "):
    c=c.replace("\n","").replace("(","").replace(")","")
    regex = re.match(
                    r'(?P<name>[A-Za-z0-9_]+)[\w _]*#x'
                    r'(?P<end>[a-z0-9_]+)',
                    c
                )
    if (regex):
        data = regex.groupdict()
        rea[data["name"]]=int(data["end"],16)
    
print(rea)

def sortedDictValues1(adict): 
    return 
ss=sorted(rea.items(),key=lambda x:int(x[0].replace("flag","")))
print(ss)

print( "".join([chr(_[1]) for _ in ss] ))
print( "".join(["%02x"%(_[1]) for _ in ss] ))
print( "".join(["%02x "%(_[1]) for _ in ss] ))




    
 
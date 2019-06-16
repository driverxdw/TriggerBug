import re
import os

code="""sat(define-fun flag1 () (_ BitVec 8)
  #x01)
(define-fun flag7 () (_ BitVec 8)
  #x64)
(define-fun flag9 () (_ BitVec 8)
  #x4e)
(define-fun flag13 () (_ BitVec 8)
  #x06)
(define-fun flag12 () (_ BitVec 8)
  #x59)
(define-fun flag0 () (_ BitVec 8)
  #x14)
(define-fun flag14 () (_ BitVec 8)
  #x23)
(define-fun flag5 () (_ BitVec 8)
  #x68)
(define-fun flag6 () (_ BitVec 8)
  #x78)
(define-fun flag10 () (_ BitVec 8)
  #x2f)
(define-fun flag3 () (_ BitVec 8)
  #x69)
(define-fun flag4 () (_ BitVec 8)
  #x28)
(define-fun flag11 () (_ BitVec 8)
  #x66)
(define-fun flag2 () (_ BitVec 8)
  #x0c)
(define-fun flag15 () (_ BitVec 8)
  #x4f)
(define-fun flag8 () (_ BitVec 8)
  #x02)

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




    
 
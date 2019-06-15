import base64
import hashlib
import json
import sqlite3
import sys
import xml.dom.minidom as xmldom
from lxml import etree
import time
from re import findall
import requests
import pickle
import re

html=None
with open("./Intel® Intrinsics Guide.html")as f:
    html=f.read()

class call:
    def __init__(self, insn):
        sig=insn.xpath('div[@class="signature"]/span[@class="sig"]')[0]
        self.instruction=None
        for dynopsis in insn.xpath('div[@class="details"]/div[@class="synopsis"]/text()'):
            if "Instruction" in dynopsis:
                self.instruction=dynopsis.replace("Instruction: ","")
        self.cpuid=insn.xpath('div[@class="details"]/div[@class="synopsis"]/span[@class="cpuid"]/text()')[0]
        self.name = sig.xpath('span[@class="name"]/text()')[0]
        rety=sig.xpath('span[@class="rettype"]/text()')
        self.rettype =rety[0] if rety else ""
        params = sig.xpath('span[starts-with(@class,"param")]')
        self.params=[]
        for ind in range(0,len(params),2):
            p1=params[ind].xpath("text()")[0]
            if p1=="void":
                self.params.append("void")
                break
            p2=params[ind+1].xpath("text()")[0]
            self.params.append([p1,p2])
        description=insn.xpath('div[@class="details"]/div[@class="description"]/node()')
        self.description="\n"
        for des in description:
            if not isinstance(des,str):
                t=des.xpath('text()')
                if t:
                    des="["+t[0]+"]"
                else:
                    des=""
            self.description=self.description+des
        operation=insn.xpath('div[@class="details"]/div[@class="operation"]/text()')
        self.operation=operation[0] if operation else None
    def __str__(self):
        res=""
        for i in self.__dict__:
            res = res + "{:s}\t{:s}\n".format(str(i),str(self.__dict__[i]))
        return res
intrinsics={}
tree = etree.HTML(html)
intrinsics_list=tree.xpath('//div[@id="intrinsics_list"]/div')
for insn in intrinsics_list:
    kind=insn.xpath('@class')
    cf=call(insn)
    intrinsics[cf.name]=cf


print(intrinsics)

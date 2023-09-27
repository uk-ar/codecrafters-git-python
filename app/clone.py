# SHA-1 type size size-in-packfile offset-in-packfile depth base-SHA-1

# $ git verify-pack -v  .git/objects/pack/pack-dcb42ab2f64d6f9c58d4c3b74152cee3608612a9.pack
# 2ed99a4a46a26fc7dd29f7749424a3bedae44c19 commit 182 126 12
# e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 blob   0 9 138
# 10c1f4528d8ce950be424789b00dda94e0846f9b blob   9 18 147
# 9b93a2a6e4bbc949ef413fcdcdb1085bbc7ed237 blob   9 18 165
# 70f144afc91f9cb05b2775bde6cb36a684fd7746 tree   126 123 183
# ec5e386905ff2d36e291086a1207f2585aaa8920 tree   33 44 306
# non delta: 6 objects
# .git/objects/pack/pack-dcb42ab2f64d6f9c58d4c3b74152cee3608612a9.pack: ok


import requests
import zlib
import hashlib
import base64
import gzip
import os
import io
from struct import unpack
from collections import OrderedDict
from dataclasses import dataclass, field
#".git/objects/pack/pack-1b3414d8dcf88f8de78a61a7a8264d379c711e85.pack"

#file = ".git/objects/pack/pack-6e797c86f303c7323056431875af4eefea332fe7.pack"
types = [b"ERROR",b"COMMIT",b"TREE",b"BLOB",b"TAG",b"ERROR",b"OFS_DELTA",b"REF_DELTA"]

@dataclass
class Obj:
    type: int
    content: bytes
    sha1: int = 0    
    def __post_init__(self):
        self.sha1 = Obj.hash(self.type,self.content)

    @staticmethod
    def file(type,content):
        return types[type].lower()+f" {len(content)}\0".encode()+content

    @staticmethod
    def hash(type,content):
        return hashlib.sha1(Obj.file(type,content)).hexdigest()

    def print(self):
        print(types[self.type])
        print(self.content)

@dataclass
class Ofs_delta(Obj):
    pass

@dataclass
class Blob(Obj):
    pass

@dataclass
class Tree(Obj):
    objs: list = field(default_factory=list)
    def __post_init__(self):
        super().__post_init__()
        s = self.content
        while s:
            mode, s = s.split(b" ", maxsplit=1)
            mode = mode.decode()
            path, s = s.split(b"\0", maxsplit=1)
            path = path.decode()
            sha1, s = int.from_bytes(s[:20], byteorder="big"), s[20:]
            self.objs.append([mode,path,sha1])

    def print(self):
        for mode,path,sha1 in self.objs:
            print(f'{mode:0>6} {sha1:x} {path}')

@dataclass
class Commit(Obj):
    tree : str = ""
    def __post_init__(self):
        super().__post_init__()
        self.tree = self.content.split(b"\n")[0].split(b" ")[1].decode()

def cat_file(type,s):
    if type == b"blob" or type == b"BLOB":
        print(s.decode(), end="")
    elif type == b"tree" or type == b"TREE":
        while s:
            mode, s = s.split(b" ", maxsplit=1)
            mode = mode.decode()
            path, s = s.split(b"\0", maxsplit=1)
            path = path.decode()
            sha1, s = int.from_bytes(s[:20], byteorder="big"), s[20:]
            print(f'{mode:0>6} {sha1:x} {path}')
            # print(format(int(mode.decode(),8),'06o'),format(sha1,'x'),path.decode())
    elif type == b"commit" or type == b"COMMIT":
        print(s.decode(), end="")
    else:
        print(s, end="")

def write_object(cont,base="."): # write file to git database and return sha1
    sha1 = hashlib.sha1(cont).hexdigest()
    if os.path.exists(base+"/.git/objects/"+sha1[:2]+"/"+sha1[2:]):
        return sha1
    os.makedirs(base+"/.git/objects/"+sha1[:2], exist_ok=True)
    with open(base+"/.git/objects/"+sha1[:2]+"/"+sha1[2:], "wb") as f:
        f.write(zlib.compress(cont))
    return sha1

def decode_offset(f):
    byte = unpack("!B",f.read(1))[0]  
    print(0,bin(byte))
    off = byte & ((1 << 7)-1) #offset?
    msb = (byte >> 7) & 1    
    while msb:
        byte = unpack("!B",f.read(1))[0]
        print(1,bin(byte))
        off = (off+1) << 7
        off += ((byte & ((1<<7)-1)))
        msb = (byte >> 7) & 1
    print("off:",bin(off))
    return off

def decode_size(f):
    byte = unpack("!B",f.read(1))[0]
    msb = (byte >> 7) & 1
    length = (byte & ((1<<7)-1))
    shift = 7
    while msb:
        byte = unpack("!B",f.read(1))[0]
        length += (byte & ((1<<7)-1)) << shift
        msb = (byte >> 7) & 1
        shift += 7
    return length

#file = ".git/objects/pack/pack-f20b84305579f7cd631402e28b5680d0a4770ffa.pack"
#file = ".git/objects/pack/pack-941526bd8d94d62396a7003886258ea6e35ef936.pack"
file = ".git/objects/pack/pack-965d7c52f914e48e73b0331067c88c7c3347c77e.pack"
od = OrderedDict() # offset to sha1
contents = {}
obj_types = {}

def gen_obj(type_num : int ,content : bytes):
    if types[type_num] == b"BLOB":
        return Blob(type_num,content)
    elif types[type_num] == b"TREE":
        return Tree(type_num,content)
    elif types[type_num] == b"COMMIT":
        return Commit(type_num,content)
    else:
        return Obj(type_num,content)

def read_obj(f, offset_objs):
    offset_in_packfile = f.tell()
    byte = unpack("!b",f.read(1))[0]
    obj_type = byte >> 4 & ((1 << 3)-1)
    length = byte & ((1 << 4)-1)
    msb = (byte >> 7) & 1
    shift = 4
    while msb:
        byte = unpack("!b",f.read(1))[0]
        length += (byte & ((1<<7)-1)) << shift
        msb = (byte >> 7) & 1
        shift += 7

    if types[obj_type]==b"OFS_DELTA":
        off = decode_offset(f)
        #print(off,offset_in_packfile-off)

    decomp = zlib.decompressobj()
    cont = b""
    while not decomp.eof:
        chunk = f.read(1024)
        if not chunk:
            cont += decomp.flush()
            break
        while chunk:
            cont += decomp.decompress(chunk)
            chunk = decomp.unconsumed_tail
        f.seek(-len(decomp.unused_data),os.SEEK_CUR)# from current
    if types[obj_type]!=b"OFS_DELTA":
        return gen_obj(obj_type,cont)

    ref_obj = offset_objs[offset_in_packfile-off]
    ref      = ref_obj.content
    obj_type = ref_obj.type
    # ref_sha1 = od[offset_in_packfile-off]
    # ref = contents[ref_sha1]
    # obj_type = obj_types[ref_sha1]
    print(f'ref:{ref}')
    # print(cont.hex())
    # before,after = unpack("HH",cont[:4])
    bytes_io = io.BytesIO(cont)
    after = decode_size(bytes_io)
    before = decode_size(bytes_io)
    print(f"before:{before},after:{after}")
    inst = bytes_io.read(1)
    cont = b""
    #contents[sha1]
    while inst:
        inst = int.from_bytes(inst,byteorder="big")
        ops  = [-1]*7
        if inst == 0: # reserved
            pass
        elif (inst >> 7) & 1:
            for i in range(6):
                if (inst >> i ) & 1:
                    ops[i] = decode_size(bytes_io)
            for i in range(3):
                if ops[i]!=-1 or ops[i+4]!=-1:
                    if ops[i]==-1:
                        ops[i]=0
                    if ops[i+4]==-1:
                        ops[i+4]=0x10000
                cont += ref[ops[i]:ops[i]+ops[i+4]]
            if ops[3]!=-1:
                cont += ref[ops[3]:ops[3]+0x10000]
        else:
            size = inst & ((1<<7)-1)
            cont += bytes_io.read(size)
        print(cont)
        inst = bytes_io.read(1)

    return gen_obj(obj_type,cont)
    #print(bytes_io.read().hex())

def checkout(obj,sha1_objs,path):
    if types[obj.type]==b"BLOB":
        with open(path,"wb") as f:
            f.write(obj.content)
            return
    os.makedirs(path, exist_ok=True)
    for mode,name,sha1 in obj.objs:
        #print(f'{mode:0>6} {sha1:x} {path}') 
        checkout(sha1_objs[f"{sha1:x}"],sha1_objs,path+"/"+name)
    #tree_sha1 = contents[commit].split(b" ")[1]

def peek(byte_io, n):
    ori = byte_io.tell()
    ans = byte_io.read(n)
    byte_io.seek(ori)
    return ans

def download(url):
    def add_length(s):
        s += b'\n'
        return format(len(s)+4, '04x').encode()+s

    #url = "https://github.com/codecrafters-io/git-sample-1"
    r = requests.get(url+"/info/refs?service=git-upload-pack")
    s = r.content
    version, s = s.split(b"\n", maxsplit=1)
    print(s)
    sha1s = []
    while s:
        length, s = int(s[:4], base=16)-4, s[4:]
        if length <= 0:
            continue
        line, s = s[:length], s[length:]
        sha1, ref = line[:40], line[40:].strip()
        if ref.startswith(b"HEAD\0"):
            ref = b"HEAD"
        print(sha1, ref)
        sha1s.append(sha1)

    data = add_length(b"want "+sha1+b" multi_ack side-band-64k ofs-delta")
    data += b"\n".join([add_length(b"want "+sha1) for sha1 in sha1s[:1]])
    data += b"0000"
    data += add_length(b"done")
    #print(b"foo\rbar".decode())

    r = requests.post(url+"/git-upload-pack", data=data)
    # print(r)
    s = r.content

    # skip until "NAK"
    while s:
        length, s = int(s[:4], base=16)-4, s[4:]
        if length <= 0:
            continue
        line, s = s[:length], s[length:]
        if line == b"NAK\n":
            break
    f = open('temp',mode='wb')
    while s:
        #length = int(bytes_io.read(4),base=16)-4
        length, s = int(s[:4], base=16)-4, s[4:]
        if length <= 0:
            continue
        #line = bytes_io.read(length)
        line, s = s[:length], s[length:]
        bytes_io = io.BytesIO(line)
        sideband = bytes_io.read(1)
        # sideband, line = line[:1], line[1:]
        if sideband == b"\2": # progress
            print(bytes_io.read().decode(), end="")
        elif sideband == b"\1":  # data
            print(peek(bytes_io,30))
            f.write(bytes_io.read())
            #print(peek(bytes_io,4))
            #print(bytes_io.getvalue()[:4])
            #if peek(bytes_io,4) == b"PACK":
                # line = line[4:]
                #bytes_io.read(4)
                #version = bytes_io.read(4)
                # version, line = line[:4], line[4:]
                #print(version)
                #num = int.from_bytes(bytes_io.read(4), byteorder="big")
                # num, line = int.from_bytes(line[:4], byteorder="big"), line[4:]
                # num,line = line[:4],line[4:]
                #print(version, num, bytes_io.getbuffer()[:10])
        elif sideband == b"\3":  # error
            print(bytes_io.read()[:10])


def clone(url,dir):
    #download(url)
    #f = open('temp',mode='wb')
    #with open(file, "rb") as f:
    with open('temp', "rb") as f:
        sig,version,num = unpack("!4sii",f.read(12)) # ! means big endian
        print(sig,version,num)

        files = []
        offset_objs = {}
        sha1_objs = {}
        for _ in range(num):
            offset_in_packfile = f.tell()
            obj = read_obj(f,offset_objs)
            #print(obj)
            offset_objs[offset_in_packfile]=obj
            sha1_objs[obj.sha1]=obj

            write_object(Obj.file(obj.type,obj.content),"test_dir/")
            print(obj)
            obj.print()
        [print("---",k,v) for k,v in sha1_objs.items()]
        #print("sha1:",sha1_objs)
        print(sha1_objs["b76748386b277ead1d1a473655acc621288e4ff1"])
        tree = sha1_objs[sha1_objs["b76748386b277ead1d1a473655acc621288e4ff1"].tree]
        checkout(tree,sha1_objs,"test_dir")

clone("https://github.com/codecrafters-io/git-sample-1","test_dir")
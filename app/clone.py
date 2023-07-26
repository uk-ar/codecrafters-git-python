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
from struct import unpack
from collections import OrderedDict
#".git/objects/pack/pack-1b3414d8dcf88f8de78a61a7a8264d379c711e85.pack"
file = ".git/objects/pack/pack-6e797c86f303c7323056431875af4eefea332fe7.pack"
types = [b"ERROR",b"COMMIT",b"TREE",b"BLOB",b"TAG",b"ERROR",b"OFS_DELTA",b"REF_DELTA"]

file = ".git/objects/pack/pack-f20b84305579f7cd631402e28b5680d0a4770ffa.pack"
od = OrderedDict()
with open(file, "rb") as f:
    sig,version,num = unpack("!4sii",f.read(12)) # ! means big endian
    print(sig,version,num)
    files = []
    for _ in range(num):
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
            byte = unpack("!b",f.read(1))[0]
            print(bin(byte))
            off = byte & ((1 << 7)-1) #offset?
            msb = (byte >> 7) & 1
            while msb:
                byte = unpack("!b",f.read(1))[0]
                off = (off+1) << 7
                off += ((byte & ((1<<7)-1)))
                msb = (byte >> 7) & 1
            print(off,offset_in_packfile-off)
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
        sha1 = hashlib.sha1(types[obj_type].lower()+f" {len(cont)}\0".encode()+cont).hexdigest()
        od[offset_in_packfile]=sha1
        print(f'{sha1} {types[obj_type]} {length} {f.tell()-offset_in_packfile} {offset_in_packfile}',end="")
        if types[obj_type]==b"OFS_DELTA":
            print(f' {od[offset_in_packfile-off]}')
            print(cont.hex())
            before,after = unpack("HH",cont[:4])
            print(before,after)
            print(cont[4:])
        else:
            print()

exit(0)
#7a004b59311d7ff9bb2fb32de5c23d523034c5d6 commit 230 157 12
#2ed99a4a46a26fc7dd29f7749424a3bedae44c19 commit 182 126 169
#e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 blob   0 9 295
#d39046687cccee82a87b07ffa2e3a720c9acbeb7 blob   11 20 304
#9b93a2a6e4bbc949ef413fcdcdb1085bbc7ed237 blob   9 18 324
#5148616738f455349c86ad15cb492343c9284a35 tree   126 124 342
#ec5e386905ff2d36e291086a1207f2585aaa8920 tree   33 44 466
#70f144afc91f9cb05b2775bde6cb36a684fd7746 tree   28 41 510 1 5148616738f455349c86ad15cb492343c9284a35
#10c1f4528d8ce950be424789b00dda94e0846f9b blob   9 18 551
#non delta: 8 objects
#chain length = 1: 1 object
#.git/objects/pack/pack-f20b84305579f7cd631402e28b5680d0a4770ffa.pack: ok
sig, s = s[:4],s[4:]
version, s = int.from_bytes(s[:4],byteorder="big"),s[4:]
num, s = int.from_bytes(s[:4],byteorder="big"),s[4:]
print(sig,version,num)
files = []
for _ in range(num):
    byte, s = int.from_bytes(s[:1], byteorder="big"), s[1:]
    obj_type = byte >> 4 & ((1 << 3)-1)
    length = byte & ((1 << 4)-1)
    msb = (byte >> 7) & 1
    shift = 4
    #print(sig,version,num,ty,le,msb)
    while msb:
        byte, s = int.from_bytes(s[:1], byteorder="big"), s[1:]
        length += (byte & ((1<<7)-1)) << shift
        msb = (byte >> 7) & 1
        shift += 7
    #delta, s = int.from_bytes(s[:1], byteorder="big"), s[1:]
    print(types[obj_type],length,msb)
    if types[obj_type] == b"OFS_DELTA" or types[obj_type]==b"REF_DELTA":
        decomp = zlib.decompressobj()#auto header detection
        #base64.b64decode(s[:le])
        cont,s = decomp.decompress(s,length),decomp.unused_data
        print(types[obj_type],length,cont)
        #print(s[:20])
        #_,s = s[:le],s[le:]
        continue
        # byte, s = int.from_bytes(s[:1], byteorder="big"), s[1:]
        # msb = (byte >> 7) & 1
        # shift = 7
        # offset = byte & ((1 << 7)-1)
        # while msb:
        #     byte, s = int.from_bytes(s[:1], byteorder="big"), s[1:]
        #     offset += (byte & ((1<<7)-1)) << shift
        #     msb = (byte >> 7) & 1
        #     shift += 7
        # print(offset)
        # print(files[-offset])
    decomp = zlib.decompressobj()
    cont,s = decomp.decompress(s,length),decomp.unused_data
    #cont,s = zlib.decompress(s[:le]),s[le:]
    #if types[ty]=="BLOB":
    #cont = zlib.decompress(cont)
    cont = types[obj_type].lower()+f" {len(cont)}\0".encode()+cont
    sha1 = hashlib.sha1(cont).hexdigest()
    print(types[obj_type],length,sha1)
    files.append([types[obj_type],length,sha1])
    #print(hex(int.from_bytes(s[:20], byteorder="big")))

print(files)

exit(0)

sha1, s = int.from_bytes(s[:20], byteorder="little"), s[20:]
print(hex(sha1))
print(hex(sha1), obj_type, length)


def add_length(s):
    s += b'\n'
    return format(len(s)+4, '04x').encode()+s


url = "https://github.com/codecrafters-io/git-sample-1"
r = requests.get(url+"/info/refs?service=git-upload-pack")
# for line in r.iter_lines():
#    print(line)
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
print(b"foo\rbar".decode())

r = requests.post(url+"/git-upload-pack", data=data)
# print(r)
s = r.content
while s:
    length, s = int(s[:4], base=16)-4, s[4:]
    if length <= 0:
        continue
    line, s = s[:length], s[length:]
    if line == b"NAK\n":
        break

while s:
    length, s = int(s[:4], base=16)-4, s[4:]
    if length <= 0:
        continue
    line, s = s[:length], s[length:]
    sideband, line = line[:1], line[1:]
    if sideband == b"\2":
        print(line.decode(), end="")
    elif sideband == b"\1":  # data
        print(line[:30])
        if line.startswith(b"PACK"):
            line = line[4:]
            version, line = line[:4], line[4:]
            print(version)
            num, line = int.from_bytes(line[:4], byteorder="big"), line[4:]
            # num,line = line[:4],line[4:]
            print(version, num, line[:10])
    elif sideband == b"\3":  # error
        print(line[:10])

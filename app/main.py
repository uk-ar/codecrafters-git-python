import sys
import os
import zlib
import hashlib
# from sys import byteorder
import datetime  
import subprocess
#import app.clone
from app.clone import gen_obj,Obj
from enum import Enum

# 100644 blob e69de29bb2d1d6434b8b29ae775ad8c2e48c5391    a.txt
# 100644 blob 78981922613b2afb6025042ff6bd878ac1994e85    b.txt
# 040000 tree 681a0256c5949eb40b927539f040092f453546ca    c


def write_tree(path):  # write file & directory to git database and return sha1
    if os.path.isfile(path):
        return hash_object(path)
    contents = sorted(os.listdir(path),
                      key=lambda x: x if os.path.isfile(os.path.join(path, x))
                      else x+"/")
    s = b""
    for item in contents:
        if item == ".git":
            continue
        full = os.path.join(path, item)
        if os.path.isfile(full):
            s += f"100644 {item}\0".encode()
        else:
            s += f"40000 {item}\0".encode()
        sha1 = int.to_bytes(int(write_tree(full), base=16),
                            length=20, byteorder="big")
        s += sha1
    s = f"tree {len(s)}\0".encode() + s
    # print(s)
    sha1 = hashlib.sha1(s).hexdigest()
    os.makedirs(".git/objects/"+sha1[:2], exist_ok=True)
    with open(".git/objects/"+sha1[:2]+"/"+sha1[2:], "wb") as f:
        f.write(zlib.compress(s))
    return sha1

class Type(Enum):
    COMMIT = 1
    TREE = 2
    BLOB = 3
    TAG = 4
    OFS_DELTA = 6
    REF_DELTA = 7

class Repo:
    path = ""
    def __init__(self,path="."):
        self.path = path
        if os.path.isdir(path + "/.git"):
            return
        os.mkdir(path + "/.git")
        os.mkdir(path + "/.git/objects")
        os.mkdir(path + "/.git/refs")
        with open(path + "/.git/HEAD", "w") as f:
            f.write("ref: refs/heads/master\n")
        print("Initialized git directory")
    
    def gen_path(self,sha1):
        return f"{self.path}/.git/objects/{sha1[:2]}/{sha1[2:]}"

    def get_obj(self,sha1):
        with open(self.gen_path(sha1), "rb") as f:
            s = zlib.decompress(f.read())
        kind, s = s.split(b" ", maxsplit=1)
        size, s = s.split(b"\0", maxsplit=1)
        return gen_obj(Type[kind.decode().upper()].value,s)
    
    def write_obj(self,obj : Obj):
        path = self.gen_path(obj.sha1())
        if os.path.exists(path):
            return obj.sha1()
        os.makedirs(os.path.dirname(path),exist_ok=True)
        with open(path, "wb") as f:
            f.write(zlib.compress(Obj.file(obj.type(),obj.content())))
        return obj.sha1()

def hash_file(file) -> Obj: # write file to git database and return sha1
    #if os.path.isdir(file):
    #    return write_tree(file)
    return gen_obj(Type["BLOB"].value,open(file, "rb").read())

def main():
    command = sys.argv[1]
    if command == "init":
        Repo("./")
    elif command == "cat-file":
        sha1 = sys.argv[3]
        repo = Repo("./")
        repo.get_obj(sha1).cat_file()
    elif command == "hash-object":
        file = sys.argv[3]
        print(Repo("./").write_obj(hash_file(file)))
    elif command == "ls-tree":
        sha1 = sys.argv[3]
        with open(".git/objects/"+sha1[:2]+"/"+sha1[2:], "rb") as f:
            s = zlib.decompress(f.read())
        kind, s = s.split(b" ", maxsplit=1)
        size, s = s.split(b"\0", maxsplit=1)
        while s:
            mode, s = s.split(b" ", maxsplit=1)
            path, s = s.split(b"\0", maxsplit=1)
            sha1, s = s[:20], s[20:]
            # print(mode,path,sha1)
            print(path.decode("utf-8"))
        # print(rest, end="")
    elif command == "write-tree":
        print(write_tree("./"))
    elif command == "clone":
        print("clone")
        url = sys.argv[2]
        dir = sys.argv[3]
        print(sys.argv)
        os.makedirs(dir, exist_ok=True)
        init(dir)
        app.clone.clone(url,dir)
        #subprocess.call("ls")
        #r = requests.get(url+"/info/refs?service=git-upload-pack")
        
        #print(write_tree("./"))
    elif command == "commit-tree":
        # print(sys.argv)
        tree_sha = sys.argv[2]
        commit_sha = sys.argv[4]
        message = sys.argv[6]
        author = "Yuuki Arisawa <yuuki.ari@gmail.com>"
        timestamp = datetime.datetime.now().isoformat()+"+09:00"
        s = f"""tree {tree_sha}
parent {commit_sha}
author {author} {timestamp}
committer {author} {timestamp}

{message}
""".encode()
        s = f"commit {len(s)}\0".encode() + s
        # print(s)
        sha1 = hashlib.sha1(s).hexdigest()
        # if os.path.exists(".git/objects/"+sha1[:2]+"/"+sha1[2:]):
        #    return sha1
        os.makedirs(".git/objects/"+sha1[:2], exist_ok=True)
        with open(".git/objects/"+sha1[:2]+"/"+sha1[2:], "wb") as f:
            f.write(zlib.compress(s))
        print(sha1)
        # 'commit-tree', 'eeb712e789b6616df86a6ed45a1d2629f360fcbf', '-p', 'ff669c388e263c71948998930630cb9828f677d6', '-m', 'vanilla yikes scooby monkey humpty humpty'
        # git cat-file commit <sha>
    else:
        print(sys.argv)
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()

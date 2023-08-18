import sys
import os
import zlib
import hashlib
# from sys import byteorder
import datetime  
import subprocess

def hash_object(file): # write file to git database and return sha1
    if os.path.isdir(file):
        return write_tree(file)
    with open(file, "rb") as f:
        s = f.read()
    s = b"blob " + str(len(s)).encode()+b'\0'+s
    sha1 = hashlib.sha1(s).hexdigest()
    if os.path.exists(".git/objects/"+sha1[:2]+"/"+sha1[2:]):
        return sha1
    os.makedirs(".git/objects/"+sha1[:2], exist_ok=True)
    with open(".git/objects/"+sha1[:2]+"/"+sha1[2:], "wb") as f:
        f.write(zlib.compress(s))
    return sha1
# 100644 blob e69de29bb2d1d6434b8b29ae775ad8c2e48c5391    a.txt
# 100644 blob 78981922613b2afb6025042ff6bd878ac1994e85    b.txt
# 040000 tree 681a0256c5949eb40b927539f040092f453546ca    c


def write_tree(path):  # return sha1
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

def cat_file(kind,s):
    if kind == b"blob":
        print(s.decode(), end="")
    elif kind == b"tree":
        while s:
            mode, s = s.split(b" ", maxsplit=1)
            path, s = s.split(b"\0", maxsplit=1)
            sha1, s = int.from_bytes(s[:20], byteorder="big"), s[20:]
            print(mode, format(sha1, 'x'), path.decode())
            # print(format(int(mode.decode(),8),'06o'),format(sha1,'x'),path.decode())
    elif kind == b"commit":
        print(s.decode(), end="")
    else:
        print(s, end="")

def init(path="."):
    os.mkdir(path + "/.git")
    os.mkdir(path + "/.git/objects")
    os.mkdir(path + "/.git/refs")
    with open(path + "/.git/HEAD", "w") as f:
        f.write("ref: refs/heads/master\n")
    print("Initialized git directory")

def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")

    # Uncomment this block to pass the first stage
    #
    command = sys.argv[1]
    if command == "init":
        init("./")
    elif command == "cat-file":
        sha1 = sys.argv[3]
        with open(".git/objects/"+sha1[:2]+"/"+sha1[2:], "rb") as f:
            s = zlib.decompress(f.read())
        # print(s.decode(), end="")
        # print(hashlib.sha1(zlib.decompress(s)).hexdigest())
        kind, s = s.split(b" ", maxsplit=1)
        size, s = s.split(b"\0", maxsplit=1)
        # print(kind,size,s)
        cat_file(kind,s)
    elif command == "hash-object":
        print(write_tree(sys.argv[3]))
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
        url = sys.argv[2]
        dir = sys.argv[3]
        print(sys.argv)
        os.makedirs(dir, exist_ok=True)
        init(dir)
        subprocess.call("ls")
        # r = requests.get(url+"/info/refs?service=git-upload-pack")
        
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

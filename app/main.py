import sys
import os
import zlib
import hashlib


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")

    # Uncomment this block to pass the first stage
    #
    command = sys.argv[1]
    if command == "init":
        os.mkdir(".git")
        os.mkdir(".git/objects")
        os.mkdir(".git/refs")
        with open(".git/HEAD", "w") as f:
            f.write("ref: refs/heads/master\n")
        print("Initialized git directory")
    elif command == "cat-file":
        sha1 = sys.argv[3]
        with open(".git/objects/"+sha1[:2]+"/"+sha1[2:], "rb") as f:
            s = f.read()
        # print(hashlib.sha1(zlib.decompress(s)).hexdigest())
        kind, rest = zlib.decompress(s).split(b" ", maxsplit=1)
        size, rest = rest.split(b"\0", maxsplit=1)
        # print(kind,size,rest)
        print(rest.decode(), end="")
    elif command == "hash-object":
        file = sys.argv[3]
        with open(file, "rb") as f:
            s = f.read()
        s = b"blob " + str(len(s)).encode()+b'\0'+s
        sha1 = hashlib.sha1(s).hexdigest()
        os.makedirs(".git/objects/"+sha1[:2],exist_ok=True)
        with open(".git/objects/"+sha1[:2]+"/"+sha1[2:], "wb") as f:
            f.write(zlib.compress(s))
        print(sha1)
    elif command == "ls-tree":
        sha1 = sys.argv[3]
        with open(".git/objects/"+sha1[:2]+"/"+sha1[2:], "rb") as f:
            s = zlib.decompress(f.read())
        kind, s = s.split(b" ", maxsplit=1)
        size, s = s.split(b"\0", maxsplit=1)
        while s:
            mode, s = s.split(b" ", maxsplit=1)
            path, s = s.split(b"\0", maxsplit=1)
            sha1, s = s[:20],s[20:]
            #print(mode,path,sha1)
            print(path.decode("utf-8"))
        #print(rest, end="")
    elif command == "write-tree":
        for dirpath, dirnames, filenames in os.walk("./"):
            print(f'Found directory: {dirpath}',os.path.basename(os.path.dirname(dirpath)))
            if ".git" in dirnames:
                dirnames.remove(".git")
            for file_name in filenames:
                print(file_name)
    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()

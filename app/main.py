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
    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()

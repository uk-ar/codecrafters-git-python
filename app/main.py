import sys
import os
import zlib
import re

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
        with open(".git/objects/"+sha1[:2]+"/"+sha1[2:],"rb") as f:
            s = f.read()
        kind,rest = zlib.decompress(s).split(b" ",maxsplit=1)
        size,rest = rest.split(b"\0",maxsplit=1)
        #print(kind,size,rest)
        print(rest.decode(),end="")

    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()

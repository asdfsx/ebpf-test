import os
import time

def getpid():
    print(os.getpid())

def main():
    while 1:
        getpid()
        time.sleep(1)

if __name__ == "__main__":
    main()

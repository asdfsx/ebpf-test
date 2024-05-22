import time

with open("test.out", "w") as ostream:
    while 1:
        time.sleep(1)
        ostream.write("test=====================================asdfasdfasdf=\n")
        print("test")
#        ostream.flush()

#while 1:
#    time.sleep(1)
#    print("test")
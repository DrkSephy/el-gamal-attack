#!/usr/bin/env python2
import sys
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import ElGamal
import cPickle as pcl

# # # Implement the challenger for the semantic security game # # #
# 1. send a random key
# 2. wait for two messages
# 3. flip coin, encrypt corresponding message.
# 4. wait for guess
# 5. report results.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

initMessage = pcl.load(sys.stdin)

if initMessage != "hello":
    sys.stderr.write("You're supposed to say hello.\n")
    sys.exit()

# initiate the protocol
# First, send a key.  For speed, we will use some keys from a precomputed
# database on the disk.  We can actually throw away the private key, since
# that is not needed to play the game.

# TODO: pick a random key, not always the same one.
keyfile = open("./key2.pkl","rb")
key = pcl.load(keyfile)
keyfile.close()
pcl.dump(key,sys.stdout)
sys.stdout.flush()

# Now wait for the messages.  Read it as an array.
mesgList = pcl.load(sys.stdin)

# NOTE: I don't think length checks are acutually needed, since the system
# seems to wrap messages mod p, no matter what.  Nevertheless, we check:
if type(mesgList[0]) is str:
    if len(mesgList[0]) != len(mesgList[1]):
        sys.stderr.write("The submitted messages must be of equal length.\n")
        sys.exit()
elif type(mesgList[0]) is long:
    if mesgList[0] >= key.p or mesgList[1] >= key.p \
            or mesgList[0] == 0 or mesgList[1] == 0:
        sys.stderr.write("The submitted messages must be in [1..p-1].\n")
        sys.exit()

# flip a random coin:
b = ord(Random.get_random_bytes(1)) % 2
# Now encrypt the random message.
rval = Random.get_random_bytes(256)
ct = key.encrypt(mesgList[b],rval)
pcl.dump(ct,sys.stdout)
sys.stdout.flush()

# finally wait for the guess and check the result.
guess = pcl.load(sys.stdin)
if guess == b:
    sys.stderr.write("right answer!\n")
else:
    sys.stderr.write("wrong!! x_x\n")

sys.exit()

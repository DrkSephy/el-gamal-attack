"""
Name: David Leonard
E-mail: DrkSephy1025@gmail.com
Date: October 9th, 2013

Assignment
----------
Show that PyCrypto's implementation of ElGamal 
is NOT semantically secure.

Idea
----
When using the CRT to map, we can see that some 
information is leaked. It is not critical, but an
adversary can recover this and always win the 
guessing game with 100 percent probability. We 
have almost all the pieces in this code, we just
need to figure out how to compute "a" by only
extracting bits of A (Since we cannot actually
recover A entirely).
"""




#!/usr/bin/env python2

# IDEA: start a new process (which will play the role of the challenger
# for the CPA game), and communicate with it via stdin and stdout.

import sys
from subprocess import *
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import ElGamal
import cPickle as pcl
import numbthy

p1 = Popen(["./chall.py"], stdin=PIPE, stdout=PIPE, close_fds=True)

# start the conversation with a "hello" message
hellomesg = "hello"
pcl.dump(hellomesg, p1.stdin)
p1.stdin.flush()

# now read the key.
key = pcl.load(p1.stdout)

# NOTE: the public key consists of 3 parts:
# g is the generator
# y is g^x (x is secret)
# p is the prime.

# TODO: you need to find two messages that you can distinguish via
# their ciphertext.  They have to be of equal length.  Note that
# you can just use long integers instead of strings (recommended).

# send the pair of messages:

# Create two new messages, one has a value of 1, the other has a value of -1
message0 = '' 
message1 = ''


start = random.randint(1, key.p)
p_minus = (key.p-1)/2

# Make sure we don't "GAME" the guessing game
while not message0:
    ans = numbthy.powmod(start, p_minus, key.p)
    if ans == 1:
        message0 = start
    start = random.randint(1, key.p)


message1 = key.g

# List of messages
mesgList = [message0, message1]

pcl.dump(mesgList, p1.stdin)
p1.stdin.flush()

# now get the challenge ciphertext.
ct = pcl.load(p1.stdout)

# TODO: you should be able to guess the right message with probability 1
# Ciphertext Computation
cipher1 = numbthy.powmod(ct[0], (key.p-1)/2, key.p)
cipher2 = numbthy.powmod(ct[1], (key.p-1)/2, key.p)

if cipher1 / cipher2 == 1:
    guess = 0
else:
    guess = 1

# now report our guess
pcl.dump(guess, p1.stdin)
p1.stdin.flush()

p1.stdin.close()

sys.exit()

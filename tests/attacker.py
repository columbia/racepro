import os
from racepro import *

# (0) chdir to the jail root
# (1) split the line to argument list
# (2) generate the attack
# (3) go-live
# (4) restore cwd

if chroot:
    cwd = os.getcwd()
    os.chdir(chroot)

args = string.split()
assert args[0] == 'attack'
attack_toctou(args[1], args[2:])
context.stop()

if chroot:
    os.chdir(cwd)

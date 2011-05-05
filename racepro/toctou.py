import sys
import os
import scribe
from racepro import *
import syscalls
import fcntl

syscalls.declare_syscall_sets({
        "Check"      : ["stat", "stat64", "access"],
        "FileCreate" : ["creat", "link", "mknod", "open", "rename"],
        "LinkCreate" : ["link", "symlink", "rename"],
        "DirCreate"  : ["mkdir", "rename"],
        "FileRemove" : ["unlink", "rename", "mknod", "rename"],
        "LinkRemove" : ["unlink", "rename"],
        "DirRemove"  : ["rmdir", "rename"],
        "FileWrite"  : ["chmod", "chown", "truncate", "utime", "open"],
        "FileRead"   : ["open", "execve"],
        "DirWrite"   : ["chmod", "chown", "utime", "open"],
        "DirRead"    : ["mount", "chdir", "chroot", "open", "execve"],
        })

##################################################################

patterns = set()

##################################################################

class Pattern:
    def check(self, e1, e2):
        s1 = syscalls.Syscalls[e1.nr](e1)
        s2 = syscalls.Syscalls[e2.nr](e2)
        if s1 is None or s2 is None:
            return False
        for callback in self.callbacks:
            ret = callback(s1, s2)
            if ret is None: continue
            return ret, s1, s2
        return False

    def generate(self, s1, s2):
        string = ""
        for generator in self.generators:
            string += 'attack %s %s %s %s\n' % (self.desc, s1.name, s2.name, 
                                                generator(s1, s2))
        return string

    def attack(self, p):
        if not os.path.exists("/.JAILED"):
            print >> sys.stderr, "The attacker is not jailed"
            return
        for attacker in self.attackers:
            attacker(p)

    def test(self, p):
        if not os.path.exists("/.JAILED"):
            print >> sys.stderr, "The tester is not jailed"
            return
        for tester in self.testers:
            if tester(p):
                print('Generic TOCTOU tester (%s): REPRODUCED' % self.desc)
                sys.exit(255)

        print('Generic TOCTOU tester (%s): PASSED' % self.desc)
        sys.exit(0)

    def __init__(self, desc, sys1, sys2, detail = "", callbacks = [], 
                 generators = [], attackers = [], testers = []):
        self.desc = desc
        self.sys1 = sys1
        self.sys2 = sys2
        self.detail = detail
        self.callbacks = callbacks
        self.generators = generators
        self.attackers = attackers
        self.testers = testers
        patterns.add(self)

################################################################
# Checkers

def path_checker(s1, s2):
    if s1.path != s2.path:
        return False

#################################################################
# Generators

def link_generator(s1, s2):
    return '%s %s' % s1.path, '/tmp/victim'

def deny_generator(s1, s2):
    return '%s' % s1.path

###############################################################
# Attackers

def link_attacker(p):
    if len(p) >= 4:
        os.remove(p[2])
        os.symlink(p[3], p[2])

def deny_attacker(p):
    if len(p) >= 3:
        os.remove(p[2])

##################################################################
# Pattern 1

def cb_check_file_write_link (s1, s2):
    if s1.belong_a([SYS_stat, SYS_stat64]):
        return True
    if s1.mode != fcntl.W_OK:
        return False
    if s2.is_a(SYS_open):
        return (s2.mode & (fcntl.O_WRONLY | fcntl.O_RDWR)) != 0

Pattern(sys1=SYS_Check, sys2=SYS_FileWrite,
        callbacks=[path_checker, cb_check_file_write_link],
        attackers=[link_attacker], generators=[link_generator],
        desc='Check-FileWrite-Link',
        detail='\
Check System Calls x File Writing System Calls, Attacked by Link \
Creation System Calls')

#######################################################################
# Pattern 2

def cb_check_file_read_link(s1, s2):
    if s1.belong_a([SYS_stat, SYS_stat64]):
        return True
    if s1.mode != fcntl.R_OK:
        return False
    if s2.is_a(SYS_open):
        return (s2.mode & (fcntl.O_RDONLY | fcntl.O_RDWR)) != 0

Pattern(sys1=SYS_Check, sys2=SYS_FileRead,
        callbacks=[path_checker, cb_check_file_read_link],
        attackers=[link_attacker], generators=[link_generator],
        desc='Check-FileRead-Link',
        detail='\
Check System Calls x File Reading System Calls, Attacked by Link Creation \
System Calls')

########################################################################
# Pattern 3

def cb_check_file_write_file_read_deny (s1, s2):
    return True

Pattern(sys1=SYS_Check, sys2=SYS_FileWrite.union(SYS_FileRead),
        callbacks=[path_checker, cb_check_file_write_file_read_deny],
        attackers=[deny_attacker], generators=[deny_generator],
        desc="Check-FileWrite-FileRead-Deny",
        detail='\
Check System Calls x File Usage System Calls, Attacked by Deny Access\
System Calls')

########################################################################
# Pattern 4

def cb_file_create_file_write_link (s1, s2):
    return True

Pattern(sys1=SYS_FileCreate, sys2=SYS_FileWrite,
        callbacks=[path_checker, cb_file_create_file_write_link],
        attackers=[link_attacker], generators=[link_generator],
        desc='FileCreat-FileWrite-Link',
        detail='\
File Creation System Calls x File Writing System Calls, Attacked by Link \
Creation System Calls')

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
        "FileWrite"  : ["chmod", "chown", "truncate", "open"],
        "FileRead"   : ["open", "execve"],
        "DirWrite"   : ["chmod", "chown", "open"],
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
            return False, s1, s2
        for callback in self.callbacks:
            ret = callback(s1, s2)
            if ret is None: continue
            return ret, s1, s2
        return False, s1, s2

    def generate(self, s1, s2):
        string = ""
        for generator in self.generators:
            string += 'attack %s %s %s %s\n' % (self.desc,
                                                s1.name, s2.name,
                                                generator(s1, s2))
        return string

    def attack(self, p):
        if not os.path.exists('/.JAILED'):
            print >> sys.stderr, "The attacker is not jailed"
            return
        for attacker in self.attackers:
            attacker(p)
        open('/.TEST', 'w').write('test %s %s' % (self.desc, ' '.join(p)))

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
    return '%s %s' % (s1.path, '/tmp/victim')

def deny_generator(s1, s2):
    return '%s' % s1.path

###############################################################
# Attackers

def link_attacker(p):
    if len(p) == 4:
        sys1, sys2, src, tgt = tuple(p)
        if os.path.exists(tgt):
            os.remove(tgt)
        f = open(tgt, 'w')
        if os.path.exists(src):
            f.write(open(src, 'r').read())
        f.close()
        os.remove(src)
        os.symlink(tgt, src)
        if sys2 == 'open' or sys2 == 'truncate':
            os.utime(tgt, (None, 0))
            p.append(0)
        elif sys2 == 'chmod':
            os.chmod(tgt, 0)
            p.append(str(os.stat(tgt).st_mode))
        elif sys2 == 'chown':
            os.chown(tgt, 0, 0)
            p.append('%s:%s' % (str(os.stat(tgt).st_uid),
                                str(os.stat(tgt).st_gid)))
        elif sys2 == 'link':
            p.append(str(os.stat(tgt).st_ino))

##############################################################
# Testers

def link_write_tester(p):
    if len(p) == 5:
        sys1, sys2, src, tgt, val = tuple(p)
        if sys2 == 'open' or sys2 == 'truncate':
            return val != str(os.stat(tgt).st_mtime)
        elif sys2 == 'chmod':
            return val != str(os.stat(tgt).st_mode)
        elif sys2 == 'chown':
            return val != '%s:%s' % (str(os.stat(tgt).st_uid),
                                     str(os.stat(tgt).st_gid))
        elif sys2 == 'link':
            return val != str(os.stat(tgt).st_ino)

def link_read_tester(p):
    if len(p) == 5:
        sys1, sys2, src, tgt, val = tuple(p)
        if sys2 == 'open' or sys2 == 'execve':
            return val != str(os.stat(tgt).st_atime)

##################################################################
# Pattern 1

def cb_check_file_write_link (s1, s2):
    if s1.belong_a([SYS_stat, SYS_stat64]):
        return True
    if s1.mode != fcntl.W_OK:
        return False
    if s2.is_a(SYS_open):
        return (s2.mode & (fcntl.O_WRONLY | fcntl.O_RDWR)) != 0
    return True

Pattern(sys1=SYS_Check, sys2=SYS_FileWrite,
        callbacks=[path_checker, cb_check_file_write_link],
        attackers=[link_attacker], 
        generators=[link_generator],
        testers=[link_write_tester],
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
    return True

Pattern(sys1=SYS_Check, sys2=SYS_FileRead,
        callbacks=[path_checker, cb_check_file_read_link],
        attackers=[link_attacker], 
        generators=[link_generator],
        testers=[link_read_tester],
        desc='Check-FileRead-Link',
        detail='\
Check System Calls x File Reading System Calls, Attacked by Link Creation \
System Calls')

########################################################################
# Pattern 3
def cb_file_create_file_write_link (s1, s2):
    if s1.is_a(SYS_open) and (s1.mode & fcntl.O_RDONLY) != 0:
        return False
    if s2.is_a(SYS_open) and (s2.mode & fcntl.O_RDONLY) != 0:
        return False
    return True


Pattern(sys1=SYS_FileCreate, sys2=SYS_FileWrite,
        callbacks=[path_checker, cb_file_create_file_write_link],
        attackers=[link_attacker], 
        generators=[link_generator],
        testers=[link_write_tester],
        desc='FileCreat-FileWrite-Link',
        detail='\
File Creation System Calls x File Writing System Calls, Attacked by Link \
Creation System Calls')

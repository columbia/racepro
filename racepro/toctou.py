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

class Pattern:
    def _callback_def(self, s1, s2):
        return False

    def _generator_def(self, s1, s2):
        return 'attack'

    def _attacker_def(self, args):
        pass

    def check(self, e1, e2):
        s1 = syscalls.Syscalls[e1.nr](e1)
        s2 = syscalls.Syscalls[e2.nr](e2)
        if s1 is None or s2 is None:
            return False
        return self.callback(s1, s2), s1, s2

    def __init__(self, desc, sys1, sys2, detail = "",
                 callback=_callback_def,
                 attacker=_attacker_def,
                 generator=_generator_def):
        self.desc = desc
        self.sys1 = sys1
        self.sys2 = sys2
        self.detail = detail
        self.callback = callback
        self.attacker = attacker
        self.generator = generator

##################################################################

patterns = set()

##################################################################
# Pattern 1

def cb_check_file_write_link (s1, s2):
    if s1.path != s2.path:
        return False
    if s1.belong_a([SYS_stat, SYS_stat64]):
        return True
    if s1.mode != fcntl.W_OK:
        return False
    if s2.is_a(SYS_open):
        return (s2.mode & (fcntl.O_WRONLY | fcntl.O_RDWR)) != 0
    return True

def at_check_file_write_link (p):
    if len(p) < 2:
        return
    os.remove(p[1])
    os.symlink(p[2], p[1])

def gn_check_file_write_link (s1, s2):
    return 'attack Check-FileWrite-Link %s /tmp/victim' % s1.path

check_file_write_link = \
"""Check System Calls x File Writing System Calls, Attacked by Link Creation
System Calls"""

patterns.add(Pattern(desc="Check-FileWrite-Link",
                     sys1=SYS_Check, sys2=SYS_FileWrite,
                     callback=cb_check_file_write_link,
                     attacker=at_check_file_write_link,
                     generator=gn_check_file_write_link,
                     detail=check_file_write_link))

#######################################################################
# Pattern 2

def cb_check_file_read_link(s1, s2):
    if s1.path != s2.path:
        return False
    if s1.belong_a([SYS_stat, SYS_stat64]):
        return True
    if s1.mode != fcntl.R_OK:
        return False
    if s2.is_a(SYS_open):
        return (s2.mode & (fcntl.O_RDONLY | fcntl.O_RDWR)) != 0
    return True

def at_check_file_read_link (p):
    if len(p) < 2:
        return
    os.remove(p[0])
    os.symlink(p[1], p[0])

def gn_check_file_read_link (s1, s2):
    return 'attack Check-FileRead-Link %s /tmp/victim' % s1.path

check_file_read_link = \
"""Check System Calls x File Reading System Calls, Attacked by Link Creation
System Calls"""

patterns.add(Pattern(desc="Check-FileRead-Link",
                     sys1=SYS_Check, sys2=SYS_FileRead,
                     callback=cb_check_file_read_link,
                     attacker=at_check_file_read_link,
                     generator=gn_check_file_read_link,
                     detail=check_file_read_link))

########################################################################
# Pattern 3

def cb_check_file_write_file_read_deny (s1, s2):
    if s1.path != s2.path:
        return False
    return True

def at_check_file_write_file_read_deny (p):
    if len(p) < 1:
        return
    os.remove(p[0])

def gn_check_file_write_file_read_deny (s1, s2):
    return 'attack Check-FileWrite-FileRead-Deny %s' % s1.path

check_file_write_file_read_deny = \
"""Check System Calls x File Usage System Calls, Attacked by Deny Access
System Calls"""

patterns.add(Pattern(desc="Check-FileWrite-FileRead-Deny",
                     sys1=SYS_Check, sys2=SYS_FileWrite.union(SYS_FileRead),
                     callback=cb_check_file_write_file_read_deny,
                     attacker=at_check_file_write_file_read_deny,
                     generator=gn_check_file_write_file_read_deny,
                     detail=check_file_write_file_read_deny))

########################################################################
# Pattern 4

def cb_file_create_file_write_link (s1, s2):
    if s1.path != s2.path:
        return False
    return True

def at_file_create_file_write_link (s1, s2):
    if len(p) < 2:
        return
    os.remove(p[0])
    os.symlink(p[1], p[0])

def gn_file_create_file_write_link (s1, s2):
    return 'attack FileCreate-FileWrite-Link %s /tmp/victim' % s1.path

file_create_file_write_link = \
"""File Creation System Calls x File Writing System Calls, Attacked by Link
Creation System Calls"""

patterns.add(Pattern(desc="FileCreat-FileWrite-Link",
                     sys1=SYS_FileCreate, sys2=SYS_FileWrite,
                     callback=cb_file_create_file_write_link,
                     attacker=at_file_create_file_write_link,
                     generator=gn_file_create_file_write_link,
                     detail=file_create_file_write_link))

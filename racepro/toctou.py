import os
import pwd
import sys
import stat
import logging

import syscalls
import execute
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
        "LinkWrite"  : ["link", "symlink"],
        "LinkRead"   : ["readlink"],
        "DirWrite"   : ["chmod", "chown", "open"],
        "DirRead"    : ["mount", "chdir", "chroot", "open", "execve"],
        "ProcCreat"  : ["fork", "vfork", "clone"],
        "DirChange"  : ["chdir", "chroot"],
        })

##################################################################

patterns  = list()
attackers = list()
queriers  = list()

##################################################################

def event_to_syscall(event):
    """Convert a syscall event to Syscall object"""
    syscall = syscalls.Syscalls[event.nr](event)
    return syscall

###############################################################################

class Pattern:
    def check(self, event1, event2):
        """Check if the event pair causes toctou racing"""
        s1 = event_to_syscall(event1)
        s2 = event_to_syscall(event2)
        if not (s1 and s1):
            return False

        for callback in self.callbacks:
            ret = callback(s1, s2)
            if ret is not None:
                return ret

        return False

    def generate(self, event1, event2):
        """Generate string to run in the attacker"""
        s1 = event_to_syscall(event1)
        s2 = event_to_syscall(event2)
        if not (s1 and s1):
            return False

        attack_strings = list()
        for attacker in self.attackers:
            string = attacker.generate(s1, s2)
            if string != "":
                attack_strings.append(string)

        return '\n'.join(attack_strings)

    def __init__(self, desc, syscallset1, syscallset2,
                 callbacks = [], attackers = []):
        self.desc = desc
        self.syscallset1 = syscallset1
        self.syscallset2 = syscallset2
        self.callbacks = callbacks
        self.attackers = attackers

##############################################################################

class Attacker:
    def generate(self, s1, s2):
        """To be run by the attacker"""
        a = '%s' % self.generator(s1, s2)
        return 'attack %s %s %s %s' % (self.desc, s1.name, s2.name, a)

    def pre_attack(self, params):
        """To be run pre-attacker callback"""
        assert execute.is_jailed(), 'Must be jailed for pre-attack'
        self.pre_attacker(params)
        a = 'test %s %s' % (self.desc, ' '.join(params))
        open('/.TEST', 'w').write('%s' % a)

    def attack(self, params):
        """To be run attacker callback"""
        assert execute.is_jailed(), 'Must be jailed for attack'
        self.attacker(params)

    def test(self, params):
        """To be run tester callback"""
        assert execute.is_jailed(), 'Must be jailed for tester'
        return self.tester(params)

    def __init__(self, desc,
                 generator = None, pre_attacker = None,
                 attacker = None, tester = None):
        self.desc = desc
        self.generator  = generator
        self.pre_attacker = pre_attacker
        self.attacker = attacker
        self.tester = tester

###############################################################################

class NodeBookmark:
    def need_bookmark(self, event, before=False, after=False):
        return False

    def upon_bookmark(self, event, exe, before=False, after=False):
        assert False

    def debug(self, event):
        pass

    def __init__(self):
        pass

##############################################################################

def get_resource_path(s):
    if hasattr(s.node, 'file_info') and 'path' in s.node.file_info:
        return s.node.file_info['path']

    syscalls_info_path = [
        SYS_stat, SYS_stat64, SYS_access, SYS_creat,
        SYS_mknod, SYS_open, SYS_mkdir, SYS_rmdir, SYS_chmod,
        SYS_chown, SYS_truncate, SYS_execve, SYS_readlink,
        SYS_chdir, SYS_chroot, SYS_unlink,
        ]

    syscalls_info_oldname = [
        SYS_rename, SYS_link, SYS_symlink,
        ]

    syscalls_info_dir = [
        SYS_mount,
        ]

    if s.belongs_to(syscalls_info_path):
        return s.path
    elif s.belongs_to(syscalls_info_oldname):
        return s.oldname
    elif s.belongs_to(syscalls_info_dir):
        return s.dir

#############################################################################

class NodeBookmarkFile(NodeBookmark):
    def need_bookmark(self, event, before=False, after=False):
        assert (before and not after) or (after and not before)

        syscalls_node_file = set([
            SYS_Check, SYS_FileCreate, SYS_LinkCreate, SYS_DirCreate,
            SYS_FileRemove, SYS_LinkRemove, SYS_DirRemove, SYS_FileWrite,
            SYS_FileRead, SYS_LinkWrite, SYS_LinkRead, SYS_DirWrite,
            SYS_DirRead
            ])

        if before:
            return event.nr in syscalls_node_file
        else:
            return False

    def upon_bookmark(self, event, exe, before=False, after=False):
        assert (before and not after) or (after and not before)

        syscall = event_to_syscall(event)
        if not syscall:
            return

        path = get_resource_path(syscall)

        assert path, 'Path expected for syscall %s ?' % syscall
        assert before

        def get_real_pid(event, exe):
            return exe.pids[event.proc.pid]

        def get_proc_info(proc, pid, key, callback):
            return callback('%s/%d/%s' % (proc, pid, key))

        pid = get_real_pid(event, exe)
        proc = exe.chroot + '/proc'

        file_info = dict()
        file_info['cwd'] = get_proc_info(proc, pid, 'cwd', os.readlink)
        file_info['root'] = get_proc_info(proc, pid, 'root', os.readlink)

        def set_event_file_info(path, prefix):
            if os.path.exists(path):
                file_stat = os.stat(path)
                for attr in dir(file_stat):
                    if attr.startswith('st_'):
                        file_info[prefix + attr] = getattr(file_stat, attr)

        path = os.path.join(file_info['cwd'], get_resource_path(syscall))
        set_event_file_info(os.path.normpath(path), '')

        path = os.path.dirname(path)
        set_event_file_info(os.path.normpath(path), 'dir_')

        event.file_info = file_info

    def debug(self, event):
        if hasattr(event, 'file_info'):
            logging.debug('    %s' % event)
            for key, value in event.file_info.items():
                logging.debug('        %s : %s' % (key, value))

queriers.append(NodeBookmarkFile())

#############################################################################

ignored_prefixs = ['/dev', '/proc', '/lib', '/usr/lib', '/bin', '/usr/bin',
                   '/sbin', '/usr/sbin', '/etc/ld.so.cache']

def path_checker(s1, s2):
    path1 = get_resource_path(s1)
    path2 = get_resource_path(s2)
    if not path1 or not path2 or path1 != path2:
        return False
    for prefix in ignored_prefixs:
        if os.path.normpath(path1).startswith(prefix):
            return False

    if hasattr(s2.node, 'file_info') and 'dir_st_mode' in s2.node.file_info:
        if not s2.node.file_info['dir_st_mode'] & stat.S_IWOTH:
            return False

def file_checker(s1, s2):
    if hasattr(s1.node, 'file_info') and 'st_flags' in s1.node.file_info:
        if s1.node.file_info['st_flags'] & stat.stat.S_IFDIR:
            return False

def dir_checker(s1, s2):
    if hasattr(s1.node, 'file_info') and 'st_flags' in s1.node.file_info:
        if not (s1.node.file_info['st_flags'] & stat.stat.S_IFDIR):
            return False

############################################################################

def link_attack_generator(s1, s2):
    return '%s %s' % (get_resource_path(s1), '/tmp/victim')

def link_pre_attacker(p):
    if len(p) == 4:
        sys1, sys2, src, tgt = tuple(p)
        if os.path.exists(tgt):
            os.remove(tgt)
        f = open(tgt, 'w')
        if os.path.exists(src):
            f.write(open(src, 'r').read())
        f.close()
        if sys2 == 'open' or sys2 == 'truncate':
            os.utime(tgt, (0, 0))
            p.append('0')
        elif sys2 == 'chmod':
            os.chmod(tgt, 0)
            p.append(str(os.stat(tgt).st_mode))
        elif sys2 == 'chown':
            os.chown(tgt, 0, 0)
            p.append('%s:%s' % (str(os.stat(tgt).st_uid),
                                str(os.stat(tgt).st_gid)))
        elif sys2 == 'link':
            p.append(str(os.stat(tgt).st_ino))

def link_attacker(p):
    if len(p) == 4:
        sys1, sys2, src, tgt = tuple(p)
        os.remove(src)
        os.symlink(tgt, src)


################################################################
# Attackers
# Naming rules: <Action>-<Cutoff Syscall>

#################################################################
# Attacker 1: LinkCreat-FileRead

def link_for_read_tester(p):
    if len(p) == 5:
        sys1, sys2, src, tgt, val = tuple(p)
        if sys2 == 'open' or sys2 == 'execve':
            return val != str(os.stat(tgt).st_atime)

attacker_LinkCreat_FileRead = Attacker(desc="LinkCreat-FileRead",
    generator = link_attack_generator, pre_attacker = link_pre_attacker,
    attacker = link_attacker, tester = link_for_read_tester)

attackers.append(attacker_LinkCreat_FileRead)

#################################################################
# Attacker 2: LinkCreat-FileWrite

def link_for_write_tester(p):
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

attacker_LinkCreat_FileWrite = Attacker(desc="LinkCreat-FileWrite",
    generator = link_attack_generator, pre_attacker = link_pre_attacker,
    attacker = link_attacker, tester = link_for_write_tester)

attackers.append(attacker_LinkCreat_FileWrite)

#################################################################
# Patterns
# Naming rules: <First Syscall>-<Second Syscall>

##################################################################
# Pattern 1: Check-FileWrite

def cb_check_file_write_link (s1, s2):
    if s1.belongs_to([SYS_stat, SYS_stat64]):
        return True
    if s1.is_a(SYS_access) and \
       s1.mode != fcntl.W_OK and s1.mode != fcntl.F_OK:
        return False
    if s2.is_a(SYS_open):
        return fcntl.has_W(s2.flag)
    return True

patterns.append(Pattern(desc='Check-FileWrite', syscallset1=SYS_Check,
    syscallset2=SYS_FileWrite, callbacks=[path_checker, file_checker,
    cb_check_file_write_link], attackers=[attacker_LinkCreat_FileWrite]))

#######################################################################
# Pattern 2: Check-FileRead

def cb_check_file_read_link(s1, s2):
    if s1.belongs_to([SYS_stat, SYS_stat64]):
        return True
    if s1.is_a(SYS_access) and \
       s1.mode != fcntl.R_OK and s1.mode != fcntl.F_OK:
        return False
    if s2.is_a(SYS_open):
        return fcntl.has_R(s2.flag)
    return True

patterns.append(Pattern(desc='Check-FileRead', syscallset1=SYS_Check,
    syscallset2=SYS_FileRead, callbacks=[path_checker, file_checker,
    cb_check_file_read_link], attackers=[attacker_LinkCreat_FileRead]))

########################################################################
# Pattern 3: FileCreat-FileWrite

def cb_file_create_file_write_link (s1, s2):
    if s1.is_a(SYS_open) and fcntl.is_R(s1.flag):
        return False
    if s2.is_a(SYS_open) and fcntl.is_R(s2.flag):
        return False
    return True

patterns.append(Pattern(desc='FileCreat-FileWrite', syscallset1=SYS_FileCreate,
    syscallset2=SYS_FileWrite, callbacks=[path_checker, file_checker,
    cb_file_create_file_write_link], attackers=[attacker_LinkCreat_FileWrite]))

########################################################################
# Pattern 4: FileCreat-FileRead

def cb_file_create_file_read_link (s1, s2):
    if s1.is_a(SYS_open) and fcntl.is_R(s1.flag):
        return False
    if s2.is_a(SYS_open) and fcntl.is_W(s2.flag):
        return False
    return True

patterns.append(Pattern(desc='FileCreat-FileRead', syscallset1=SYS_FileCreate,
    syscallset2=SYS_FileRead, callbacks=[path_checker, file_checker,
    cb_file_create_file_read_link], attackers=[attacker_LinkCreat_FileRead]))

########################################################################
# Pattern 5: LinkRead-FileRead

def cb_link_read_file_read_link (s1, s2):
    if s2.is_a(SYS_open) and fcntl.is_W(s2.flag):
        return False
    return True

patterns.append(Pattern(desc='LinkRead-FileRead', syscallset1=SYS_LinkRead,
    syscallset2=SYS_FileRead, callbacks=[path_checker, file_checker,
    cb_link_read_file_read_link], attackers=[attacker_LinkCreat_FileWrite]))

########################################################################
# Pattern 6: LinkRead-FileWrite

def cb_link_read_file_write_link (s1, s2):
    if s2.is_a(SYS_open) and fcntl.is_R(s2.flag):
        return False
    return True

patterns.append(Pattern(desc='LinkRead-FileWrite', syscallset1=SYS_LinkRead,
    syscallset2=SYS_FileWrite, callbacks=[path_checker, file_checker,
    cb_link_read_file_write_link], attackers=[attacker_LinkCreat_FileWrite]))

########################################################################
# helpers to attack, test, explain
def _attack(attacker, params):
    print >> sys.stderr, "perform %s attack..." % attacker.desc

    try:
        attacker.pre_attack(params)
    except:
        print >> sys.stderr, "Unable to attack:", sys.exc_info()[1]
        return

    pid = os.fork()
    if pid == 0:
        try:
            pw = pwd.getpwnam("racepro")
            os.seteuid(pw.pw_uid)
        except:
            print >> sys.stderr, "Unable to run non-root:", sys.exc_info()[1]

        try:
            attacker.attack(params)
        except:
            print >> sys.stderr, "Unable to attack:", sys.exc_info()[1]
        else:
            print >> sys.stderr, "Attack succeeds"

        os._exit(0)
    else:
        os.waitpid(pid, 0)

def attack_toctou(desc, params):
    for attacker in attackers:
        if attacker.desc == desc:
            _attack(attacker, params)

def test_toctou(desc, params):
    ret = False
    for attacker in attackers:
        if attacker.desc == desc:
            print >> sys.stdout, "perform %s test..." % desc
            if attacker.test(params):
                ret = True
    return ret

import os
import pwd
import sys
import stat
import logging
import tempfile

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
        return 'attack %s %s' % (self.desc, a)

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

def consider_path(path):
    bad_prefix = ['/proc', '/dev', '/tmp/isolate']
    for prefix in bad_prefix:
        if path.startswith(prefix):
            return False
    return True

#############################################################################

class NodeBookmarkFile(NodeBookmark):
    def need_bookmark(self, event, before=False, after=False):
        assert (before and not after) or (after and not before)

        syscalls_node_file = set().union(
            SYS_Check, SYS_FileCreate, SYS_LinkCreate, SYS_DirCreate,
            SYS_FileRemove, SYS_LinkRemove, SYS_DirRemove, SYS_FileWrite,
            SYS_FileRead, SYS_LinkWrite, SYS_LinkRead, SYS_DirWrite,
            SYS_DirRead
            )

        if before:
            if event.nr in syscalls_node_file:
                syscall = event_to_syscall(event)
                path = get_resource_path(syscall)
                return consider_path(path)

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

        cwd = get_proc_info(proc, pid, 'cwd', os.readlink)
        root = get_proc_info(proc, pid, 'root', os.readlink)
        cwd = os.path.join('/', os.path.relpath(cwd, root))
        root = os.path.join('/', os.path.relpath(root, exe.chroot))

        file_info = dict()
        file_info['cwd'] = os.path.normpath(cwd)
        file_info['root'] = os.path.normpath(root)

        def set_event_file_info(path, prefix):
            file_info[prefix + 'path'] = os.path.normpath(path)
            if os.path.exists(exe.chroot + path):
                file_stat = os.stat(exe.chroot + path)
                for attr in dir(file_stat):
                    if attr.startswith('st_'):
                        file_info[prefix + attr] = getattr(file_stat, attr)

        path = os.path.join(cwd, get_resource_path(syscall))
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

def perm_checker(s1, s2):
    path1 = get_resource_path(s1)
    path2 = get_resource_path(s2)
    if path1 != path2 or not consider_path(path2):
        return False
    if hasattr(s2.node, 'file_info') and 'dir_st_mode' in s2.node.file_info:
        if not s2.node.file_info['dir_st_mode'] & stat.S_IWOTH:
            return False
    return None

def file_checker(s1, s2):
    if hasattr(s2.node, 'file_info') and 'st_flags' in s2.node.file_info:
        if s2.node.file_info['st_flags'] & stat.stat.S_IFDIR:
            return False
    return None

def dir_checker(s1, s2):
    if hasattr(s2.node, 'file_info') and 'st_flags' in s2.node.file_info:
        if not (s2.node.file_info['st_flags'] & stat.stat.S_IFDIR):
            return False
    return None

############################################################################

def link_attack_generator(s1, s2):
    if (s2.is_a(SYS_open) and fcntl.has_W(s2.flag)) or s2.is_a(SYS_truncate):
        key = 'mtime'
    elif (s2.is_a(SYS_open) and fcntl.has_R(s2.flag)) or s2.is_a(SYS_execve):
        key = 'atime'
    elif s2.is_a(SYS_chmod):
        key = 'mode'
    elif s2.is_a(SYS_chown):
        key = 'owner'
    elif s2.is_a(SYS_link):
        key = 'ino'
    else:
        assert False, 'The system call is not handled'

    return '%s %s' % (get_resource_path(s2), key)

def link_pre_attacker(param):
    assert len(param) == 2

    src, key = param
    tgt = os.path.join(tempfile.mkdtemp(dir='/tmp'), 'victiom')

    f = open(tgt, 'w')
    if os.path.exists(src):
        f.write(open(src, 'r').read())
        os.chmod(tgt, os.stat(src).st_mode)
        os.chown(tgt, os.stat(src).st_uid, os.stat(src).st_gid)
    f.close()
    param.append(tgt)

    if key == 'mtime' or key == 'atime':
        os.utime(tgt, (0, 0))
    elif key == 'mode':
        os.chmod(tgt, 0)
    elif key == 'owner':
        os.chown(tgt, 0, 0)
    elif key == 'ino':
        param.append(str(os.stat(tgt).st_ino))

def link_attacker(param):
    assert len(param) == 3
    src, key, tgt = param

    # isn't it ironic to have a TOCTOU race here ourselves ?!
    if os.path.exists(src):
        os.remove(src)

    os.symlink(tgt, src)

def link_tester(param):
    assert len(param) >= 3

    src, key, tgt = param[:3]

    if key == 'atime':
        return os.stat(tgt).st_atime != 0
    if key == 'mtime':
        return os.stat(tgt).st_mtime != 0
    if key == 'mode':
        return os.stat(tgt).st_mode != 0
    if key == 'owner':
        return os.stat(tgt).st_uid !=0 or os.stat(tgt).st_gid != 0
    if key == 'ino':
        return param[3] != str(os.stat(tgt).st_ino)

    assert False, 'The system call is not handled'

################################################################
# Attackers
# Naming rules: <Action>-<Cutoff Syscall>

# Attacker 1: LinkCreate

attacker_LinkCreate = Attacker(desc="LinkCreate",
                               generator = link_attack_generator,
                               pre_attacker = link_pre_attacker,
                               attacker = link_attacker,
                               tester = link_tester)

attackers.append(attacker_LinkCreate)

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
    syscallset2=SYS_FileWrite, callbacks=[perm_checker, file_checker,
    cb_check_file_write_link], attackers=[attacker_LinkCreate]))

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
    syscallset2=SYS_FileRead, callbacks=[perm_checker, file_checker,
    cb_check_file_read_link], attackers=[attacker_LinkCreate]))

########################################################################
# Pattern 3: FileCreat-FileWrite

def cb_file_create_file_write_link (s1, s2):
    if s1.is_a(SYS_open) and fcntl.is_R(s1.flag):
        return False
    if s2.is_a(SYS_open) and fcntl.is_R(s2.flag):
        return False
    return True

patterns.append(Pattern(desc='FileCreat-FileWrite', syscallset1=SYS_FileCreate,
    syscallset2=SYS_FileWrite, callbacks=[perm_checker, file_checker,
    cb_file_create_file_write_link], attackers=[attacker_LinkCreate]))

########################################################################
# Pattern 4: FileCreat-FileRead

def cb_file_create_file_read_link (s1, s2):
    if s1.is_a(SYS_open) and fcntl.is_R(s1.flag):
        return False
    if s2.is_a(SYS_open) and fcntl.is_W(s2.flag):
        return False
    return True

patterns.append(Pattern(desc='FileCreat-FileRead', syscallset1=SYS_FileCreate,
    syscallset2=SYS_FileRead, callbacks=[perm_checker, file_checker,
    cb_file_create_file_read_link], attackers=[attacker_LinkCreate]))

########################################################################
# Pattern 5: LinkRead-FileRead

def cb_link_read_file_read_link (s1, s2):
    if s2.is_a(SYS_open) and fcntl.is_W(s2.flag):
        return False
    return True

patterns.append(Pattern(desc='LinkRead-FileRead', syscallset1=SYS_LinkRead,
    syscallset2=SYS_FileRead, callbacks=[perm_checker, file_checker,
    cb_link_read_file_read_link], attackers=[attacker_LinkCreate]))

########################################################################
# Pattern 6: LinkRead-FileWrite

def cb_link_read_file_write_link (s1, s2):
    if s2.is_a(SYS_open) and fcntl.is_R(s2.flag):
        return False
    return True

patterns.append(Pattern(desc='LinkRead-FileWrite', syscallset1=SYS_LinkRead,
    syscallset2=SYS_FileWrite, callbacks=[perm_checker, file_checker,
    cb_link_read_file_write_link], attackers=[attacker_LinkCreate]))

########################################################################
# helpers to attack, test, explain
def _attack(attacker, params):
    print >> sys.stderr, "perform %s attack..." % attacker.desc

    try:
        attacker.pre_attack(params)
    except OSError:
        print >> sys.stderr, "Unable to pre-attack:", sys.exc_info()[1]
        return

    pid = os.fork()
    if pid == 0:
        try:
            pw = pwd.getpwnam("racepro")
            os.seteuid(pw.pw_uid)
        except OSError:
            print >> sys.stderr, "Unable to run non-root:", sys.exc_info()[1]

        try:
            attacker.attack(params)
        except OSError:
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

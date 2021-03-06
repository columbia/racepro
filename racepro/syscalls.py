import scribe
import unistd


def int32(x):
    if x > 0xFFFFFFFF:
        raise OverflowError

    if x > 0x7FFFFFFF:
        x = int(0x100000000-x)
        if x < 2147483648:
            return -x
        else:
            return -2147483648
    return x

class Syscall(object):
    def __init__(self, node):
        self.node = node
        self.args = self._getargs()

    def _getargs(self):
        # Put arguments of a single system call into a list. Be careful when
        # trying to place the string argument at the right place
        syscall = self.node

        args = None
        for e in syscall.children:
            if e.is_a(scribe.EventRegs):
                args = [e.regs['ebx'], e.regs['ecx'], e.regs['edx'],
                        e.regs['esi'], e.regs['edi']]
                break
        if args is None:
            raise SYSTypeError

        for e in syscall.children:
            if e.is_a(scribe.EventDataExtra) and \
                e.data_type == scribe.SCRIBE_DATA_INPUT | \
                               scribe.SCRIBE_DATA_STRING:
                for i, arg in enumerate(args):
                    if int32(args[i]) == int32(e.user_ptr):
                        args[i] = e.data

        return args

    def is_a(self, klass):
        return isinstance(self, klass)

    def belongs_to(self, klass_list):
        for klass in klass_list:
            if isinstance(self, klass):
                return True
        return False


SyscallDefs = {
'restart_syscall'        : [],
'exit'                   : ['error_code'],
'fork'                   : [],
'read'                   : ['fd', 'buf', 'count'],
'write'                  : ['fd', 'buf', 'count'],
'open'                   : ['path', 'flag', 'mode'],
'close'                  : ['fd'],
'waitpid'                : ['pid', 'stat_addr', 'options'],
'creat'                  : ['path', 'mode'],
'link'                   : ['oldname', 'newname'],
'unlink'                 : ['path'],
'execve'                 : ['path'],
'chdir'                  : ['path'],
'time'                   : ['tloc'],
'mknod'                  : ['path', 'mode', 'dev'],
'chmod'                  : ['path', 'mode'],
'lchown'                 : ['path', 'user', 'group'],
'break'                  : [],
'oldstat'                : [],
'lseek'                  : ['fd', 'offset', 'origin'],
'getpid'                 : [],
'mount'                  : ['dev', 'dir', 'type', 'flag', 'data'],
'umount'                 : ['name', 'flag'],
'setuid'                 : ['uid'],
'getuid'                 : [],
'stime'                  : ['tptr'],
'ptrace'                 : ['request', 'pid', 'addr', 'data'],
'alarm'                  : ['seconds'],
'oldfstat'               : [],
'pause'                  : [],
'utime'                  : ['path', 'times'],
'stty'                   : [],
'gtty'                   : [],
'access'                 : ['path', 'mode'],
'nice'                   : ['increment'],
'ftime'                  : [],
'sync'                   : [],
'kill'                   : ['pid', 'sig'],
'rename'                 : ['oldname', 'newname'],
'mkdir'                  : ['path', 'mode'],
'rmdir'                  : ['path'],
'dup'                    : ['fildes'],
'pipe'                   : ['fildes'],
'times'                  : ['tbuf'],
'prof'                   : [],
'brk'                    : ['brk'],
'setgid'                 : ['gid'],
'getgid'                 : [],
'signal'                 : ['sig', 'handler'],
'geteuid'                : [],
'getegid'                : [],
'acct'                   : ['name'],
'umount2'                : ['path', 'mode'],
'lock'                   : [],
'ioctl'                  : ['fd', 'cmd', 'arg'],
'fcntl'                  : ['fd', 'cmd', 'arg'],
'mpx'                    : [],
'setpgid'                : ['pid', 'pgid'],
'ulimit'                 : [],
'oldolduname'            : [],
'umask'                  : ['mask'],
'chroot'                 : ['path'],
'ustat'                  : ['dev', 'ubuf'],
'dup2'                   : ['oldfd', 'newfd'],
'getppid'                : [],
'getpgrp'                : [],
'setsid'                 : [],
'sigaction'              : [],
'sgetmask'               : [],
'ssetmask'               : ['newmask'],
'setreuid'               : ['ruid', 'euid'],
'setregid'               : ['rgid', 'egid'],
'sigsuspend'             : [],
'sigpending'             : ['set'],
'sethostname'            : ['name', 'len'],
'setrlimit'              : ['resource', 'rlim'],
'getrlimit'              : ['resource', 'rlim'],
'getrusage'              : ['who', 'ru'],
'gettimeofday'           : ['tv', 'tz'],
'settimeofday'           : ['tv', 'tz'],
'getgroups'              : ['gidsetsize', 'grouplist'],
'setgroups'              : ['gidsetsize', 'grouplist'],
'select'                 : ['fd', 'inp', 'outp', 'exp', 'tvp'],
'symlink'                : ['oldname', 'newname'],
'oldlstat'               : [],
'readlink'               : ['path', 'buf', 'bufsiz'],
'uselib'                 : ['library'],
'swapon'                 : ['specialfile', 'flag'],
'reboot'                 : ['magic1', 'magic2', 'cmd', 'arg'],
'readdir'                : [],
'mmap'                   : [],
'munmap'                 : ['addr', 'len'],
'truncate'               : ['path', 'length'],
'ftruncate'              : ['fd', 'length'],
'fchmod'                 : ['fd', 'mode'],
'fchown'                 : ['fd', 'user', 'group'],
'getpriority'            : ['which', 'who'],
'setpriority'            : ['which', 'who', 'niceval'],
'profil'                 : [],
'statfs'                 : ['path', 'buf'],
'fstatfs'                : ['fd', 'buf'],
'ioperm'                 : ['from', 'num', 'on'],
'socketcall'             : [],
'syslog'                 : ['type', 'buf', 'len'],
'setitimer'              : ['which', 'value', 'ovalue'],
'getitimer'              : ['which', 'value'],
'stat'                   : ['path', 'statbuf'],
'lstat'                  : ['path', 'statbuf'],
'fstat'                  : ['fd', 'statbuf'],
'olduname'               : [],
'iopl'                   : [],
'vhangup'                : [],
'idle'                   : [],
'vm86old'                : [],
'wait4'                  : ['pid', 'stat_addr', 'options', 'ru'],
'swapoff'                : ['specialfile'],
'sysinfo'                : ['info'],
'ipc'                    : ['call', 'first', 'second', 'third', 'ptr', 'fifth'],
'fsync'                  : ['fd'],
'sigreturn'              : [],
'clone'                  : [],
'setdomainname'          : ['name', 'len'],
'uname'                  : [],
'modify_ldt'             : [],
'adjtimex'               : ['txc_p'],
'mprotect'               : ['start', 'len', 'prot'],
'sigprocmask'            : ['how', 'set', 'oset'],
'create_module'          : [],
'init_module'            : ['umod', 'len', 'uarg'],
'delete_module'          : ['name_user', 'flag'],
'get_kernel_syms'        : [],
'quotactl'               : ['cmd', 'special', 'id', 'addr'],
'getpgid'                : ['pid'],
'fchdir'                 : ['fd'],
'bdflush'                : ['func', 'data'],
'sysfs'                  : ['option', 'arg1', 'arg2'],
'personality'            : ['personality'],
'afs_syscall'            : [],
'setfsuid'               : ['uid'],
'setfsgid'               : ['gid'],
'_llseek'                : [],
'getdents'               : ['fd', 'dirent', 'count'],
'_newselect'             : [],
'flock'                  : ['fd', 'cmd'],
'msync'                  : ['start', 'len', 'flag'],
'readv'                  : ['fd', 'vec', 'vlen'],
'writev'                 : ['fd', 'vec', 'vlen'],
'getsid'                 : ['pid'],
'fdatasync'              : ['fd'],
'_sysctl'                : [],
'mlock'                  : ['start', 'len'],
'munlock'                : ['start', 'len'],
'mlockall'               : ['flag'],
'munlockall'             : [],
'sched_setparam'         : ['pid', 'param'],
'sched_getparam'         : ['pid', 'param'],
'sched_setscheduler'     : ['pid', 'policy', 'param'],
'sched_getscheduler'     : ['pid'],
'sched_yield'            : [],
'sched_get_priority_max' : ['policy'],
'sched_get_priority_min' : ['policy'],
'sched_rr_get_interval'  : ['pid', 'interval'],
'nanosleep'              : ['rqtp', 'rmtp'],
'mremap'                 : ['addr', 'old_len', 'new_len', 'flags', 'new_addr'],
'setresuid'              : ['ruid', 'euid', 'suid'],
'getresuid'              : ['ruid', 'euid', 'suid'],
'vm86'                   : [],
'query_module'           : [],
'poll'                   : ['ufds', 'nfds', 'timeout'],
'nfsservctl'             : ['cmd', 'arg', 'res'],
'setresgid'              : ['rgid', 'egid', 'sgid'],
'getresgid'              : ['rgid', 'egid', 'sgid'],
'prctl'                  : ['option', 'arg2', 'arg3', 'arg4', 'arg5'],
'rt_sigreturn'           : [],
'rt_sigaction'           : [],
'rt_sigprocmask'         : ['how', 'set', 'oset', 'sigsetsize'],
'rt_sigpending'          : ['set', 'sigsetsize'],
'rt_sigtimedwait'        : ['uthese', 'uinfo', 'uts', 'sigsetsize'],
'rt_sigqueueinfo'        : ['pid', 'sig', 'uinfo'],
'rt_sigsuspend'          : [],
'pread64'                : ['fd', 'buf', 'count', 'pos'],
'pwrite64'               : ['fd', 'buf', 'count', 'pos'],
'chown'                  : ['path', 'user', 'group'],
'getcwd'                 : ['buf', 'size'],
'capget'                 : ['header', 'dataptr'],
'capset'                 : ['header', 'data'],
'sigaltstack'            : [],
'sendfile'               : ['out_fd', 'in_fd', 'offset', 'count'],
'getpmsg'                : [],
'putpmsg'                : [],
'vfork'                  : [],
'ugetrlimit'             : [],
'mmap2'                  : [],
'truncate64'             : ['path', 'length'],
'ftruncate64'            : ['fd', 'length'],
'stat64'                 : ['path', 'statbuf'],
'lstat64'                : ['path', 'statbuf'],
'fstat64'                : ['fd', 'statbuf'],
'lchown32'               : [],
'getuid32'               : [],
'getgid32'               : [],
'geteuid32'              : [],
'getegid32'              : [],
'setreuid32'             : [],
'setregid32'             : [],
'getgroups32'            : [],
'setgroups32'            : [],
'fchown32'               : [],
'setresuid32'            : [],
'getresuid32'            : [],
'setresgid32'            : [],
'getresgid32'            : [],
'chown32'                : [],
'setuid32'               : [],
'setgid32'               : [],
'setfsuid32'             : [],
'setfsgid32'             : [],
'pivot_root'             : ['new_root', 'put_old'],
'mincore'                : ['start', 'len', 'vec'],
'madvise'                : ['start', 'len', 'behavior'],
'getdents64'             : ['fd', 'dirent', 'count'],
'fcntl64'                : ['fd', 'cmd', 'arg'],
'gettid'                 : [],
'readahead'              : ['fd', 'offset', 'count'],
'setxattr'               : ['path', 'name', 'value', 'size', 'flag'],
'lsetxattr'              : ['path', 'name', 'value', 'size', 'flag'],
'fsetxattr'              : ['fd', 'name', 'value', 'size', 'flag'],
'getxattr'               : ['path', 'name', 'value', 'size'],
'lgetxattr'              : ['path', 'name', 'value', 'size'],
'fgetxattr'              : ['fd', 'name', 'value', 'size'],
'listxattr'              : ['path', 'list', 'size'],
'llistxattr'             : ['path', 'list', 'size'],
'flistxattr'             : ['fd', 'list', 'size'],
'removexattr'            : ['path', 'name'],
'lremovexattr'           : ['path', 'name'],
'fremovexattr'           : ['fd', 'name'],
'tkill'                  : ['pid', 'sig'],
'sendfile64'             : ['out_fd', 'in_fd', 'offset', 'count'],
'futex'                  : ['uaddr', 'op', 'val', 'utime', 'uaddr2', 'val3'],
'sched_setaffinity'      : ['pid', 'len', 'user_mask_ptr'],
'sched_getaffinity'      : ['pid', 'len', 'user_mask_ptr'],
'set_thread_area'        : [],
'get_thread_area'        : [],
'io_setup'               : ['nr_reqs', 'ctx'],
'io_destroy'             : ['ctx'],
'io_getevents'           : ['ctx_id', 'min_nr', 'nr', 'events', 'timeout'],
'io_submit'              : [],
'io_cancel'              : ['ctx_id', 'iocb', 'result'],
'fadvise64'              : ['fd', 'offset', 'len', 'advice'],
'exit_group'             : ['error_code'],
'lookup_dcookie'         : ['cookie64', 'buf', 'len'],
'epoll_create'           : ['size'],
'epoll_ctl'              : ['epfd', 'op', 'fd', 'event'],
'epoll_wait'             : ['epfd', 'events', 'maxevents', 'timeout'],
'remap_file_pages'       : ['start', 'size', 'prot', 'pgoff', 'flag'],
'set_tid_address'        : ['tidptr'],
'timer_create'           : ['which_clock', 'timer_event_spec', 'created_timer_id'],
'timer_settime'          : ['timer_id', 'flag', 'new_setting', 'old_setting'],
'timer_gettime'          : ['timer_id', 'setting'],
'timer_getoverrun'       : ['timer_id'],
'timer_delete'           : ['timer_id'],
'clock_settime'          : ['which_clock', 'tp'],
'clock_gettime'          : ['which_clock', 'tp'],
'clock_getres'           : ['which_clock', 'tp'],
'clock_nanosleep'        : ['which_clock', 'flag', 'rqtp', 'rmtp'],
'statfs64'               : ['path', 'sz', 'buf'],
'fstatfs64'              : ['fd', 'sz', 'buf'],
'tgkill'                 : ['tgid', 'pid', 'sig'],
'utimes'                 : ['path', 'utimes'],
'fadvise64_64'           : ['fd', 'offset', 'len', 'advice'],
'vserver'                : [],
'mbind'                  : ['start', 'len', 'mode', 'nmask', 'maxnode', 'flag'],
'get_mempolicy'          : ['policy', 'nmask', 'maxnode', 'addr', 'flag'],
'set_mempolicy'          : ['mode', 'nmask', 'maxnode'],
'mq_open'                : ['name', 'oflag', 'mode', 'attr'],
'mq_unlink'              : ['name'],
'mq_timedsend'           : ['mqdes', 'msg_ptr', 'msg_len', 'msg_prio', 'abs_timeout'],
'mq_timedreceive'        : ['mqdes', 'msg_ptr', 'msg_len', 'msg_prio', 'abs_timeout'],
'mq_notify'              : ['mqdes', 'notification'],
'mq_getsetattr'          : ['mqdes', 'mqstat', 'omqstat'],
'kexec_load'             : ['entry', 'nr_segments', 'segments', 'flag'],
'waitid'                 : ['which', 'pid', 'infop', 'options', 'ru'],
'add_key'                : ['_type', '_description', '_payload', 'plen', 'destringid'],
'request_key'            : ['_type', '_description', '_callout_info', 'destringid'],
'keyctl'                 : ['cmd', 'arg2', 'arg3', 'arg4', 'arg5'],
'ioprio_set'             : ['which', 'who', 'ioprio'],
'ioprio_get'             : ['which', 'who'],
'inotify_init'           : [],
'inotify_add_watch'      : ['fd', 'path', 'mask'],
'inotify_rm_watch'       : ['fd', 'wd'],
'migrate_pages'          : ['pid', 'maxnode', 'from', 'to'],
'openat'                 : ['dfd', 'path', 'flag', 'mode'],
'mkdirat'                : ['dfd', 'path', 'mode'],
'mknodat'                : ['dfd', 'path', 'mode', 'dev'],
'fchownat'               : ['dfd', 'path', 'user', 'group', 'flag'],
'futimesat'              : ['dfd', 'path', 'utimes'],
'fstatat64'              : ['dfd', 'path', 'statbuf', 'flag'],
'unlinkat'               : ['dfd', 'path', 'flag'],
'renameat'               : ['olddfd', 'oldname', 'newdfd', 'newname'],
'linkat'                 : ['olddfd', 'oldname', 'newdfd', 'newname', 'flag'],
'symlinkat'              : ['oldname', 'newdfd', 'newname'],
'readlinkat'             : ['dfd', 'path', 'buf', 'bufsiz'],
'fchmodat'               : ['dfd', 'path', 'mode'],
'faccessat'              : ['dfd', 'path', 'mode'],
'pselect6'               : [],
'ppoll'                  : [],
'unshare'                : ['flag'],
'set_robust_list'        : ['head', 'len'],
'get_robust_list'        : ['pid', 'head_ptr', 'len_ptr'],
'splice'                 : ['fd_in', 'off_in', 'fd_out', 'off_out', 'len', 'flag'],
'sync_file_range'        : ['fd', 'offset', 'nbytes', 'flag'],
'tee'                    : ['fdin', 'fdout', 'len', 'flag'],
'vmsplice'               : ['fd', 'iov', 'nr_segs', 'flags'],
'move_pages'             : ['pid', 'nr_pages', 'pages', 'nodes', 'status', 'flag'],
'getcpu'                 : ['cpu', 'node', 'cache'],
'epoll_pwait'            : ['epfd', 'events', 'maxevents', 'timeout', 'sigmask', 'sigsetsize'],
'utimensat'              : ['dfd', 'path', 'utimes', 'flags'],
'signalfd'               : ['ufd', 'user_mask', 'sizemask'],
'timerfd_create'         : ['clockid', 'flag'],
'eventfd'                : ['count'],
'fallocate'              : ['fd', 'mode', 'offset', 'len'],
'timerfd_settime'        : ['ufd', 'flags', 'utmr', 'otmr'],
'timerfd_gettime'        : ['ufd', 'otmr'],
'signalfd4'              : ['ufd', 'user_mask', 'sizemask', 'flag'],
'eventfd2'               : ['count', 'flag'],
'epoll_create1'          : ['flags'],
'dup3'                   : ['oldfd', 'newfd', 'flag'],
'pipe2'                  : ['fildes', 'flag'],
'inotify_init1'          : ['flag'],
'preadv'                 : ['fd', 'vec', 'vlen', 'pos_l', 'pos_h'],
'pwritev'                : ['fd', 'vec', 'vlen', 'pos_l', 'pos_h'],
'rt_tgsigqueueinfo'      : ['tgid', 'pid', 'sig', 'uinfo'],
'perf_event_open'        : [],
'recvmmsg'               : [],
'send'                   : [],
'sendto'                 : [],
'sendmsg'                : [],
'recv'                   : [],
'recvfrom'               : [],
'recvmsg'                : [],
}


Syscalls = dict()

for name, arglist in SyscallDefs.iteritems():
    nr = getattr(unistd, 'NR_%s' % name)

    def init(self, syscall):
        Syscall.__init__(self, syscall)
        if syscall.nr != self.nr:
            raise ValueError
        for i, arg in enumerate(self.arglist):
            setattr(self, arg, self.args[i])

    klass_name = 'SYS_%s' % name
    klass = type(klass_name, (Syscall, ), { '__init__': init, 'nr': nr,
        'name': name, 'arglist': arglist })
    Syscalls[nr] = klass
    __builtins__[klass_name] = klass


def declare_syscall_sets(sets):
    for name, syslist in sets.iteritems():
        syscallset_name = 'SYS_%s' % name
        syscalls = [getattr(unistd, 'NR_%s' % s) for s in syslist]
        __builtins__[syscallset_name] = frozenset(syscalls)


def event_to_syscall(event):
    """Convert a syscall event to Syscall object"""
    if event.nr in Syscalls:
        return Syscalls[event.nr](event)
    else:
        return None


def get_resource_path(s):
    if s is None:
        return None

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

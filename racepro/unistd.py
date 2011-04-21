import sys

ERESTARTSYS = -512
ERESTARTNOINTR = -513
ERESTARTNOHAND = -514
ERESTART_RESTARTBLOCK = -516

EINTERRUPTED = [
    ERESTARTSYS,
    ERESTARTNOINTR,
    ERESTARTNOHAND,
    ERESTART_RESTARTBLOCK,
]

def syscall_ret(ret):
    """Convert syscall return value from unsigned to signed"""
    if ret >= sys.maxint:
        return ret - (sys.maxint + 1) * 2
    else:
        return ret

def syscall_str(nr):
    """Convert syscall number to syscall string"""
    if nr in SYSCALLS:
        return SYSCALLS[nr]
    else:
        return '?????'

NR_restart_syscall        = 0
NR_exit                   = 1
NR_fork                   = 2
NR_read                   = 3
NR_write                  = 4
NR_open                   = 5
NR_close                  = 6
NR_waitpid                = 7
NR_creat                  = 8
NR_link                   = 9
NR_unlink                 = 10
NR_execve                 = 11
NR_chdir                  = 12
NR_time                   = 13
NR_mknod                  = 14
NR_chmod                  = 15
NR_lchown                 = 16
NR_break                  = 17
NR_oldstat                = 18
NR_lseek                  = 19
NR_getpid                 = 20
NR_mount                  = 21
NR_umount                 = 22
NR_setuid                 = 23
NR_getuid                 = 24
NR_stime                  = 25
NR_ptrace                 = 26
NR_alarm                  = 27
NR_oldfstat               = 28
NR_pause                  = 29
NR_utime                  = 30
NR_stty                   = 31
NR_gtty                   = 32
NR_access                 = 33
NR_nice                   = 34
NR_ftime                  = 35
NR_sync                   = 36
NR_kill                   = 37
NR_rename                 = 38
NR_mkdir                  = 39
NR_rmdir                  = 40
NR_dup                    = 41
NR_pipe                   = 42
NR_times                  = 43
NR_prof                   = 44
NR_brk                    = 45
NR_setgid                 = 46
NR_getgid                 = 47
NR_signal                 = 48
NR_geteuid                = 49
NR_getegid                = 50
NR_acct                   = 51
NR_umount2                = 52
NR_lock                   = 53
NR_ioctl                  = 54
NR_fcntl                  = 55
NR_mpx                    = 56
NR_setpgid                = 57
NR_ulimit                 = 58
NR_oldolduname            = 59
NR_umask                  = 60
NR_chroot                 = 61
NR_ustat                  = 62
NR_dup2                   = 63
NR_getppid                = 64
NR_getpgrp                = 65
NR_setsid                 = 66
NR_sigaction              = 67
NR_sgetmask               = 68
NR_ssetmask               = 69
NR_setreuid               = 70
NR_setregid               = 71
NR_sigsuspend             = 72
NR_sigpending             = 73
NR_sethostname            = 74
NR_setrlimit              = 75
NR_getrlimit              = 76
NR_getrusage              = 77
NR_gettimeofday           = 78
NR_settimeofday           = 79
NR_getgroups              = 80
NR_setgroups              = 81
NR_select                 = 82
NR_symlink                = 83
NR_oldlstat               = 84
NR_readlink               = 85
NR_uselib                 = 86
NR_swapon                 = 87
NR_reboot                 = 88
NR_readdir                = 89
NR_mmap                   = 90
NR_munmap                 = 91
NR_truncate               = 92
NR_ftruncate              = 93
NR_fchmod                 = 94
NR_fchown                 = 95
NR_getpriority            = 96
NR_setpriority            = 97
NR_profil                 = 98
NR_statfs                 = 99
NR_fstatfs                = 100
NR_ioperm                 = 101
NR_socketcall             = 102
NR_syslog                 = 103
NR_setitimer              = 104
NR_getitimer              = 105
NR_stat                   = 106
NR_lstat                  = 107
NR_fstat                  = 108
NR_olduname               = 109
NR_iopl                   = 110
NR_vhangup                = 111
NR_idle                   = 112
NR_vm86old                = 113
NR_wait4                  = 114
NR_swapoff                = 115
NR_sysinfo                = 116
NR_ipc                    = 117
NR_fsync                  = 118
NR_sigreturn              = 119
NR_clone                  = 120
NR_setdomainname          = 121
NR_uname                  = 122
NR_modify_ldt             = 123
NR_adjtimex               = 124
NR_mprotect               = 125
NR_sigprocmask            = 126
NR_create_module          = 127
NR_init_module            = 128
NR_delete_module          = 129
NR_get_kernel_syms        = 130
NR_quotactl               = 131
NR_getpgid                = 132
NR_fchdir                 = 133
NR_bdflush                = 134
NR_sysfs                  = 135
NR_personality            = 136
NR_afs_syscall            = 137
NR_setfsuid               = 138
NR_setfsgid               = 139
NR__llseek                = 140
NR_getdents               = 141
NR__newselect             = 142
NR_flock                  = 143
NR_msync                  = 144
NR_readv                  = 145
NR_writev                 = 146
NR_getsid                 = 147
NR_fdatasync              = 148
NR__sysctl                = 149
NR_mlock                  = 150
NR_munlock                = 151
NR_mlockall               = 152
NR_munlockall             = 153
NR_sched_setparam         = 154
NR_sched_getparam         = 155
NR_sched_setscheduler     = 156
NR_sched_getscheduler     = 157
NR_sched_yield            = 158
NR_sched_get_priority_max = 159
NR_sched_get_priority_min = 160
NR_sched_rr_get_interval  = 161
NR_nanosleep              = 162
NR_mremap                 = 163
NR_setresuid              = 164
NR_getresuid              = 165
NR_vm86                   = 166
NR_query_module           = 167
NR_poll                   = 168
NR_nfsservctl             = 169
NR_setresgid              = 170
NR_getresgid              = 171
NR_prctl                  = 172
NR_rt_sigreturn           = 173
NR_rt_sigaction           = 174
NR_rt_sigprocmask         = 175
NR_rt_sigpending          = 176
NR_rt_sigtimedwait        = 177
NR_rt_sigqueueinfo        = 178
NR_rt_sigsuspend          = 179
NR_pread64                = 180
NR_pwrite64               = 181
NR_chown                  = 182
NR_getcwd                 = 183
NR_capget                 = 184
NR_capset                 = 185
NR_sigaltstack            = 186
NR_sendfile               = 187
NR_getpmsg                = 188
NR_putpmsg                = 189
NR_vfork                  = 190
NR_ugetrlimit             = 191
NR_mmap2                  = 192
NR_truncate64             = 193
NR_ftruncate64            = 194
NR_stat64                 = 195
NR_lstat64                = 196
NR_fstat64                = 197
NR_lchown32               = 198
NR_getuid32               = 199
NR_getgid32               = 200
NR_geteuid32              = 201
NR_getegid32              = 202
NR_setreuid32             = 203
NR_setregid32             = 204
NR_getgroups32            = 205
NR_setgroups32            = 206
NR_fchown32               = 207
NR_setresuid32            = 208
NR_getresuid32            = 209
NR_setresgid32            = 210
NR_getresgid32            = 211
NR_chown32                = 212
NR_setuid32               = 213
NR_setgid32               = 214
NR_setfsuid32             = 215
NR_setfsgid32             = 216
NR_pivot_root             = 217
NR_mincore                = 218
NR_madvise                = 219
NR_getdents64             = 220
NR_fcntl64                = 221
NR_gettid                 = 224
NR_readahead              = 225
NR_setxattr               = 226
NR_lsetxattr              = 227
NR_fsetxattr              = 228
NR_getxattr               = 229
NR_lgetxattr              = 230
NR_fgetxattr              = 231
NR_listxattr              = 232
NR_llistxattr             = 233
NR_flistxattr             = 234
NR_removexattr            = 235
NR_lremovexattr           = 236
NR_fremovexattr           = 237
NR_tkill                  = 238
NR_sendfile64             = 239
NR_futex                  = 240
NR_sched_setaffinity      = 241
NR_sched_getaffinity      = 242
NR_set_thread_area        = 243
NR_get_thread_area        = 244
NR_io_setup               = 245
NR_io_destroy             = 246
NR_io_getevents           = 247
NR_io_submit              = 248
NR_io_cancel              = 249
NR_fadvise64              = 250
NR_exit_group             = 252
NR_lookup_dcookie         = 253
NR_epoll_create           = 254
NR_epoll_ctl              = 255
NR_epoll_wait             = 256
NR_remap_file_pages       = 257
NR_set_tid_address        = 258
NR_timer_create           = 259
NR_timer_settime          = (NR_timer_create+1)
NR_timer_gettime          = (NR_timer_create+2)
NR_timer_getoverrun       = (NR_timer_create+3)
NR_timer_delete           = (NR_timer_create+4)
NR_clock_settime          = (NR_timer_create+5)
NR_clock_gettime          = (NR_timer_create+6)
NR_clock_getres           = (NR_timer_create+7)
NR_clock_nanosleep        = (NR_timer_create+8)
NR_statfs64               = 268
NR_fstatfs64              = 269
NR_tgkill                 = 270
NR_utimes                 = 271
NR_fadvise64_64           = 272
NR_vserver                = 273
NR_mbind                  = 274
NR_get_mempolicy          = 275
NR_set_mempolicy          = 276
NR_mq_open                = 277
NR_mq_unlink              = (NR_mq_open+1)
NR_mq_timedsend           = (NR_mq_open+2)
NR_mq_timedreceive        = (NR_mq_open+3)
NR_mq_notify              = (NR_mq_open+4)
NR_mq_getsetattr          = (NR_mq_open+5)
NR_kexec_load             = 283
NR_waitid                 = 284
NR_add_key                = 286
NR_request_key            = 287
NR_keyctl                 = 288
NR_ioprio_set             = 289
NR_ioprio_get             = 290
NR_inotify_init           = 291
NR_inotify_add_watch      = 292
NR_inotify_rm_watch       = 293
NR_migrate_pages          = 294
NR_openat                 = 295
NR_mkdirat                = 296
NR_mknodat                = 297
NR_fchownat               = 298
NR_futimesat              = 299
NR_fstatat64              = 300
NR_unlinkat               = 301
NR_renameat               = 302
NR_linkat                 = 303
NR_symlinkat              = 304
NR_readlinkat             = 305
NR_fchmodat               = 306
NR_faccessat              = 307
NR_pselect6               = 308
NR_ppoll                  = 309
NR_unshare                = 310
NR_set_robust_list        = 311
NR_get_robust_list        = 312
NR_splice                 = 313
NR_sync_file_range        = 314
NR_tee                    = 315
NR_vmsplice               = 316
NR_move_pages             = 317
NR_getcpu                 = 318
NR_epoll_pwait            = 319
NR_utimensat              = 320
NR_signalfd               = 321
NR_timerfd_create         = 322
NR_eventfd                = 323
NR_fallocate              = 324
NR_timerfd_settime        = 325
NR_timerfd_gettime        = 326
NR_signalfd4              = 327
NR_eventfd2               = 328
NR_epoll_create1          = 329
NR_dup3                   = 330
NR_pipe2                  = 331
NR_inotify_init1          = 332
NR_preadv                 = 333
NR_pwritev                = 334
NR_rt_tgsigqueueinfo      = 335
NR_perf_event_open        = 336
NR_recvmmsg               = 337

SYSCALLS = {
    NR_restart_syscall : 'restart_syscall',
    NR_exit : 'exit',
    NR_fork : 'fork',
    NR_read : 'read',
    NR_write : 'write',
    NR_open : 'open',
    NR_close : 'close',
    NR_waitpid : 'waitpid',
    NR_creat : 'creat',
    NR_link : 'link',
    NR_unlink : 'unlink',
    NR_execve : 'execve',
    NR_chdir : 'chdir',
    NR_time : 'time',
    NR_mknod : 'mknod',
    NR_chmod : 'chmod',
    NR_lchown : 'lchown',
    NR_break : 'break',
    NR_oldstat : 'oldstat',
    NR_lseek : 'lseek',
    NR_getpid : 'getpid',
    NR_mount : 'mount',
    NR_umount : 'umount',
    NR_setuid : 'setuid',
    NR_getuid : 'getuid',
    NR_stime : 'stime',
    NR_ptrace : 'ptrace',
    NR_alarm : 'alarm',
    NR_oldfstat : 'oldfstat',
    NR_pause : 'pause',
    NR_utime : 'utime',
    NR_stty : 'stty',
    NR_gtty : 'gtty',
    NR_access : 'access',
    NR_nice : 'nice',
    NR_ftime : 'ftime',
    NR_sync : 'sync',
    NR_kill : 'kill',
    NR_rename : 'rename',
    NR_mkdir : 'mkdir',
    NR_rmdir : 'rmdir',
    NR_dup : 'dup',
    NR_pipe : 'pipe',
    NR_times : 'times',
    NR_prof : 'prof',
    NR_brk : 'brk',
    NR_setgid : 'setgid',
    NR_getgid : 'getgid',
    NR_signal : 'signal',
    NR_geteuid : 'geteuid',
    NR_getegid : 'getegid',
    NR_acct : 'acct',
    NR_umount2 : 'umount2',
    NR_lock : 'lock',
    NR_ioctl : 'ioctl',
    NR_fcntl : 'fcntl',
    NR_mpx : 'mpx',
    NR_setpgid : 'setpgid',
    NR_ulimit : 'ulimit',
    NR_oldolduname : 'oldolduname',
    NR_umask : 'umask',
    NR_chroot : 'chroot',
    NR_ustat : 'ustat',
    NR_dup2 : 'dup2',
    NR_getppid : 'getppid',
    NR_getpgrp : 'getpgrp',
    NR_setsid : 'setsid',
    NR_sigaction : 'sigaction',
    NR_sgetmask : 'sgetmask',
    NR_ssetmask : 'ssetmask',
    NR_setreuid : 'setreuid',
    NR_setregid : 'setregid',
    NR_sigsuspend : 'sigsuspend',
    NR_sigpending : 'sigpending',
    NR_sethostname : 'sethostname',
    NR_setrlimit : 'setrlimit',
    NR_getrlimit : 'getrlimit',
    NR_getrusage : 'getrusage',
    NR_gettimeofday : 'gettimeofday',
    NR_settimeofday : 'settimeofday',
    NR_getgroups : 'getgroups',
    NR_setgroups : 'setgroups',
    NR_select : 'select',
    NR_symlink : 'symlink',
    NR_oldlstat : 'oldlstat',
    NR_readlink : 'readlink',
    NR_uselib : 'uselib',
    NR_swapon : 'swapon',
    NR_reboot : 'reboot',
    NR_readdir : 'readdir',
    NR_mmap : 'mmap',
    NR_munmap : 'munmap',
    NR_truncate : 'truncate',
    NR_ftruncate : 'ftruncate',
    NR_fchmod : 'fchmod',
    NR_fchown : 'fchown',
    NR_getpriority : 'getpriority',
    NR_setpriority : 'setpriority',
    NR_profil : 'profil',
    NR_statfs : 'statfs',
    NR_fstatfs : 'fstatfs',
    NR_ioperm : 'ioperm',
    NR_socketcall : 'socketcall',
    NR_syslog : 'syslog',
    NR_setitimer : 'setitimer',
    NR_getitimer : 'getitimer',
    NR_stat : 'stat',
    NR_lstat : 'lstat',
    NR_fstat : 'fstat',
    NR_olduname : 'olduname',
    NR_iopl : 'iopl',
    NR_vhangup : 'vhangup',
    NR_idle : 'idle',
    NR_vm86old : 'vm86old',
    NR_wait4 : 'wait4',
    NR_swapoff : 'swapoff',
    NR_sysinfo : 'sysinfo',
    NR_ipc : 'ipc',
    NR_fsync : 'fsync',
    NR_sigreturn : 'sigreturn',
    NR_clone : 'clone',
    NR_setdomainname : 'setdomainname',
    NR_uname : 'uname',
    NR_modify_ldt : 'modify_ldt',
    NR_adjtimex : 'adjtimex',
    NR_mprotect : 'mprotect',
    NR_sigprocmask : 'sigprocmask',
    NR_create_module : 'create_module',
    NR_init_module : 'init_module',
    NR_delete_module : 'delete_module',
    NR_get_kernel_syms : 'get_kernel_syms',
    NR_quotactl : 'quotactl',
    NR_getpgid : 'getpgid',
    NR_fchdir : 'fchdir',
    NR_bdflush : 'bdflush',
    NR_sysfs : 'sysfs',
    NR_personality : 'personality',
    NR_afs_syscall : 'afs_syscall',
    NR_setfsuid : 'setfsuid',
    NR_setfsgid : 'setfsgid',
    NR__llseek : '_llseek',
    NR_getdents : 'getdents',
    NR__newselect : '_newselect',
    NR_flock : 'flock',
    NR_msync : 'msync',
    NR_readv : 'readv',
    NR_writev : 'writev',
    NR_getsid : 'getsid',
    NR_fdatasync : 'fdatasync',
    NR__sysctl : '_sysctl',
    NR_mlock : 'mlock',
    NR_munlock : 'munlock',
    NR_mlockall : 'mlockall',
    NR_munlockall : 'munlockall',
    NR_sched_setparam : 'sched_setparam',
    NR_sched_getparam : 'sched_getparam',
    NR_sched_setscheduler : 'sched_setscheduler',
    NR_sched_getscheduler : 'sched_getscheduler',
    NR_sched_yield : 'sched_yield',
    NR_sched_get_priority_max : 'sched_get_priority_max',
    NR_sched_get_priority_min : 'sched_get_priority_min',
    NR_sched_rr_get_interval : 'sched_rr_get_interval',
    NR_nanosleep : 'nanosleep',
    NR_mremap : 'mremap',
    NR_setresuid : 'setresuid',
    NR_getresuid : 'getresuid',
    NR_vm86 : 'vm86',
    NR_query_module : 'query_module',
    NR_poll : 'poll',
    NR_nfsservctl : 'nfsservctl',
    NR_setresgid : 'setresgid',
    NR_getresgid : 'getresgid',
    NR_prctl : 'prctl',
    NR_rt_sigreturn : 'rt_sigreturn',
    NR_rt_sigaction : 'rt_sigaction',
    NR_rt_sigprocmask : 'rt_sigprocmask',
    NR_rt_sigpending : 'rt_sigpending',
    NR_rt_sigtimedwait : 'rt_sigtimedwait',
    NR_rt_sigqueueinfo : 'rt_sigqueueinfo',
    NR_rt_sigsuspend : 'rt_sigsuspend',
    NR_pread64 : 'pread64',
    NR_pwrite64 : 'pwrite64',
    NR_chown : 'chown',
    NR_getcwd : 'getcwd',
    NR_capget : 'capget',
    NR_capset : 'capset',
    NR_sigaltstack : 'sigaltstack',
    NR_sendfile : 'sendfile',
    NR_getpmsg : 'getpmsg',
    NR_putpmsg : 'putpmsg',
    NR_vfork : 'vfork',
    NR_ugetrlimit : 'ugetrlimit',
    NR_mmap2 : 'mmap2',
    NR_truncate64 : 'truncate64',
    NR_ftruncate64 : 'ftruncate64',
    NR_stat64 : 'stat64',
    NR_lstat64 : 'lstat64',
    NR_fstat64 : 'fstat64',
    NR_lchown32 : 'lchown32',
    NR_getuid32 : 'getuid32',
    NR_getgid32 : 'getgid32',
    NR_geteuid32 : 'geteuid32',
    NR_getegid32 : 'getegid32',
    NR_setreuid32 : 'setreuid32',
    NR_setregid32 : 'setregid32',
    NR_getgroups32 : 'getgroups32',
    NR_setgroups32 : 'setgroups32',
    NR_fchown32 : 'fchown32',
    NR_setresuid32 : 'setresuid32',
    NR_getresuid32 : 'getresuid32',
    NR_setresgid32 : 'setresgid32',
    NR_getresgid32 : 'getresgid32',
    NR_chown32 : 'chown32',
    NR_setuid32 : 'setuid32',
    NR_setgid32 : 'setgid32',
    NR_setfsuid32 : 'setfsuid32',
    NR_setfsgid32 : 'setfsgid32',
    NR_pivot_root : 'pivot_root',
    NR_mincore : 'mincore',
    NR_madvise : 'madvise',
    NR_getdents64 : 'getdents64',
    NR_fcntl64 : 'fcntl64',
    NR_gettid : 'gettid',
    NR_readahead : 'readahead',
    NR_setxattr : 'setxattr',
    NR_lsetxattr : 'lsetxattr',
    NR_fsetxattr : 'fsetxattr',
    NR_getxattr : 'getxattr',
    NR_lgetxattr : 'lgetxattr',
    NR_fgetxattr : 'fgetxattr',
    NR_listxattr : 'listxattr',
    NR_llistxattr : 'llistxattr',
    NR_flistxattr : 'flistxattr',
    NR_removexattr : 'removexattr',
    NR_lremovexattr : 'lremovexattr',
    NR_fremovexattr : 'fremovexattr',
    NR_tkill : 'tkill',
    NR_sendfile64 : 'sendfile64',
    NR_futex : 'futex',
    NR_sched_setaffinity : 'sched_setaffinity',
    NR_sched_getaffinity : 'sched_getaffinity',
    NR_set_thread_area : 'set_thread_area',
    NR_get_thread_area : 'get_thread_area',
    NR_io_setup : 'io_setup',
    NR_io_destroy : 'io_destroy',
    NR_io_getevents : 'io_getevents',
    NR_io_submit : 'io_submit',
    NR_io_cancel : 'io_cancel',
    NR_fadvise64 : 'fadvise64',
    NR_exit_group : 'exit_group',
    NR_lookup_dcookie : 'lookup_dcookie',
    NR_epoll_create : 'epoll_create',
    NR_epoll_ctl : 'epoll_ctl',
    NR_epoll_wait : 'epoll_wait',
    NR_remap_file_pages : 'remap_file_pages',
    NR_set_tid_address : 'set_tid_address',
    NR_timer_create : 'timer_create',
    NR_timer_settime : 'timer_settime',
    NR_timer_gettime : 'timer_gettime',
    NR_timer_getoverrun : 'timer_getoverrun',
    NR_timer_delete : 'timer_delete',
    NR_clock_settime : 'clock_settime',
    NR_clock_gettime : 'clock_gettime',
    NR_clock_getres : 'clock_getres',
    NR_clock_nanosleep : 'clock_nanosleep',
    NR_statfs64 : 'statfs64',
    NR_fstatfs64 : 'fstatfs64',
    NR_tgkill : 'tgkill',
    NR_utimes : 'utimes',
    NR_fadvise64_64 : 'fadvise64_64',
    NR_vserver : 'vserver',
    NR_mbind : 'mbind',
    NR_get_mempolicy : 'get_mempolicy',
    NR_set_mempolicy : 'set_mempolicy',
    NR_mq_open : 'mq_open',
    NR_mq_unlink : 'mq_unlink',
    NR_mq_timedsend : 'mq_timedsend',
    NR_mq_timedreceive : 'mq_timedreceive',
    NR_mq_notify : 'mq_notify',
    NR_mq_getsetattr : 'mq_getsetattr',
    NR_kexec_load : 'kexec_load',
    NR_waitid : 'waitid',
    NR_add_key : 'add_key',
    NR_request_key : 'request_key',
    NR_keyctl : 'keyctl',
    NR_ioprio_set : 'ioprio_set',
    NR_ioprio_get : 'ioprio_get',
    NR_inotify_init : 'inotify_init',
    NR_inotify_add_watch : 'inotify_add_watch',
    NR_inotify_rm_watch : 'inotify_rm_watch',
    NR_migrate_pages : 'migrate_pages',
    NR_openat : 'openat',
    NR_mkdirat : 'mkdirat',
    NR_mknodat : 'mknodat',
    NR_fchownat : 'fchownat',
    NR_futimesat : 'futimesat',
    NR_fstatat64 : 'fstatat64',
    NR_unlinkat : 'unlinkat',
    NR_renameat : 'renameat',
    NR_linkat : 'linkat',
    NR_symlinkat : 'symlinkat',
    NR_readlinkat : 'readlinkat',
    NR_fchmodat : 'fchmodat',
    NR_faccessat : 'faccessat',
    NR_pselect6 : 'pselect6',
    NR_ppoll : 'ppoll',
    NR_unshare : 'unshare',
    NR_set_robust_list : 'set_robust_list',
    NR_get_robust_list : 'get_robust_list',
    NR_splice : 'splice',
    NR_sync_file_range : 'sync_file_range',
    NR_tee : 'tee',
    NR_vmsplice : 'vmsplice',
    NR_move_pages : 'move_pages',
    NR_getcpu : 'getcpu',
    NR_epoll_pwait : 'epoll_pwait',
    NR_utimensat : 'utimensat',
    NR_signalfd : 'signalfd',
    NR_timerfd_create : 'timerfd_create',
    NR_eventfd : 'eventfd',
    NR_fallocate : 'fallocate',
    NR_timerfd_settime : 'timerfd_settime',
    NR_timerfd_gettime : 'timerfd_gettime',
    NR_signalfd4 : 'signalfd4',
    NR_eventfd2 : 'eventfd2',
    NR_epoll_create1 : 'epoll_create1',
    NR_dup3 : 'dup3',
    NR_pipe2 : 'pipe2',
    NR_inotify_init1 : 'inotify_init1',
    NR_preadv : 'preadv',
    NR_pwritev : 'pwritev',
    NR_rt_tgsigqueueinfo : 'rt_tgsigqueueinfo',
    NR_perf_event_open : 'perf_event_open',
    NR_recvmmsg : 'recvmmsg'
}

SYS_fork       = set([NR_fork, NR_clone, NR_vfork])
SYS_exit       = set([NR_exit, NR_exit_group])
SYS_wait       = set([NR_waitpid, NR_wait4, NR_waitid])
SYS_read       = set([NR_read, NR_readv, NR_pread64, NR_preadv])
SYS_write      = set([NR_write, NR_writev, NR_pwrite64, NR_pwritev])
SYS_creat      = set([NR_creat, NR_link, NR_mknod])
SYS_kill       = set([NR_kill, NR_tkill])

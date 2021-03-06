R_OK = 4
W_OK = 2
X_OK = 1
F_OK = 0

O_ACCMODE   = 0003
O_RDONLY    = 00
O_WRONLY    = 01
O_RDWR      = 02
O_CREAT     = 0100
O_EXCL      = 0200
O_NOCTT     = 0400
O_TRUNC     = 01000
O_APPEND    = 02000
O_NONBLOCK  = 04000
O_NDELAY    = O_NONBLOCK
O_SYNC      = 04010000
O_FSYNC     = O_SYNC
O_ASYNC     = 020000
O_DIRECT    = 040000
O_DIRECTORY = 0200000
O_NOFOLLOW  = 0400000
O_CLOEXEC   = 02000000
O_NOATIME   = 01000000

def is_R(flag):
    return (flag & (O_WRONLY | O_RDWR)) == 0

def is_W(flag):
    return (flag & O_WRONLY) != 0

def has_R(flag):
    return (flag & O_WRONLY) == 0

def has_W(flag):
    return (flag & (O_WRONLY | O_RDWR)) != 0

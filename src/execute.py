import os
import sys
import tempfile
import subprocess

def _popen(cmd, stdin=None, stdout=None, stderr=None, notty=False):
    if notty:
        p1 = subprocess.Popen(cmd, stdin=stdin, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
        p2 = subprocess.Popen(['/bin/cat'], stdin=p1.stdout, stdout=stdout,
                              stderr=subprocess.STDOUT)
        p1.stdout.close()
        p2.wait()
    else:
        p1 = subprocess.Popen(cmd, stdin=stdin, stdout=stdout, stderr=stderr)
    return p1.wait()

def _sudo(cmd, stdin=None, stdout=None, stderr=None, notty=False, nofail=True):
    if os.geteuid() != 0:
        cmd = ['sudo'] + cmd
    ret = _popen(cmd, notty=notty, stdin=stdin, stdout=stdout, stderr=stderr)
    if ret and nofail:
        raise RuntimeError('%s failed with %d' % (' '.join(cmd), ret))
    return ret

#############################################################################

class Execute:
    def execute(self, cmd,
                stdin=None, stdout=None, stderr=None,
                chroot=False, notty=False):
        if not chroot:
            ret = _sudo(cmd,
                        stdin=stdin, stdout=stdout, stderr=stderr,
                        notty=notty, nofail=False)
        else:
            assert self.chroot
            ret = _sudo(['chroot', self.chroot, '/bin/sh', '-c',
                         'cd %s; exec %s' % (os.getcwd(), ' '.join(cmd))],
                        stdin=stdin, stdout=stdout, stderr=stderr,
                        notty=notty, nofail=False)
        return ret

    def __exit__(self, type, value, tb):
        pass

    def __enter__(self):
        return self

    def __init__(self, chroot=None):
        self.chroot = chroot

#############################################################################

class ExecuteJail(Execute):
    def execute(self, command,
                stdin=None, stdout=None, stderr=None,
                chroot=True, notty=False):
        assert self.mounted
        return Execute.execute(self, command,
                               stdin, stdout, stderr, chroot, notty)

    def _bind(self, dir):
        assert(dir[0] == '/')
        _sudo(['mount', '-o', 'bind', dir, os.path.join(self.chroot, dir)])
        self._binded_dirs.append(dir)

    def open(self):
        assert(not self.mounted)

        if not self.root:
            self.root = '/'
        if not self.scratch:
            self.scratch = tempfile.mkdtemp(prefix='isolate-temp-')
            self._rmdirs.append(self.scratch)
        if not self.chroot:
            self.chroot = tempfile.mkdtemp(prefix='isolate-temp-')
            self._rmdirs.append(self.chroot)

        mount_dirs = '%s=rw:%s=ro' % \
            (os.path.abspath(self.scratch), os.path.abspath(self.root))
        mount_point = os.path.abspath(self.chroot)

        _sudo(['unionfs-fuse', '-o', 'cow,allow_other,use_ino,suid,' + \
                   'dev,nonempty,max_files=32768', mount_dirs, mount_point])

        self._bind('/proc')
        self._bind('/dev')
        if self.persist:
            self._bind(self.persist)

        self.mounted = True

    def close(self):
        assert(self.mounted)

        for dir in self._binded_dirs:
            _sudo('umount -l'.split() + [os.path.join(self.chroot, dir)])

        _sudo('fusermount -z -u'.split() + [self.chroot])

        for dir in self._rmdirs:
            _sudo(['rm', '-rf', dir])

        self.mounted = False

    def __exit__(self, type, value, tb):
        self.close()

    def __enter__(self):
        self.open()
        return self

    def __init__(self, root='/', mount=None, scratch=None, persist=None):
        self.root = root
        self.chroot = mount
        self.scratch = scratch
        self.persist = persist

        self._rmdirs = list()
        self._binded_dirs = list()
        self.mounted = False

#############################################################################

def open(root='/', jailed=False,
         chroot=None, mount=None, scratch=None, persist=None):
    if not jailed:
        return Execute(chroot=mount)
    else:
        return ExecuteJail(root=root, mount=None, scratch=None, persist=None)


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
    return p1

def _sudo(cmd, **kwargs):
    if os.geteuid() != 0:
        cmd = ['sudo'] + cmd
        p = _popen(cmd, **kwargs)
    return p

#############################################################################

class Execute:
    def execute(self, cmd, chroot=False, **kwargs):
        if chroot:
            assert self.chroot
            cmd = ['chroot', self.chroot, '/bin/sh', '-c',
                   'cd %s; exec %s' % (os.getcwd(), ' '.join(cmd))]
        p = _sudo(cmd, **kwargs)
        return p.wait()

    def execute_raw(self, cmd, chroot=False, **kwargs):
        if chroot:
            assert self.chroot
            cmd = ['chroot', self.chroot, '/bin/sh', '-c',
                   'cd %s; exec %s' % (os.getcwd(), ' '.join(cmd))]
        p = _sudo(cmd, **kwargs)
        return p

    def __exit__(self, type, value, tb):
        pass

    def __enter__(self):
        return self

    def __init__(self, chroot=None):
        self.chroot = chroot

#############################################################################

class ExecuteJail(Execute):
    def execute(self, command, **kwargs):
        assert self.mounted
        return Execute.execute(self, command, **kwargs)

    def execute_raw(self, command, **kwargs):
        assert self.mounted
        return Execute.execute_raw(self, command, **kwargs)

    def bind(self, d):
        assert d[0] == '/'
        m = os.path.join(self.chroot, d[1:])
        _sudo(['mount', '-o', 'bind', d, m])
        self._binded_dirs.append(d)

    def unbind(self, d):
        assert d[0] == '/'
        m = os.path.join(self.chroot, d[1:])
        _sudo(['umount', '-l', m])
        self._binded_dirs.remove(d)

    def open(self):
        assert(not self.mounted)

        if not self.root:
            self.root = '/'
        if not self.scratch:
            self.scratch = tempfile.mkdtemp(prefix='isolate-temp-')
            os.chmod(self.scratch, 0777)
            self._rmdirs.append(self.scratch)
        if not self.chroot:
            self.chroot = tempfile.mkdtemp(prefix='isolate-temp-')
            os.chmod(self.chroot, 0777)
            self._rmdirs.append(self.chroot)

        mount_dirs = '%s=rw:%s=ro' % \
            (os.path.abspath(self.scratch), os.path.abspath(self.root))
        mount_point = os.path.abspath(self.chroot)

        _sudo(['unionfs-fuse', '-o', 'cow,allow_other,use_ino,suid,' + \
                   'dev,nonempty,max_files=32768', mount_dirs, mount_point])

        self.bind('/proc')
        self.bind('/dev')
        if self.persist:
            self.bind(self.persist)

        self.mounted = True

    def close(self):
        assert(self.mounted)

        for d in list(self._binded_dirs):
            self.unbind(d)

        _sudo('fusermount -z -u'.split() + [self.chroot])

        for d in self._rmdirs:
            _sudo(['rm', '-rf', d])

        self.mounted = False

    def __exit__(self, type, value, tb):
        self.close()

    def __enter__(self):
        self.open()
        return self

    def __init__(self, root='/', chroot=None, scratch=None, persist=None):
        self.root = root
        self.chroot = chroot
        self.scratch = scratch
        self.persist = persist

        self._rmdirs = list()
        self._binded_dirs = list()
        self.mounted = False

#############################################################################

def open(jailed=False, **kwargs):
    if not jailed:
        return Execute(kwargs['chroot'])
    else:
        return ExecuteJail(**kwargs)


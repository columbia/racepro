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
    ret = _popen(['sudo'] + cmd, notty=notty,
                 stdin=stdin, stdout=stdout, stderr=stderr)
    if ret and nofail:
        raise RuntimeError('%s failed with %d' % (' '.join(cmd), ret))
    return ret

class Isolate:
    def execute(self, command,
                stdin=None, stdout=None, stderr=None,
                chroot=True, notty=False):
        assert(self.mounted)

        if not chroot:
            ret = _sudo(command.split(),
                        stdin = stdin, stdout = stdout, stderr = stderr,
                        notty = notty, nofail = False)
        else:
            ret = _sudo(['chroot', self.mount, '/bin/sh', '-c',
                         'cd %s; exec %s' % (os.getcwd(), ' '.join(command))],
                        stdin = stdin, stdout = stdout, stderr = stderr,
                        notty = notty, nofail = False)
        return ret

    def bind(self, dir):
        assert(dir[0] == '/')
        _sudo(['mount', '-o', 'bind', dir, self.mount + dir])
        self._binded_dirs.append(dir)

    def open(self):
        assert(not self.mounted)

        if not self.root:
            self.root = '/'
        if not self.scratch:
            self.scratch = tempfile.mkdtemp(prefix='isolate-temp-')
            self._rmdirs.append(self.scratch)
        if not self.mount:
            self.mount = tempfile.mkdtemp(prefix='isolate-temp-')
            self._rmdirs.append(self.mount)

        mount_dirs = '%s=rw:%s=ro' % \
            (os.path.abspath(self.scratch), os.path.abspath(self.root))
        mount_point = os.path.abspath(self.mount)

        _sudo(['unionfs-fuse', '-o', 'cow,allow_other,use_ino,suid,' + \
                   'dev,nonempty,max_files=32768', mount_dirs, mount_point])

        self.bind('/proc')
        self.bind('/dev')
        if self.persist:
            self.bind(self.persist)

        self.mounted = True

    def close(self):
        assert(self.mounted)

        for dir in self._binded_dirs:
            _sudo('sudo umount -l'.split() + [self.mount + dir])

        _sudo('fusermount -z -u'.split() + [self.mount])

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
        self.mount = mount
        self.scratch = scratch
        self.persist = persist

        self._rmdirs = list()
        self._binded_dirs = list()
        self.mounted = False

def open(root='/', mount=None, scratch=None, persist=None):
    return Isolate(root=root, mount=mount, scratch=scratch, persist=persist)


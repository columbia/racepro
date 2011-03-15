import os
import sys
import tempfile
import subprocess

def _sudo(cmd):
    ret = subprocess.call(['sudo'] + cmd)
    if ret:
        raise RuntimeError('%s failed with %d' % (' '.join(cmd), ret))

class Isolate:
    def execute(self, command, chroot=True):
        assert(self.mounted)
        if not chroot:
            _sudo(command.split())
        else:
            _sudo(['chroot', self.mount, '/bin/sh', '-c',
                   'cd %s; exec %s' % (os.getcwd(), ' '.join(command))])

    def bind(self, dir):
        assert(dir[0] == '/')
        _sudo(['mount', '-o', 'bind', dir, self.mount + dir])
        self._binded_dirs.append(dir)

    def open(self):
        assert(not self.mounted)

        if not self.scratch:
            self.scratch = tempfile.mkdtemp(prefix='isolate-temp-')
            self._rmdirs.append(self.scratch)
        if not self.mount:
            self.mount = tempfile.mkdtemp(prefix='isolate-temp-')
            self._rmdirs.append(self.mount)

        _sudo(['unionfs-fuse', '-o', 'cow,allow_other,use_ino,suid,' + \
                                     'dev,nonempty,max_files=32768',
               '%s=rw:%s=ro' % (self.scratch, self.root), self.mount])
        self.bind('/proc')
        self.bind('/dev')
        if self.persist:
            self.bind(self.persist)

        self.mounted = True

    def close(self):
        assert(self.mounted)

        for dir in self._binded_dirs:
            _sudo('sudo umount -l'.split() + [self.mount + dir])

        _sudo('fusermount -u'.split() + [self.mount])

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


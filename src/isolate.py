import os
import sys
import tempfile
import subprocess

class Isolate:

    def execute(self, command, chroot=True):
        if not self.mounted:
            raise OSError 
        if not chroot:
            cmd = command.split()
        else:
            pre = 'sudo chroot %s /bin/sh -c' % self.mount
            cmd = pre.split()
            cmd.append('cd %s; exec %s' % (os.getcwd(), ' '.join(command)))
        return subprocess.call(cmd)

    def scratch_path(self):
        return self.scratch

    def mount_path(self):
        return self.mount

    def close(self):
        cmd = 'sudo fusermount -u %s' % (self.mount)
        ret = subprocess.call(cmd.split())
        if ret != 0:
            print('fusertmount -u %s: failed with exit %d' % (self.mount, ret))
            return False
        return True

    def open(self):
        cmd = \
            'sudo unionfs-fuse' + \
            ' -o cow,allow_other,use_ino,suid,dev,nonempty,max_files=32768' + \
            ' %s=rw:%s=ro %s' % (self.scratch, self.root, self.mount)
        ret = subprocess.call(cmd.split())
        if ret != 0:
            print('unionfs-fuse of "%s", "%s" --> "%s": failed with exit %d' %
                  (self.root, self.scratch, self.mount, ret))
            return False
        return True

    def _umount_dirs(self):
        cmd = 'sudo umount -l %s/proc' % self.mount
        subprocess.call(cmd.split())
        cmd = 'sudo umount -l %s/dev' % self.mount
        subprocess.call(cmd.split())
        if self.persist:
            cmd = 'umount -l %s/%s' % (self.mount, self.persist)
            subprocess.call(cmd.split())

    def _mount_dirs(self):
        cmd = 'sudo mount -o bind /proc %s/proc' % self.mount
        subprocess.call(cmd.split())
        cmd = 'sudo mount -o bind /dev %s/dev' % self.mount
        subprocess.call(cmd.split())
        if self.persist:
            cmd = 'sudo mount -o bind %s %s/%s' % \
                (self.persist, self.mount, self.persist)
            subprocess.call(cmd.split())

    def __exit__(self, type, value, tb):
        self.mounted = False
        self._umount_dirs()
        self.close()
        for dir in self._rmdirs:
            cmd = 'rm -rf %s' % self.scratch
            subprocess.call(cmd.split())

    def __enter__(self):
        self.open()
        self._mount_dirs()
        self.mounted = True
        return self

    def __init__(self,
                 root='/',
                 mount=None,
                 scratch=None,
                 persist=None):

        self._rmdirs = list()

        if not scratch:
            scratch = tempfile.mkdtemp(prefix='isolate-temp-')
            self._rmdirs.append(scratch)
        if not mount:
            mount = tempfile.mkdtemp(prefix='isolate-temp-')
            self._rmdirs.append(mount)

        self.mounted = False
        self.root = root
        self.scratch = scratch
        self.mount = mount
        self.persist = persist

def open(root='/',
         mount=None,
         scratch=None,
         persist=None):

    return Isolate(root=root,
                   mount=mount,
                   scratch=scratch,
                   persist=persist)


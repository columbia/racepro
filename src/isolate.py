import os
import sys
import tempfile
import subprocess

class Isolate:

    def execute(self, command, chroot=True):
        if not self.mounted:
            raise OSError 
        return subprocess.call(['sudo', 'chroot', self.mount])
        if not chroot:
            cmd = command.split()
        else:
            pre = 'sudo chroot %s /bin/bash -c' % self.mount
            cmd = pre.split()
            cmd.append('"cd %s; exec %s"' % (os.getcwd(), ' '.join(command)))
        print('cmd = %s' % cmd)
        return subprocess.call(cmd)

    def scratch_path(self):
        return self.scratch

    def mount_path(self):
        return self.mount

    def __umount_dirs(self):
        cmd = 'sudo umount %s/proc' % self.mount
        subprocess.call(cmd.split())
        cmd = 'sudo umount %s/dev' % self.mount
        subprocess.call(cmd.split())
        if self.persist:
            cmd = 'umount -o bind %s/%s' % (self.mount, self.persist)
            subprocess.call(cmd.split())

    def __mount_dirs(self):
        cmd = 'sudo mount -o bind /proc %s/proc' % self.mount
        subprocess.call(cmd.split())
        cmd = 'sudo mount -o bind /dev %s/dev' % self.mount
        subprocess.call(cmd.split())
        if self.persist:
            cmd = 'sudo mount -o bind %s %s/%s' % \
                (self.persist, self.mount, self.persist)
            subprocess.call(cmd.split())

    def __close(self):
        cmd = 'sudo fusermount -u %s' % (self.mount)
        ret = subprocess.call(cmd.split())
        if ret != 0:
            print('fusertmount -u %s: failed with exit %d' % (self.mount, ret))
            return False
        return True

    def __open(self):
        cmd = \
            'sudo unionfs-fuse' + \
            ' -o cow,allow_other,use_ino,suid,dev,nonempty,max_files=32768' + \
            ' %s=rw:%s=ro %s' % (self.scratch, self.root, self.mount)
        print(cmd)
        ret = subprocess.call(cmd.split())
        if ret != 0:
            print('unionfs-fuse of "%s", "%s" --> "%s": failed with exit %d' %
                  (self.root, self.scratch, self.mount, ret))
            return False
        return True

    def __exit__(self, type, value, tb):
        self.mounted = False
        self.__umount_dirs()
        self.__close()

    def __enter__(self):
        self.__open()
        self.__mount_dirs()
        self.mounted = True
        return self

    def __init__(self,
                 root='/',
                 mount=None,
                 scratch=None,
                 persist=None):

        if not scratch:
            scratch = tempfile.mkdtemp(prefix='isolate-temp-')
        if not mount:
            mount = tempfile.mkdtemp(prefix='isolate-temp-')

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


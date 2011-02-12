import sys
import mmap
import scribe

class Process:
    def __init__(self, pid):
        self.pid = pid
        self.name = '-'
        self.events = list()
        self.syscall = None
        
class Resource:
    def __init__(self, event):
        self.type = event.type
        self.id = event.id
        self.events = list()

class Session:

    def __init__(self, logfile):
        self.process_map = dict()
        self.process_list = list()
        self.resource_map = dict()
        self.resource_list = list()
        self.event_list = list()

        m = mmap.mmap(logfile.fileno(), 0, prot=mmap.PROT_READ)
        e = list(scribe.EventsFromBuffer(m, remove_annotations=False))
        m.close()

        # @pid and @proc track current process
        # @i tracks current index in self.events

        proc = None
        pid = 0
        i = -1

        for (info, event) in e:

            i += 1

            if isinstance(event, scribe.EventPid):
                self.event_list.append((info, event, None, 0, None, 0))
                pid = info.pid
                try:
                    proc = self.process_map[pid]
                except:
                    proc = Process(pid)
                    self.process_map[pid] = proc
                    self.process_list.append(proc)
                continue

            if pid == 0:
                self.event_list.append((info, event, None, 0, None, 0))
                continue;

            if isinstance(event, scribe.EventSyscallExtra):
                proc.syscall = i
            elif isinstance(event, scribe.EventSyscallEnd):
                proc.syscall = -1

            if isinstance(event, scribe.EventResourceLockExtra):
                if event.id not in self.resource_map:
                    resource = Resource(event)
                    self.resource_map[event.id] = resource
                    self.resource_list.append(resource)
                resource = self.resource_map[event.id]
                resource.events.append((info, event, i, proc.syscall))

            plen = len(proc.events)
            proc.events.append((info, event, i))

            self.event_list.append((info, event, proc, plen, None, 0))

            if isinstance(event, scribe.EventQueueEof):
                proc = None

        for resource in self.resource_list:
            i = 0
            resource.events.sort(key=lambda ev: ev[1].serial)
            for r in resource.events:
                i += 1
                ev = self.event_list[r[2]]
                self.event_list[r[2]] = (ev[0:3], resource, i)


import scribe
import unistd

NR_send = scribe.__NR_send
NR_sendto = scribe.__NR_sendto
NR_sendmsg = scribe.__NR_sendmsg
NR_recv = scribe.__NR_recv
NR_recvfrom = scribe.__NR_recvfrom
NR_recvmsg = scribe.__NR_recvmsg

class ProcessEvent:
    """An event from the point of view of a process:
    @info: pointer to scribe's info
    @event: pointer to scribe's event
    @index: index of event in global log
    @syscnt: syscall count (per process)
    """
    __slots__ = ('info', 'event', 'index', 'syscnt')

    def __init__(self, info, event, index, syscnt):
        self.info = info
        self.event = event
        self.index = index
        self.syscnt = syscnt

class Process:
    """Describe execution log of a single process.
    @pid: pid of the process
    @ppid: pid of the parent
    @name: name of the program
    @events: (ordered) list of events performed by this process
    @sysind: track current (last) syscall event (temporary)
    @regind: track current (last) regs events (temporary)
    """
    __slots__ = ('pid', 'ppid', 'name', 'events', 'syscnt', 'sysind', 'regind')

    def next_syscall(self, index):
        """Find the next syscall in a process events log"""
        while True:
            index += 1
            event = self.events[index].event
            if isinstance(event, scribe.EventSyscallExtra):
                return index

    def __init__(self, pid):
        self.pid = pid
        self.ppid = None
        self.name = None
        self.events = list()
        self.syscnt = 0
        self.sysind = -1
        self.regind = -1
        
class ResourceEvent:
    """An event from the point of view of a resource:
    @info: pointer to scribe's info
    @event: pointer to scribe's event
    @index: index of event in global log
    @sysind: index of owning syscall in global log
    """
    __slots__ = ('info', 'event', 'index', 'sysind')

    def __init__(self, info, event, index, sysind):
        self.info = info
        self.event = event
        self.index = index
        self.sysind = sysind

class Resource:
    """Describe execution log related to a resource isntance.
    @type: type of resource event
    @subtype: type of specific resource
    @desc: descruption of resource
    @id: unique identifier of the resource
    @events: (ordered) list of events affecting this resource
    """
    __slots__ = ('type', 'subtype', 'desc', 'id', 'events')

    def __init__(self, event):
        self.type = event.type
        self.subtype = event.resource_type
        self.id = event.id
        self.events = list()

class SignalEvent:
    """An event from the point of view of a signal:
    @info: pointer to scribe's info
    @event: pointer to scribe's event
    @index: index of event in global log
    @sysind: index of owning syscall in global log
    """
    __slots__ = ('info', 'event', 'index', 'syscnt')

    def __init__(self, info, event, index, syscnt):
        self.info = info
        self.event = event
        self.index = index
        self.syscnt = syscnt

class SessionEvent:
    """An event from the point of view of a session:
    @info: pointer to scribe's info
    @event: pointer to scribe's event
    @proc: pointer to respective Process
    @pindex: process index of event (in respective Process)
    @resource: pointer to respective Resource
    @rindex: resource index of event (in respective Resource)
    @sysind: global index of owning syscall event
    @regind: global index of owning regs event
    """
    __slots__ = ('info', 'event',
                 'proc', 'pindex',
                 'resource', 'rindex',
                 'sysind', 'regind')

    def __init__(self, info, event,
                 proc, pindex,
                 resource, rindex,
                 sysind, regind):
        self.info = info
        self.event = event
        self.proc = proc
        self.pindex = pindex
        self.resource = resource
        self.rindex = rindex
        self.sysind = sysind
        self.regind = regind

class Session:
    """Describe exceution log of an entire session.

    Parse the scribe log of a session and produce instances of class
    Process and class Resource for each new pid and unique resource
    identifer found.

    @process_map: map a pid to the corresponding Process
    @process_list: list of all Process instances
    @resource_map: map a unique identifier to the coresponding Resource
    @resource_list: list of all Resource instances
    @signals: list of all signals
    @events: list of all events (pointers to Process/Resources)
    @cookie_e: map of all cookie events (signals)
    @clone_e: list of all clone() events
    @wait_e: list of all wait() events
    @exit_e: list of all exit() events
    @pipe_e: all pipe/socket read/write events (keyed by pipe/socket)
    @pipe_d: dictionary mapping pipe/socket peers
    @graph: the corresponding graph when computed
    """

    def __init__(self, events):
        self.process_map = dict()
        self.process_list = list()
        self.resource_map = dict()
        self.resource_list = list()
        self.signals = list()
        self.events = list()

        self.cookie_e = dict()
        self.clone_e = list()
        self.wait_e = list()
        self.exit_e = list()
        self.pipe_e = dict()
        self.pipe_d = dict()

        self._load_events(events)
        self._find_ppid_of_each_proc()
        self._sort_events_for_each_resource()
        self._find_pipes_dependencies()

    def _load_events(self, event_iter):
        """Parse the scribe log from @event_iter"""

        # we also collect for further processing:
        # - wait/exit
        # - pipe/socket read/write
        # - kill/signal

        # @pid and @proc track current process
        # @i tracks current index in self.events
        proc = None
        pid = 0
        ind = -1

        # parse events
        for (info, event) in event_iter:
            ind += 1

            if isinstance(event, scribe.EventPid):
                s_ev = SessionEvent(info, event, None, 0, None, 0, 0, 0)
                self.events.append(s_ev)
                pid = info.pid
                try:
                    proc = self.process_map[pid]
                except:
                    proc = Process(pid)
                    self.process_map[pid] = proc
                    self.process_list.append(proc)
                continue

            if pid == 0:
                s_ev = SessionEvent(info, event, None, 0, None, 0, 0, 0)
                self.events.append(s_ev)
                continue

            if isinstance(event, scribe.EventRegs):
                proc.regind = ind

            elif isinstance(event, scribe.EventSyscallExtra):
                proc.sysind = ind
                proc.syscnt += 1
                # NOTE: track separately of certain syscalls: we also
                # collect all wait/exit for further processing
                # TODO: also add kill/signal
                if event.nr in unistd.Syscalls.SYS_exit:
                    self.exit_e.append(ind)
                elif event.nr in unistd.Syscalls.SYS_wait:
                    self.wait_e.append(ind)
                elif event.nr in unistd.Syscalls.SYS_fork:
                    self.clone_e.append(ind)

            elif isinstance(event, scribe.EventSyscallEnd):
                proc.regind = -1
                proc.sysind = -1

            elif isinstance(event, scribe.EventResourceLockExtra):
                if event.id not in self.resource_map:
                    resource = Resource(event)
                    self.resource_map[event.id] = resource
                    self.resource_list.append(resource)
                resource = self.resource_map[event.id]
                r_ev = ResourceEvent(info, event, ind, proc.sysind)
                resource.events.append(r_ev)

            elif isinstance(event, scribe.EventSignal):
                sig_ev = SignalEvent(info, event, ind, proc.syscnt + 1)
                self.signals.append(sig_ev)

            elif isinstance(event, scribe.EventSigSendCookie):
                sig_ev = SignalEvent(info, event, ind, proc.syscnt + 1)
                if event.cookie in self.cookie_e:
                    send, recv = self.cookie_e[event.cookie]
                else:
                    send, recv = None, None
                send = sig_ev
                self.cookie_e[event.cookie] = (send, recv)

            elif isinstance(event, scribe.EventSigRecvCookie):
                sig_ev = SignalEvent(info, event, ind, proc.syscnt + 1)
                if event.cookie in self.cookie_e:
                    send, recv = self.cookie_e[event.cookie]
                else:
                    send, recv = None, None
                recv = sig_ev
                self.cookie_e[event.cookie] = (send, recv)

            s_ev = SessionEvent(info, event, proc, len(proc.events),
                                None, 0, proc.sysind, proc.regind)
            self.events.append(s_ev)

            p_ev = ProcessEvent(info, event, ind, proc.syscnt)
            proc.events.append(p_ev)

            if isinstance(event, scribe.EventQueueEof):
                proc = None

    def _find_ppid_of_each_proc(self):
        """ find the ppid of each process """
        for ind in self.clone_e:
            event = self.events[ind].event
            if event.ret > 0:
                # XXX if this log was generated by raceproc, _and_
                # syscall moved earlier was a fork/clone, _then_ the
                # log will have an entry for the fork/clone, but there
                # not be even a single event from the child (because
                # we will log will "single-step" the syscall) - so we
                # tolerate bogus pid (event.ret)...
                if event.ret not in self.process_map:
                    continue
                self.process_map[event.ret].ppid = self.events[ind].proc.pid

    def _sort_events_for_each_resource(self):
        for resource in self.resource_list:
            ind = 0
            resource.events.sort(key=lambda s_ev: s_ev.event.serial)
            for r_ev in resource.events:
                s_ev = self.events[r_ev.index]
                s_ev.resource = resource
                s_ev.rindex = ind
                ind += 1

    def _find_pipes_dependencies(self):
        # extended read/write set - good for pipes and sockets
        SYS_read_ext = unistd.Syscalls.SYS_read.union(
            set([NR_recv, NR_recvfrom, NR_recvmsg]))
        SYS_write_ext = unistd.Syscalls.SYS_write.union(
            set([NR_send, NR_sendto, NR_sendmsg]))

        for resource in self.resource_list:
            event = resource.events[0].event
            if event.resource_type != scribe.SCRIBE_RES_TYPE_FILE:
                continue
            if not 'pipe:' in event.desc and not 'socket:' in event.desc:
                continue
            if 'pipe' in event.desc:
                self.pipe_d[event.desc] = event.desc

            # sockets have inodes: R of one matches W of the other and
            # vice versa. @desc is "inode1 inode2" or vice versa. by
            # reversing only one side (e.g. writing) we matcn them :)
            for r_ev in resource.events:
                desc = r_ev.event.desc
                if 'socket:' in desc:
                    desc, other = (desc.split() + [None])[0:2]
                    if other:
                        self.pipe_d[desc] = other
                        self.pipe_d[other] = desc
                si = self.events[r_ev.index].sysind
                sc = self.get_syscall(si)
                if sc.ret >= 0:
                    if desc not in self.pipe_e:
                        self.pipe_e[desc] = (list(), list())  # R, W
                    if desc in self.pipe_d and self.pipe_d[desc] not in self.pipe_e:
                        self.pipe_e[self.pipe_d[desc]] = (list(), list())  # R, W
                    if sc.nr in SYS_write_ext and desc in self.pipe_d:
                        self.pipe_e[self.pipe_d[desc]][1].append((r_ev, sc.ret))
                    elif sc.nr in SYS_read_ext:
                        if 'socket' in desc and sc.ret > 0: assert desc
                        self.pipe_e[desc][0].append((r_ev, sc.ret))


    def s_ev_to_proc(self, s_ev, syscnt=False):
        if syscnt:
            index = s_ev.proc.events[s_ev.pindex].syscnt
        else:
            index = s_ev.pindex
        return s_ev.proc, index

    def r_ev_to_proc(self, r_ev, sysind=False):
        if sysind:
            s_ev = self.events[r_ev.sysind]
        else:
            s_ev = self.events[r_ev.index]
        return (s_ev.proc, s_ev.pindex)

    def get_syscall(self, index):
        sysind = self.events[index].sysind
        return self.events[sysind].event

    def next_syscall(self, index):
        proc = self.events[index].proc
        pindex = self.events[index].pindex
        pindex = proc.next_syscall(pindex)
        return proc.events[pindex].index

    def get_syscall_events(self, index, which=None):
        """Given an event, find the owning syscall, and return all the
        events of of a certain type (which) that belong the that syscall.
        If @which == None, return all of them.
        """
        events = list()

        sysind = self.events[index].sysind
        proc = self.events[sysind].proc
        pindex = self.events[sysind].pindex

        event = proc.events[pindex].event
        while not isinstance(event, scribe.EventSyscallEnd):
            if not which or isinstance(event, which):
                events.append((event, proc.events[pindex].index))
            pindex += 1
            event = proc.events[pindex].event

        return events

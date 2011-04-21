import scribe
import unistd
import itertools
import re

class Event(object):
    def __init__(self, scribe_event):
        self._scribe_event = scribe_event
        self.proc = None
        self.owners = dict()

    def __repr__(self):
        return repr(self._scribe_event)

    def __str__(self):
        return str(self._scribe_event)

    @property
    def children(self):
        # The children list is generated on the fly.
        # Only a syscall event gets to have some fun
        if self.proc is None:
            raise AttributeError
        if not self.is_a(scribe.EventSyscallExtra):
            raise AttributeError
        return itertools.takewhile(
                lambda e: not e.is_a(scribe.EventSyscallEnd),
                self.proc.events.after(self))

    @property
    def syscall(self):
        return self._syscall
    @syscall.setter
    def syscall(self, value):
        self._syscall = value

    @property
    def syscall_index(self):
        if self.proc is None:
            raise AttributeError
        index = self.proc.syscalls.index(self)
        if index == -1:
            raise AttributeError
        return index

    @property
    def resource(self):
        return self._resource
    @resource.setter
    def resource(self, value):
        self._resource = value

    # Proxying attributes getters to the scribe event instance
    def __getattr__(self, name):
        return getattr(self._scribe_event, name)
    def is_a(self, klass):
        return isinstance(self._scribe_event, klass)

class EventList:
    def __init__(self):
        self._events = list()

    def __iter__(self):
        return iter(self._events)

    def __len__(self):
        return len(self._events)

    def add(self, e):
        e.owners[self] = len(self._events)
        self._events.append(e)

    def index(self, e):
        try:
            return e.owners[self]
        except KeyError:
            return -1

    def after(self, e):
        i = e.owners[self]
        return (self._events[j] for j in xrange(i + 1, len(self)))

    def before(self, e):
        i = e.owners[self]
        return (self._events[j] for j in xrange(i - 1, -1, -1))

    def sort(self, key):
        self._events.sort(key=key)
        self._indices_have_changed()

    def _indices_have_changed(self):
        # Called when the event list has been re-ordered, and the indices
        # need to be reset
        for i in xrange(0, len(self._events)):
            self._events[i].owners[self] = i

class Process:
    def __init__(self, pid, parent=None, name=None):
        self.pid = pid
        self.parent = parent
        self.name = name
        self.events = EventList()
        self.syscalls = EventList()

        # State for add_event()
        self.current_syscall = None

    def add_event(self, e):
        self.events.add(e)
        e.proc = self

        def check_execve(syscall):
            if syscall.nr != unistd.NR_execve:
                return
            if syscall.ret < 0:
                return
            for e in syscall.children:
                if not e.is_a(scribe.EventDataExtra):
                    continue
                if e.data_type != scribe.SCRIBE_DATA_INPUT | \
                                  scribe.SCRIBE_DATA_STRING:
                    continue
                self.name = e.data
                break

        if e.is_a(scribe.EventSyscallExtra):
            self.syscalls.add(e)
            self.current_syscall = e
        elif e.is_a(scribe.EventSyscallEnd):
            check_execve(self.current_syscall)
            self.current_syscall = None
        elif self.current_syscall is not None:
            e.syscall = self.current_syscall

    def __str__(self):
        return "pid=%d (%s)" % (self.pid, self.name if self.name else "??")

    def __repr__(self):
        return "<Process pid=%d name='%s' events=%d>" % \
                   (self.pid,
                    self.name if self.name else "??",
                    len(self.events))

class Resource:
    def __init__(self):
        # The id, type, desc will be set after the first event gets added
        self.id = None
        self.type = None
        self.desc = None
        self.events = EventList()

    def add_event(self, e):
        self.events.add(e)

        assert e.is_a(scribe.EventResourceLockExtra)
        e.resource = self

        if self.id is None:
            self.id = e.id
            self.type = e.type
            self.desc = e.desc
        else:
            assert self.id == e.id
            assert self.type == e.type
            # desc might change for sockets, we'll keep the longest desc in
            # the resource lifetime to easily track the socket peers
            if len(e.desc) > len(self.desc):
                self.desc = e.desc

    def sort_events_by_serial(self):
        self.events.sort(key=lambda e: e.serial)

    def __repr__(self):
        if self.id is None:
            return "<Resource not initialized>"
        return "<Resource id=%d type=%d desc='%s' events=%d>" % \
               (self.id, self.type, self.desc, len(self.events))

class Fifo:
    """ A Fifo represents a uni-directional data stream.
    A regular pipe is represented with one fifo, and a socket with two fifos.
    """
    @staticmethod
    def find_fifos(resources):
        # First we want to group resources that belongs to the same fifo
        fifo_res = dict()
        def got_fifo_res(key, res):
            fifo_res.setdefault(key, list()).append(res)

        pipe_re = re.compile('^pipe:\[(.*)\]$')
        sock_re = re.compile('^socket:\[(.*)\] socket:\[(.*)\]$')
        for res in resources.itervalues():
            if res.type != scribe.SCRIBE_RES_TYPE_FILE:
                continue

            pipe_inode = pipe_re.findall(res.desc)
            if pipe_inode:
                got_fifo_res(pipe_inode[0], res)
                continue

            sock_inodes = sock_re.findall(res.desc)
            if sock_inodes:
                # sorting because we need 'socket:[1] socket:[2]'
                # and 'socket:[2] socket:[1]' to map to the same key
                got_fifo_res(tuple(sorted(sock_inodes[0])), res)
                print(sorted(sock_inodes[0]))

        # Then we create the fifos
        fifos = list()
        for lres in fifo_res.itervalues():
            # We only want fifos which have both endpoints in the session
            assert(len(lres) <= 2)
            if len(lres) != 2:
                continue

            # We'll try both endpoints as (src, dst) and (dst, src) and
            # keep only the one(s) that makes sense.
            # pipes should have one fifo valid, whereas sockets can have
            # two fifos.
            for src, dst in [(lres[0], lres[1]),
                             (lres[1], lres[0])]:
                f = Fifo(src, dst)
                if len(f.reads) or len(f.writes):
                    fifos.append(f)
        return fifos

    def __init__(self, src_res, dst_res):
        self.reads = EventList()
        self.writes = EventList()

        for res, el, nr in [(src_res, self.writes, unistd.SYS_ext_write),
                            (dst_res, self.reads,  unistd.SYS_ext_read)]:
            for e in res.events:
                sys = e.syscall
                if sys.nr in nr:
                    el.add(sys)

class Signal:
    @staticmethod
    def find_signals(events):
        cookies = dict()

        def got_a_cookie(e, type):
            cookies.setdefault(e.cookie, dict())[type] = e

        for e in events:
            if e.is_a(scribe.EventSigSendCookie):
                   got_a_cookie(e, 'send')
            elif e.is_a(scribe.EventSigRecvCookie):
                   got_a_cookie(e, 'recv')
            elif e.is_a(scribe.EventSigHandledCookie):
                   got_a_cookie(e, 'handled')

        signals = list()
        for sig in cookies.itervalues():
            if not sig.has_key('send'):
                raise ValueError('Found a signal without a send cookie')
            if not sig.has_key('recv'):
                raise ValueError('Found a signal without a recv cookie')
            sig.setdefault('handled', None)
            signals.append(Signal(**sig))
        return signals

    def __init__(self, send, recv, handled):
        self.send = send
        self.recv = recv
        self.handled = handled

class Session:
    def __init__(self, scribe_events):
        self.processes = dict()
        self.resources = dict()
        self.events = EventList()

        # process all events. It constructs the resource and processes maps
        self._current_proc = None # State for add_event()
        for se in scribe_events:
            assert isinstance(se, scribe.Event)
            self._add_event(Event(se))

        # Sort all the resource event by serial number
        for res in self.resources.itervalues():
            res.sort_events_by_serial()

        # Find fifo (pipes and sockets) dependencies
        self.fifos = Fifo.find_fifos(self.resources)

        # Lookup all internal signals
        self.signals = Signal.find_signals(self.events)

    def _add_event(self, e):
        # the add_event() method is made private because we need to do extra
        # processing after an event is added.

        self.events.add(e)

        # pid switcher logic
        if e.is_a(scribe.EventPid):
            if e.pid not in self.processes:
                self.processes[e.pid] = Process(pid=e.pid)

            self._current_proc = self.processes[e.pid]
            return

        if e.is_a(scribe.EventResourceLockExtra):
            if e.id not in self.resources:
                self.resources[e.id] = Resource()
            self.resources[e.id].add_event(e)

        if self._current_proc:
            self._current_proc.add_event(e)

    @property
    def init_proc(self):
        return self.processes[1]

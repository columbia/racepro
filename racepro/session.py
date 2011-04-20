import scribe
import unistd
import itertools
import re

class Event(object):
    def __init__(self, scribe_event):
        self.scribe = scribe_event
        self.proc = None
        self.owners = dict()

    def __repr__(self):
        return "Event(%s)" % repr(self.scribe)

    def __str__(self):
        return str(self.scribe)

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
        index = self.proc.syscalls.index_of(self)
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
        return getattr(self.scribe, name)
    def is_a(self, klass):
        return isinstance(self.scribe, klass)

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

    def index_of(self, e):
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
            assert self.desc == e.desc

    def sort_events_by_serial(self):
        self.events.sort(key=lambda e: e.serial)

    def __repr__(self):
        if self.id is None:
            return "<Resource not initialized>"
        return "<Resource id=%d type=%d desc='%s' events=%d>" % \
               (self.id, self.type, self.desc, len(self.events))

class Pipe:
    def __init__(self, resources):
        assert len(resources) == 2
        self.id = int(re.findall('pipe:\[(.*)\]', resources[0].desc)[0])
        self.reads = EventList()
        self.writes = EventList()

        for res in resources:
            for e in res.events:
                sys = e.syscall
                if sys.ret <= 0:
                    continue
                if sys.nr in unistd.SYS_read:
                    self.reads.add(sys)
                elif sys.nr in unistd.SYS_write:
                    self.writes.add(sys)

class Session:
    def __init__(self, scribe_events):
        self.processes = dict()
        self.resources = dict()
        self.pipes = dict()
        self.events = EventList()
        self.current_proc = None # State for add_event()

        for se in scribe_events:
            assert isinstance(se, scribe.Event)
            self._add_event(Event(se))

        self._find_parent_of_each_proc()
        self._sort_events_for_each_resource()
        self._find_pipe_dependencies()

    def _add_event(self, e):
        # the add_event() method is made private because we need to do extra
        # processing after an event is added.

        self.events.add(e)

        # pid switcher logic
        if e.is_a(scribe.EventPid):
            if e.pid not in self.processes:
                self.processes[e.pid] = Process(pid=e.pid)

            self.current_proc = self.processes[e.pid]
            return

        if e.is_a(scribe.EventResourceLockExtra):
            if e.id not in self.resources:
                self.resources[e.id] = Resource()
            self.resources[e.id].add_event(e)

        if self.current_proc:
            self.current_proc.add_event(e)

    def _find_parent_of_each_proc(self):
        for proc in self.processes.itervalues():
            for sys in proc.syscalls:
                if sys.nr in unistd.SYS_fork:
                  new_pid = sys.ret
                  if new_pid in self.processes:
                      self.processes[new_pid].parent = proc

    def _sort_events_for_each_resource(self):
        for res in self.resources.itervalues():
            res.sort_events_by_serial()

    def _find_pipe_dependencies(self):
        self.pipes = dict()
        pipe_res = dict()
        for res in self.resources.itervalues():
            if 'pipe:' in res.desc:
                pipe_res.setdefault(res.desc, list()).append(res)

        for lres in pipe_res.itervalues():
            p = Pipe(lres)
            self.pipes[p.id] = p

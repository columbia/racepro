import scribe
import unistd
import itertools

class Event:
    def __init__(self, event):
        self.event = event
        self.proc = None
        self.owners = dict()

    def __repr__(self):
        return "Event(%s)" % repr(self.event)

    def __str__(self):
        return str(self.event)

    @property
    def children(self):
        # The children list is generated on the fly.
        # Only a syscall event gets to have some fun
        if self.proc is None:
            raise AttributeError
        if not isinstance(self.event, scribe.EventSyscallExtra):
            raise AttributeError
        return itertools.takewhile(
                lambda e: not isinstance(e.event, scribe.EventSyscallEnd),
                self.proc.events.after(self))

    @property
    def syscall(self):
        # The real value will be replaced by Process.add_event()
        raise AttributeError

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
        # The real value will be replaced by Resource.add_event()
        raise AttributeError

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
            if syscall.event.nr != unistd.NR_execve:
                return
            if syscall.event.ret < 0:
                return
            for e in syscall.children:
                se = e.event
                if not isinstance(se, scribe.EventDataExtra):
                    continue
                if se.data_type != scribe.SCRIBE_DATA_INPUT | \
                                   scribe.SCRIBE_DATA_STRING:
                    continue
                self.name = se.data
                break

        if isinstance(e.event, scribe.EventSyscallExtra):
            self.syscalls.add(e)
            self.current_syscall = e
        elif isinstance(e.event, scribe.EventSyscallEnd):
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

        se = e.event
        assert isinstance(se, scribe.EventResourceLockExtra)
        e.resource = self

        if self.id is None:
            self.id = se.id
            self.type = se.type
            self.desc = se.desc
        else:
            assert self.id == se.id
            assert self.type == se.type
            assert self.desc == se.desc

    def sort_events_by_serial(self):
        self.events.sort(key=lambda e: e.event.serial)

    def __repr__(self):
        if self.id is None:
            return "<Resource not initialized>"
        return "<Resource id=%d type=%d desc='%s' events=%d>" % \
               (self.id, self.type, self.desc, len(self.events))

class Session:
    def __init__(self, scribe_events):
        self.processes = dict()
        self.resources = dict()
        self.events = EventList()
        self.current_proc = None # State for add_event()

        for se in scribe_events:
            self._add_event(Event(se))
        self._find_parent_of_each_proc()
        self._sort_events_for_each_resource()

    def _add_event(self, e):
        # the add_event() method is made private because we need to do extra
        # processing after an event is added.

        self.events.add(e)
        se = e.event

        # pid switcher logic
        if isinstance(se, scribe.EventPid):
            pid = se.pid
            if pid not in self.processes:
                self.processes[pid] = Process(pid=pid)

            self.current_proc = self.processes[pid]
            return

        if isinstance(se, scribe.EventResourceLockExtra):
            id = se.id
            if id not in self.resources:
                self.resources[id] = Resource()
            self.resources[id].add_event(e)

        if self.current_proc:
            self.current_proc.add_event(e)

    def _find_parent_of_each_proc(self):
        for proc in self.processes.itervalues():
            for sys in proc.syscalls:
                if sys.event.nr in unistd.SYS_fork:
                  new_pid = sys.event.ret
                  if new_pid in self.processes:
                      self.processes[new_pid].parent = proc

    def _sort_events_for_each_resource(self):
        for resource in self.resources.itervalues():
            resource.sort_events_by_serial()

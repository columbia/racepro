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
        # The real value will be replaced by Process.EventList.add()
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
        # The real value will be replaced by Resource.EventList.add()
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

    def _indices_have_changed(self):
        # Called when the event list has been re-ordered, and the indices
        # need to be reset
        for i in xrange(0, len(self._events)):
            self._events[i].owners[self] = i

class Process:
    class EventList(EventList):
        def __init__(self, proc):
            EventList.__init__(self)
            self.proc = proc
            self.current_syscall = None

        def add(self, e):
            EventList.add(self, e)
            e.proc = self.proc

            if isinstance(e.event, scribe.EventSyscallExtra):
                self.proc.syscalls.add(e)
                self.current_syscall = e
            elif isinstance(e.event, scribe.EventSyscallEnd):
                self._check_execve(self.current_syscall)
                self.current_syscall = None
            elif self.current_syscall is not None:
                e.syscall = self.current_syscall

        def _check_execve(self, syscall):
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
                self.proc.name = se.data
                break


    def __init__(self, pid, parent=None, name=None):
        self.pid = pid
        self.parent = parent
        self.name = name
        self.events = Process.EventList(self)
        self.syscalls = EventList()

    def __str__(self):
        return "pid=%d (%s)" % (self.pid, self.name if self.name else "??")

    def __repr__(self):
        return "<Process pid=%d name='%s' events=%d>" % \
                   (self.pid,
                    self.name if self.name else "??",
                    len(self.events))

class Resource:
    class EventList(EventList):
        def __init__(self, resource):
            EventList.__init__(self)
            self.resource = resource

        def add(self, e):
            EventList.add(self, e)
            resource = self.resource

            se = e.event
            assert isinstance(se, scribe.EventResourceLockExtra)
            e.resource = resource

            if resource.id is None:
                resource.id = se.id
                resource.type = se.type
                resource.desc = se.desc
            else:
                assert resource.id == se.id
                assert resource.type == se.type
                assert resource.desc == se.desc

        def sort_by_serial(self):
            self._events.sort(key=lambda e: e.event.serial)
            self._indices_have_changed()

    def __init__(self):
        # The id, type, desc will be set after the first event gets added
        self.id = None
        self.type = None
        self.desc = None
        self.events = Resource.EventList(self)

    def __repr__(self):
        if self.id is None:
            return "<Resource not initialized>"
        return "<Resource id=%d type=%d desc='%s' events=%d>" % \
               (self.id, self.type, self.desc, len(self.events))

class Session:
    class EventList(EventList):
        def __init__(self, session):
            EventList.__init__(self)
            self.session = session
            self.current_proc = None

        def add(self, e):
            EventList.add(self, e)
            se = e.event
            session = self.session

            # pid switcher logic
            if isinstance(se, scribe.EventPid):
                pid = se.pid
                if pid not in session.processes:
                    session.processes[pid] = Process(pid=pid)

                self.current_proc = session.processes[pid]
                return

            if isinstance(se, scribe.EventResourceLockExtra):
                id = se.id
                if id not in session.resources:
                    session.resources[id] = Resource()
                session.resources[id].events.add(e)

            if self.current_proc:
                self.current_proc.events.add(e)

    def __init__(self, scribe_events):
        self.processes = dict()
        self.resources = dict()
        self.events = Session.EventList(self)

        self._load_events(scribe_events)
        self._find_parent_of_each_proc()
        self._sort_events_for_each_resource()

    def _load_events(self, scribe_events):
        for se in scribe_events:
            self.events.add(Event(se))

    def _find_parent_of_each_proc(self):
        for e in self.events:
            se = e.event
            if isinstance(se, scribe.EventSyscallExtra):
                if se.nr in unistd.SYS_fork:
                    new_pid = se.ret
                    if new_pid in self.processes:
                        self.processes[new_pid].parent = e.proc

    def _sort_events_for_each_resource(self):
        for resource in self.resources.values():
            resource.events.sort_by_serial()

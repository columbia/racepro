import sys
import mmap
import scribe
import unistd
import networkx

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
    @name: name of the program
    @events: (ordered) list of events performed by this process
    @sys: track current (last) syscall event (temporary)
    @reg: track current (last) regs events (temporary)
    """
    __slots__ = ('pid', 'name', 'events', 'count', 'sysind', 'regind')

    def __init__(self, pid):
        self.pid = pid
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
    @type: type of resource
    @id: unique identifier of the resource
    @events: (ordered) list of events affecting this resource
    """
    __slots__ = ('type', 'id', 'events')

    def __init__(self, event):
        self.type = event.type
        self.id = event.id
        self.events = list()

class Action:
    """Describe an action to be injected into a log"""

    def __init__(self, action = None, arg1 = None):
        self.action = action
        self.arg1 = arg1

class SessionEvent:
    """An event from the point of view of a session:
    @info: pointer to scribe's info
    @event: pointer to scribe's event
    @proc: pointer to respective Process
    @pindex: index of event inside respective Process
    @resource: pointer to respective Resource
    @rindex: index of event inside respective Resource
    @sysind: index of owning syscall event
    @regind: index of owning regs event
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
    @process_list: list of all Resource instances
    @events_list: list of all events (pointers to Process/Resources)
    """

    # helpers

    def r_ev_to_proc(self, r_ev):
        return self.events_list[r_ev.index].proc

    def r_ev_to_pindex(self, r_ev):
        return self.events_list[r_ev.index].pindex

    # order of arguments: ebx, ecx, edx, esi ...

    def parse_syscall(self, i, j):
        """Parse a syscall event"""

        e_syscall = self.events_list[i].event
        e_data = self.events_list[i+1].event
        args = self.events_list[j].event.args
        ret = unistd.syscall_ret(syscall.ret)

        if e_syscall.nr == unistd.Syscalls.NR_open:
            print('[%d] open("%s", %#x, %#3o) = %ld' %
                  (i, e_data.data, args[1], args[2], ret))
        if e_syscall.nr == unistd.Syscalls.NR_close:
            print('[%d] close(%d) = %ld' %
                  (i, args[0], ret))
        if e_syscall.nr == unistd.Syscalls.NR_access:
            print('[%d] access("%s", %#3o) = %ld' %
                  (i, e_data.data, args[0], ret))
        if e_syscall.nr == unistd.Syscalls.NR_execve:
            print('[%d] execve("%s", %#x, %#x) = %ld' %
                  (i, e_data.data, args[0], args[1], ret))
        if e_syscall.nr == unistd.Syscalls.NR_stat:
            print('[%d] stat("%s", %#x) = %ld' %
                  (i, e_data.data, args[0], ret))
        if e_syscall.nr == unistd.Syscalls.NR_stat64:
            print('[%d] stat64("%s", %#x, %#x) = %ld' %
                  (i, e_data.data, args[0], args[1], ret))

    def print_process(self, pid):
        """Print all the events of a process"""
        try:
            proc = self.process_map[pid]
        except KeyError:
            print('No such process with pid %d' % (pid))
            return

        for p_ev in proc.events:
            if isinstance(p_ev.event, scribe.EventSyscallExtra):
                ev = self.events_list[i]
                self.parse_syscall(p_ev.sysind, p_ev.regind)

    def load_events(self, logfile):
        """Parse the scribe log from @logfile"""

        m = mmap.mmap(logfile.fileno(), 0, prot=mmap.PROT_READ)
        e = list(scribe.EventsFromBuffer(m, remove_annotations=False))
        m.close()

        # @pid and @proc track current process
        # @i tracks current index in self.events
        proc = None
        pid = 0
        ind = -1

        # parse events
        for (info, event) in e:
            ind += 1

            if isinstance(event, scribe.EventPid):
                s_ev = SessionEvent(info, event, None, 0, None, 0, 0, 0)
                self.events_list.append(s_ev)
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
                self.events_list.append(s_ev)
                continue;

            if isinstance(event, scribe.EventRegs):
                proc.regind = ind
            elif isinstance(event, scribe.EventSyscallExtra):
                proc.syscnt += 1
                proc.sysind = ind
            elif isinstance(event, scribe.EventSyscallEnd):
                proc.regind = -1
                proc.sysind = -1

            if isinstance(event, scribe.EventResourceLockExtra):
                if event.id not in self.resource_map:
                    resource = Resource(event)
                    self.resource_map[event.id] = resource
                    self.resource_list.append(resource)
                resource = self.resource_map[event.id]
                r_ev = ResourceEvent(info, event, ind, proc.sysind)
                resource.events.append(r_ev)

            s_ev = SessionEvent(info, event, proc, len(proc.events),
                                None, 0, proc.sysind, proc.regind)
            self.events_list.append(s_ev)

            p_ev = ProcessEvent(info, event, ind, proc.syscnt)
            proc.events.append(p_ev)

            if isinstance(event, scribe.EventQueueEof):
                proc = None

        # sort events per resource
        for resource in self.resource_list:
            ind = 0
            resource.events.sort(key=lambda s_ev: s_ev.event.serial)
            for r_ev in resource.events:
                s_ev = self.events_list[r_ev.index]
                s_ev.resource = resource
                s_ev.rindex = ind
                ind += 1

    def save_events(self, logfile,
                    pid_bookmark = None,
                    pid_cutoff = None,
                    pid_inject = None):
        """Write the (perhaps modified) scribe log to @logfile

        Write out the scribe log while potentially modifying it. Two
        types of modifications exist: "inject", to inject new events
        (per process) into the log , and "cutoff", which specifies
        locations (per process) to cut remaining log.

        @logfile: output file object (opened for binary write)
        @pid_bookmark: indicates the syscall at which to add bookmark
          { pid:syscall } (negative/positive -> before/after syscall)
        @pid_inject: indicate actions to inject to the log
          { pid:[action1,action2,...] }
        @pid_cutoff: indicate the syscall at which to cut the log
          { pid:syscall } (negative/positive -> before/after syscall)
        """

        pid_active = dict()
        pid_syscall = dict()
        pid_eoq = dict({0:False})

        if pid_bookmark is None:
            pid_bookmark = dict()
        if pid_inject is None:
            pid_inject = dict()
        if pid_cutoff is None:
            pid_cutoff = dict()

        for s_ev in self.events_list:
            info = s_ev.info
            event = s_ev.event
            pid = info.pid

            # pid first time ?
            if pid not in pid_active:
                pid_active[pid] = True
                pid_syscall[pid] = 0
                pid_eoq[pid] = False
                if pid not in pid_bookmark:
                    pid_bookmark[pid] = 0
                if pid not in pid_cutoff:
                    pid_cutoff[pid] = 0
                if pid not in pid_inject:
                    pid_inject[pid] = dict()

            assert not pid_eoq[pid] or pid == 0, \
                'Event for pid %d after eoq' % (pid)

            # pid inactive ?
            if not pid_active[pid]:
                continue

            # ignore original bookmarks
            if isinstance(event, scribe.EventBookmark):
                continue

            if isinstance(event, scribe.EventSyscallEnd):
                if pid_syscall[pid] == pid_bookmark[pid]:
                    print('[%d] add bookmark after syscall %d' \
                              % (pid, pid_syscall[pid]))
                    e = scribe.EventBookmark()
                    e.id = 0
                    e.npr = len(pid_bookmark)
                    logfile.write(e.encode())
                    pid_active[pid] = False
                    continue;

            if isinstance(event, scribe.EventSyscallExtra):
                pid_syscall[pid] += 1

                # pid bookmark ?
                if pid_syscall[pid] == -pid_bookmark[pid]:
                    print('[%d] add bookmark before syscall %d' \
                              % (pid, -pid_syscall[pid]))
                    e = scribe.EventBookmark()
                    e.id = 0
                    e.npr = len(pid_bookmark)
                    logfile.write(e.encode())
                    pid_active[pid] = False
                    continue;

                # pid inject ?
                if pid_syscall[pid] in pid_inject[pid]:
                    print('[%d] inject at syscall %d' \
                              % (pid, pid_syscall[pid]))
                    for a in pid_inject[pid].itervalues():
                        e = scribe.EventInjectAction()
                        e.action = a.action
                        e.arg1 = a.arg1
                        logfile.write(e.encode())
                    pid_active[pid] = False
                    continue

                # pid enough ?
                if pid_syscall[pid] == pid_cutoff[pid]:
                    print('[%d] cutoff at syscall %d' \
                              % (pid, pid_cutoff[pid]))
                    pid_active[pid] = False
                    continue

            if isinstance(event, scribe.EventQueueEof):
                pid_eoq[pid] = True
                pid_active[pid] = False

            logfile.write(event.encode())

        # indicate go-live where needed
        for pid in pid_active:
            if not pid_eoq[pid]:
                e = scribe.EventPid()
                e.pid = pid
                logfile.write(e.encode())
                e = scribe.EventQueueEof()
                logfile.write(e.encode())

##############################################################################
#   generate thread calls graph (fork,exit,wait,syscalls)

    def __make_node(self, pid, syscall):
        return str(pid) + ':' + str(syscall)

    def __build_graph(self, graph, proc, full=False):
        """Build the execution DAG from the execution log, as follows:
        - The first node is '0'
        - New processes begin with a node 'pid'
        - Syscalls add a node 'pid:syscall' (and edge from previous)
        - Syscall fork() creates a new process and an edge to it 
        - Syscall exit() adds a node 'pid:exit' (and edge from previous)
        - Syscall wait() adds an edge from the child's exit() syscall
        - Node attribute 'event=str(I)' for event index in global list
        - Resource access add edge from the previous user to current
        (note: attributes must be strings)
        """
        pid = proc.pid
        ancestor = str(pid)
        for p_ev in proc.events:
            event = p_ev.event
            if not isinstance(event, scribe.EventSyscallExtra):
                continue
            if event.nr in unistd.Syscalls.SYS_fork and event.ret >= 0:
                newpid = event.ret
                parent = self.__make_node(pid, p_ev.syscnt)
                graph.add_node(parent, index=str(p_ev.index))
                graph.add_edge(ancestor, parent)
                child = self.__make_node(newpid, 0)
                graph.add_node(child)
                graph.add_edge(parent, child)
                self.__build_graph(graph, self.process_map[newpid], full)
                ancestor = parent
            elif event.nr in unistd.Syscalls.SYS_wait and event.ret >= 0:
                newpid = event.ret
                node = self.__make_node(pid, p_ev.syscnt)
                graph.add_node(node, index=str(p_ev.index))
                graph.add_edge(ancestor, node)
                child = self.__make_node(newpid, 'exit')
                graph.add_edge(child, node)
                ancestor = node
            elif event.nr in unistd.Syscalls.SYS_exit:
                node = self.__make_node(pid, 'exit')
                graph.add_node(node, index=str(p_ev.index))
                graph.add_edge(ancestor, node)
                ancestor = node
            elif full:
                node = self.__make_node(pid, p_ev.syscnt)
                graph.add_node(node, index=str(p_ev.index))
                graph.add_edge(ancestor, node)
                ancestor = node

    def __refine_graph(self, graph):
        for resource in self.resource_list:
            prev = self.r_ev_to_proc(resource.events[0])
            pind = self.r_ev_to_pindex(resource.events[0])
            for r_ev in resource.events:
                next = self.r_ev_to_proc(r_ev)
                nind = self.r_ev_to_pindex(r_ev)
                if prev != next:
                    src = self.__make_node(prev.pid, prev.events[pind].syscnt)
                    dst = self.__make_node(next.pid, next.events[nind].syscnt)
                    graph.add_edge(src, dst)
                prev = next
                pind = nind

    def make_graph(self, full=False, refine=False):
        graph = networkx.DiGraph()
        graph.add_node('1')

        # build initial graph
        self.__build_graph(graph, self.process_list[0], full)

        if refine:
            # add dependencies of resources
            self.__refine_graph(graph)  # resources

        return graph

    def __init__(self):
        self.process_map = dict()
        self.process_list = list()
        self.resource_map = dict()
        self.resource_list = list()
        self.events_list = list()

##############################################################################
# main
#

if __name__ == "__main__":

    import sys
    from optparse import OptionParser

    usage = 'usage: %prog [options] graph|inject'
    desc = 'Process and modify scribe execution log'
    parser = OptionParser(usage=usage, description=desc)

    parser.add_option('-i', '--input', dest='logfile', metavar='FILE',
                      help='Read the recorded execution from FILE')
    parser.add_option('-o', '--output', dest='outfile', metavar='FILE',
                      help='Write the output graph or execution to FILE')

    parser.disable_interspersed_args()
    (options, cmd) = parser.parse_args()

    if len(cmd) > 1 or cmd[0] not in ['graph', 'inject']:
        parser.error('Unknown command')

    if not options.logfile:
        parser.error('Input logfile not specificed')
    if not options.outfile:
        parser.error('Output file not specified')

    try:
        f = open(options.logfile, 'r')
    except:
        print('Failed to open log file')
        exit(1)

    s = Session()
    s.load_events(f)

    if cmd[0] == 'graph':
        g = s.make_graph(False, False)
        print(networkx.convert.to_edgelist(g))
        networkx.write_dot(g, options.outfile + '-proc.dot')
        g = s.make_graph(True, True)
        print(networkx.convert.to_edgelist(g))
        networkx.write_dot(g, options.outfile + '-full.dot')
    elif cmd[0] == 'inject':
        a1 = Action(scribe.SCRIBE_INJECT_ACTION_SLEEP, 1000)
        a2 = Action(scribe.SCRIBE_INJECT_ACTION_SLEEP, 2000)
        actions = { 10:a1, 20:a2 }
        pid_inject = { 1:actions }
        pid_cutoff = { 2:25 }
        try:
            f = open(options.outfile, 'wb')
        except:
            print('Failed to open output file')
            exit(1)
        s.save_events(f, None, pid_cutoff, pid_inject)

    exit(0)

import sys
import mmap
import scribe
import unistd
import networkx
from itertools import combinations
from vectorclock import VectorClock

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

    def next_syscall(self, index):
        """Find the next syscall in a process events log"""
        event = self.events[index]
        if event.nr in unistd.Syscalls.SYS_exit:
            return -1
        while True:
            index += 1
            event = self.events[index]
            if isinstance(event, scribe.EventSyscallExtra):
                return index

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

    def r_ev_to_proc(self, r_ev, sysind=False):
        if sysind:
            s_ev = self.events_list[r_ev.sysind]
        else:
            s_ev = self.events_list[r_ev.index]
        return (s_ev.proc, s_ev.pindex)

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
                proc.sysind = ind
                if event.nr in unistd.Syscalls.SYS_exit:
                    proc.syscnt = 'exit'
                else:
                    proc.syscnt += 1
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
        ancestor = self.__make_node(pid, 0)
        for p_ev in proc.events:
            event = p_ev.event
            if not isinstance(event, scribe.EventSyscallExtra):
                continue
            if event.nr in unistd.Syscalls.SYS_fork and event.ret >= 0:
                newpid = event.ret
                parent = self.__make_node(pid, p_ev.syscnt)
                graph.add_node(parent, index=str(p_ev.index), type='fork')
                graph.add_edge(ancestor, parent)
                child = self.__make_node(newpid, 0)
                graph.add_node(child)
                graph.add_edge(parent, child, type='fork')
                self.__build_graph(graph, self.process_map[newpid], full)
                ancestor = parent
            elif event.nr in unistd.Syscalls.SYS_wait and event.ret >= 0:
                newpid = event.ret
                node = self.__make_node(pid, p_ev.syscnt)
                graph.add_node(node, index=str(p_ev.index))
                graph.add_edge(ancestor, node)
                child = self.__make_node(newpid, 'exit')
                graph.add_edge(child, node, type='exit')
                ancestor = node
            elif event.nr in unistd.Syscalls.SYS_exit:
                node = self.__make_node(pid, 'exit')
                graph.add_node(node, index=str(p_ev.index), type='exit')
                graph.add_edge(ancestor, node)
                ancestor = node
            elif full:
                node = self.__make_node(pid, p_ev.syscnt)
                graph.add_node(node, index=str(p_ev.index))
                graph.add_edge(ancestor, node)
                ancestor = node

    def __resources_graph(self, graph):
        """Add dependencies due to resources to an execution graph"""
        for resource in self.resource_list:
            prev, pind = self.r_ev_to_proc(resource.events[0])
            for r_ev in resource.events:
                next, nind = self.r_ev_to_proc(r_ev)
                if prev != next:
                    src = self.__make_node(prev.pid, prev.events[pind].syscnt)
                    dst = self.__make_node(next.pid, next.events[nind].syscnt)
                    if dst not in graph[src]:
                        graph.add_edge(src, dst, resource=str(r_ev.event.id))
                prev = next
                pind = nind

    def make_graph(self, full=False, resources=False):
        """Build the execution DAG from the execution log.
        @full: if True, include all syscalls, else only fork/wait/exit
        @resources: if True, add dependencies induced by resources
        Return a graph.
        """
        graph = networkx.DiGraph()
        graph.add_node('1:0')

        # build initial graph
        self.__build_graph(graph, self.process_list[0], full)

        if resources:
            # add dependencies of resources
            self.__resources_graph(graph)  # resources

        return graph

    def vclock_graph(self, graph, resources=False):
        """Compute the vector-clocks of nodes in the exceution graph.
        @resources: if True, consider dependencies induces by resources
        Return a dictionary of vector clocks (keys: graph nodes)
        """
        vclocks = dict()

        proc = self.process_list[0]
        vclocks[(proc, '1')] = VectorClock(proc.pid)

        nodes = set()
        nodes.add((proc, '1'))

        while nodes:
            (proc, index) = nodes.pop()
            n = self.__make_node(proc.pid, index)

            tick = False

            for nn in graph.neighbors(n):
                (p, nindex) = nn.split(':')
                next = self.process_map[int(p)]
                if (next, nindex) not in nodes:
                    vc = VectorClock(next.pid, vclocks[(proc, index)])
                    vclocks[(next, nindex)] = vc
                if next.pid != proc.pid:
                    if resources or 'type' in graph.edge[n][nn]:
                        tick = True

            for nn in graph.neighbors(n):
                (p, nindex) = nn.split(':')
                next = self.process_map[int(p)]
                vclocks[(next, nindex)].merge(vclocks[(proc, index)])
                if resources or 'resource' not in graph.edge[n][nn]:
                    nodes.add((next, nindex))
                if tick:
                    vclocks[(next, nindex)].tick(next.pid)

        return vclocks

    def crosscut_graph(self, graph, vclocks, node1, node2):
        """Given two nodes in the graph, find a consistent crosscut
        that includes these nodes, and return a bookmark dictionary
        that describes it.
        """
        (p, i) = node1.split(':')
        proc1 = self.process_map[int(p)]
        index1 = int(i)
        vc1 = vclocks[(proc1, i)]

        (p, i) = node2.split(':')
        proc2 = self.process_map[int(p)]
        index2 = int(i)
        vc2 = vclocks[(proc2, i)]

        nodes = dict()
        nodes[proc1.pid] = index1
        nodes[proc2.pid] = index2

        for proc in self.process_list:
            if proc == proc1 or proc == proc2:
                continue

            pindex = proc.next_syscall(0)

            tproc = None
            while True:
                nindex = proc.next_syscall(pindex)
                if nindex < 0:
                    break;

                vc = vclocks[(proc, proc.events[nindex].syscnt)]
                if vc.race(vc1) and vc.race(vc2):
                    tproc = proc
                    tindex = index
                    break;

            if tproc:
                nodes[tproc.pid] = tindex

        bookmarks = dict()

        for pid in nodes.keys():
            n = self.__make_node(pid, nodes[pid])
            att = graph.node[n]
            bookmarks[pid] = int(att['index'])

        return bookmarks

    def __races_accesses(self, access):
        """Given vclocks of a resource per process (increasing order),
        find resources races:

        For each two processes, iterate in parallel over accesses and
        find those that are neither before nor after each other. Each
        such race is reported as (vclock1, index1, vclock2, index2).

        This works because, given two process A[1..n] and B[1..m]:
        - for i < j:  Ai < Aj,  Bi < Bj
        - for i, j:   Ai < Bj  or  Ai > Bj  or  Ai || Bj
        - the relations '<' and '||' are transitive
        """
        races = list()

        for k1, k2 in combinations(access, 2):
            q1, q2 = access[k1], access[k2]

            n, m = 0, 0
            while n < len(q1) and m < len(q2):
                vc1, i1 = q1[n]
                vc2, i2 = q2[m]
                if vc1.before(vc2):
                    n += 1
                elif vc2.before(vc1):
                    m += 1
                else:
                    for vc3, i3 in q2[m:]:
                        if vc1.before(vc3):
                            break
                        races.append((vc1, i1, vc3, i3))
                    n += 1

        return races

    def races_resources(self, vclocks):
        """Given vclocks of all syscalls, find resources races:
        For each resource, iterate through its events and accumuldate
        them in a per-process list - stored in @access dictionary,
        such theat access[pid] is a list of (vclock, index) tuples of
        the events and their vector-clocks belonging to that process.
        This is passsed to __races_accesses() which returns a list of
        actual races: (vclock1, index1, vclock2, index2)
        """
        races = list()

        for resource in self.resource_list:
            access = dict(map(lambda k: (k, list()), self.process_map.keys()))

            # track accesses per process
            for r_ev in resource.events:
                proc, index = self.r_ev_to_proc(r_ev, sysind=True)
                p_ev = proc.events[index]
                node = self.__make_node(proc.pid, p_ev.syscnt)
                vc = vclocks[(proc, str(p_ev.syscnt))]
                access[proc.pid].append((vc, r_ev.index))

            races.extend(self.__races_accesses(access))

        return races

    def __init__(self):
        self.process_map = dict()
        self.process_list = list()
        self.resource_map = dict()
        self.resource_list = list()
        self.events_list = list()

##############################################################################
# main
#

def __test_graph(s):
    g = s.make_graph(False, False)
    print(networkx.convert.to_edgelist(g))
    networkx.write_dot(g, options.outfile + '-proc.dot')
    g = s.make_graph(True, True)
    print(networkx.convert.to_edgelist(g))
    networkx.write_dot(g, options.outfile + '-full.dot')
    vclocks = s.vclock_graph(g)
    for k in vclocks.keys():
        print('%s -> %s' % (k, vclocks[k].clocks))
    node1 = (s.process_map[1], 3)
    node2 = (s.process_map[2], 4)
    bookmarks = s.crosscut_graph(g, vc_dict, '1:3', '2:4')
    print(bookmarks)
    return(0)

def __test_inject(s):
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
    return(0)

def __test_races(s):
    g = s.make_graph(full=True, resources=True)
    print('graph: %s' % networkx.convert.to_edgelist(g))
    networkx.write_dot(g, options.outfile + '-full.dot')
    vclocks = s.vclock_graph(g)
    print('')
    sys.stdout.write('vclock: ')
    for k in vclocks.keys():
        print('%s, %s -> %s  ' % (k[0].pid, str(k[1]), vclocks[k].clocks))
    races = s.races_resources(vclocks)
    print('')
    print('races: %s' % races)
    for vc1, i1, vc2, i2 in races:
        p1 = s.events_list[i1].proc
        e1 = s.events_list[i1].event
        i1 = s.events_list[i1].pindex
        p2 = s.events_list[i2].proc
        e2 = s.events_list[i2].event
        i2 = s.events_list[i2].pindex
        print('proc %d syscall %s rid %d <->  proc %d syscall %s rid %d' \
                  % (p1.pid, str(p1.events[i1].syscnt), e1.id,
                     p2.pid, str(p2.events[i2].syscnt), e2.id))

if __name__ == "__main__":

    import sys
    from optparse import OptionParser

    usage = 'usage: %prog [options] graph|inject|races'
    desc = 'Process and modify scribe execution log'
    parser = OptionParser(usage=usage, description=desc)

    parser.add_option('-i', '--input', dest='logfile', metavar='FILE',
                      help='Read the recorded execution from FILE')
    parser.add_option('-o', '--output', dest='outfile', metavar='FILE',
                      help='Write the output graph or execution to FILE')

    parser.disable_interspersed_args()
    (options, cmd) = parser.parse_args()

    commands = {
        'test-graph':__test_graph,
        'test-races':__test_races,
        'test-inject':__test_inject,
        }

    if len(cmd) > 1 or cmd[0] not in commands:
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

    ret = commands[cmd[0]](s)
    exit(ret)

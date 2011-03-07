import sys
import pdb
import mmap
import logging
import networkx
from itertools import *

import scribe
import unistd
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
    __slots__ = ('pid', 'name', 'events', 'syscnt', 'sysind', 'regind')

    def next_syscall(self, index):
        """Find the next syscall in a process events log"""
        while True:
            index += 1
            event = self.events[index].event
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

    def __init__(self, action = None, arg1 = None, arg2 = None):
        self.action = action
        self.arg1 = arg1
        self.arg2 = arg2

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

    def i_to_event(self, i):
        return self.events_list[i].event

    ##########################################################################

    def parse_syscall(self, i):
        """Parse a syscall event"""

        s_ev = self.events_list[i]
        e_syscall = self.i_to_event(i)
        args = self.i_to_event(s_ev.regind).args
        ret = unistd.syscall_ret(e_syscall.ret)

        for j in xrange(s_ev.pindex + 1, len(s_ev.proc.events)):
            e_data = s_ev.proc.events[j].event
            if isinstance(e_data, scribe.EventDataExtra): break

        out = sys.stdout
        if e_syscall.nr == unistd.Syscalls.NR_open:
            out.write('open("%s", %#x, %#3o)' %
                      (e_data.data, args[1], args[2]))
        elif e_syscall.nr == unistd.Syscalls.NR_close:
            out.write('close(%d)' %
                      (args[0]))
        elif e_syscall.nr == unistd.Syscalls.NR_access:
            out.write('access("%s", %#3o)' %
                      (e_data.data, args[1]))
        elif e_syscall.nr == unistd.Syscalls.NR_execve:
            out.write('execve("%s", %#x, %#x)' %
                      (e_data.data, args[1], args[2]))
        elif e_syscall.nr == unistd.Syscalls.NR_stat:
            out.write('stat("%s", %#x)' %
                      (e_data.data, args[1]))
        elif e_syscall.nr == unistd.Syscalls.NR_stat64:
            out.write('stat64("%s", %#x, %#x)' %
                      (e_data.data, args[1], args[2]))
        else:
            out.write('%s(%#x, %#x, %#x)' %
                      (unistd.syscall_str(e_syscall.nr),
                       args[0], args[1], args[2]))
        out.write(' = %ld\n' % (ret))

    def syscalls_process(self, pid):
        """Print all the syscalls of a process"""
        try:
            proc = self.process_map[pid]
        except KeyError:
            logging.error('No such process with pid %d' % (pid))
            return

        for p_ev in proc.events:
            if isinstance(p_ev.event, scribe.EventSyscallExtra):
                sys.stdout.write('pid=%3d:cnt=%3d:' % (proc.pid, p_ev.syscnt))
                self.parse_syscall(p_ev.index)

    def profile_process(self, pid):
        """Print profile of all the events of a process"""
        proc = self.process_map[pid]
        for p_ev in proc.events:
            print("[%02d][%d] %s%s%s" %
                  (proc.pid, p_ev.syscnt,
                   ("", "    ")[p_ev.info.in_syscall],
                   "  " * p_ev.info.res_depth,
                   p_ev.event))

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
                continue

            if isinstance(event, scribe.EventRegs):
                proc.regind = ind
            elif isinstance(event, scribe.EventSyscallExtra):
                proc.sysind = ind
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

    def __check_bookmarks(self, pid, syscall, bookmarks, logfile):
        for n, bmark in enumerate(bookmarks):
            if syscall == bmark[pid]:
                e = scribe.EventBookmark()
                e.id = n
                e.npr = len([b for b in bmark.values() if b != 0])
                logfile.write(e.encode())
                logging.debug('[%d] bookmark at syscall %d' % (pid, syscall))

    def __check_inject(self, pid, syscall, injects, logfile):
        noregs = False
        if syscall in injects[pid]:
            for a in injects[pid].itervalues():
                e = scribe.EventInjectAction()
                e.action = a.action
                e.arg1 = a.arg1
                e.arg2 = a.arg2
                logfile.write(e.encode())
                logging.debug('[%d] inject at syscall %d' % (pid, syscall))
                if a.action == scribe.SCRIBE_INJECT_ACTION_PSFLAGS:
                    noregs = True
        return noregs

    def __check_cutoff(self, pid, syscall, cutoff):
        if syscall == cutoff[pid]:
            logging.debug('[%d] cutoff at syscall %d' % (pid, cutoff[pid]))
            return True
        else:
            return 

    def save_events(self, logfile,
                    bookmarks = None,
                    injects = None,
                    cutoff = None):
        """Write the (perhaps modified) scribe log to @logfile

        Write out the scribe log while potentially modifying it. Two
        types of modifications exist: "inject", to inject new events
        (per process) into the log , and "cutoff", which specifies
        locations (per process) to cut remaining log.

        @logfile: output file object (opened for binary write)
        @bookmarks: array of bookmarks [{ pid: sc1 }]
        @injects: actions to inject { pid : {sc1:act1},{sc2:act2}, ...] }
        @cutoff: where to cutoff queues { pid : sc }
        """

        active = dict()
        syscall = dict()
        noregs = dict()
        endofq = dict({0:False})

        # any(ifilter(lambda d: pid in d, a))
        include = reduce(lambda d1, d2: dict(d1, **d2), bookmarks)

        if bookmarks is None:
            bookmarks = dict()
        if injects is None:
            injects = dict()
        if cutoff is None:
            cutoff = dict()

        for s_ev in self.events_list:
            info = s_ev.info
            event = s_ev.event
            pid = info.pid

            if pid == 0:
                logfile.write(event.encode())
                continue

            if pid not in include:
                continue

            # pid first time ?
            if pid not in active:
                active[pid] = True
                syscall[pid] = 0
                endofq[pid] = False
                noregs[pid] = False
                if pid not in cutoff:
                    cutoff[pid] = 0
                if pid not in injects:
                    injects[pid] = dict()

            assert not endofq[pid] or pid == 0, \
                'Event for pid %d after eoq' % (pid)

            # pid inactive ?
            if not active[pid]:
                continue

            # ignore original bookmarks
            if isinstance(event, scribe.EventBookmark):
                continue

            #
            # I would expect to remove the EventRegs already, but nico said
            # it should stay, and remove from EventSyscallExtra nad on
            #    if isinstance(event, scribe.EventRegs):
            #
            if isinstance(event, scribe.EventSyscallExtra):
                syscall[pid] += 1

                # pid bookmark ?
                self.__check_bookmarks(pid, -syscall[pid], bookmarks, logfile)
                # pid inject ?
                if self.__check_inject(pid, -syscall[pid], injects, logfile):
                    noregs[pid] = True
                # pid cutoff ?
                if self.__check_cutoff(pid, -syscall[pid], cutoff):
                    active[pid] = False
                    continue

            if noregs[pid] and \
                    (isinstance(event, scribe.EventResourceLockExtra) or \
                    isinstance(event, scribe.EventResourceLockIntr) or \
                    isinstance(event, scribe.EventResourceUnlock)):
                continue

            if isinstance(event, scribe.EventQueueEof):
                endofq[pid] = True
                active[pid] = False

            logfile.write(event.encode())

            if isinstance(event, scribe.EventSyscallEnd):
                # pid bookmark ?
                self.__check_bookmarks(pid, syscall[pid], bookmarks, logfile)
                # pid inject ?
                if self.__check_inject(pid, syscall[pid], injects, logfile):
                    noregs[pid] = True
                # pid cutoff ?
                if self.__check_cutoff(pid, syscall[pid], cutoff):
                    active[pid] = False
                    continue

        # indicate go-live where needed
        for pid in active:
            if not endofq[pid]:
                e = scribe.EventPid()
                e.pid = pid
                logfile.write(e.encode())
                e = scribe.EventQueueEof()
                logfile.write(e.encode())

##############################################################################
#   generate thread calls graph (fork,exit,wait,syscalls)

    def make_node(self, pid, syscall):
        return str(pid) + ':' + str(syscall)

    def split_node(self, node):
        (pid, index) = node.split(':')
        proc = self.process_map[int(pid)]
        return (proc, int(index))

    def __build_graph(self, graph, proc, full=False):
        """Build the execution DAG from the execution log, as follows:
        - The first node is '0'
        - New processes begin with a node 'pid'
        - Syscalls add a node 'pid:syscall' (and edge from previous)
        - Syscall fork() creates a new process and an edge to it 
        - Syscall exit() adds a node 'pid:exit' (and edge from previous)
        - Syscall wait() adds an edge from the child's exit() syscall
        - Node attribute 'index=str(I)' for event index in global list
        - Resource access add edge from the previous user to current
        (note: attributes must be strings)
        """
        pid = proc.pid
        ancestor = self.make_node(pid, 0)
        for p_ev in proc.events:
            event = p_ev.event
            if not isinstance(event, scribe.EventSyscallExtra):
                pass
            elif event.nr in unistd.Syscalls.SYS_fork and event.ret > 0:
                newpid = event.ret
                parent = self.make_node(pid, p_ev.syscnt)
                graph.add_node(parent, index=str(p_ev.index), fork='1')
                graph.add_edge(ancestor, parent)
                child = self.make_node(newpid, 0)
                graph.add_node(child)
                graph.add_edge(parent, child, fork='1', label='fork')
                self.__build_graph(graph, self.process_map[newpid], full)
                ancestor = parent
            elif event.nr in unistd.Syscalls.SYS_wait and event.ret > 0:
                newpid = event.ret
                node = self.make_node(pid, p_ev.syscnt)
                graph.add_node(node, index=str(p_ev.index))
                graph.add_edge(ancestor, node)
                child = self.make_node(newpid, self.process_map[newpid].syscnt)
                graph.add_edge(child, node, label='exit')
                ancestor = node
            elif event.nr in unistd.Syscalls.SYS_exit:
                node = self.make_node(pid, p_ev.syscnt)
                graph.add_node(node, index=str(p_ev.index), exit='1')
                graph.add_edge(ancestor, node)
                ancestor = node
            elif full:
                node = self.make_node(pid, p_ev.syscnt)
                graph.add_node(node, index=str(p_ev.index))
                graph.add_edge(ancestor, node)
                ancestor = node

    def __resources_graph(self, graph):
        """Add dependencies due to resources to an execution graph"""

        for r in self.resource_list:
            prev, pind = self.r_ev_to_proc(r.events[0])
            pr_ev = list()
            nr_ev = list()
            serial = 0

            def add_resource_edges():
                tr_ev = product(pr_ev, nr_ev)

                for (prev, pind), (next, nind) in tr_ev:
                    if prev == next:
                        continue
                    logging.info('%d:%d -> %d:%d' % (prev.pid,pind,next.pid,nind))
                    src = self.make_node(prev.pid, prev.events[pind].syscnt)
                    dst = self.make_node(next.pid, next.events[nind].syscnt)
                    if 'resource' not in graph.node[src]:
                        graph.node[src]['resource'] = ''
                    graph.node[src]['resource'] += str(r.id)
                    if dst not in graph[src]:
                        graph.add_edge(src, dst,
                                       resource=str(r.id),
                                       label='r%d(%d)' % (r.id, serial))

            for r_ev in r.events:
                next, nind = self.r_ev_to_proc(r_ev)
                if r_ev.event.serial == serial:
                    nr_ev.append((next, nind))
                    # if next not in nr_ev.keys():
                    #    nr_ev[next] = (next, nind)
                else:
                    add_resource_edges()
                    pr_ev = nr_ev
                    nr_ev = list([(next, nind)])
                    serial = r_ev.event.serial
            else:
                add_resource_edges()

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
            self.__resources_graph(graph)

        return graph

    def vclock_graph(self, graph, resources=False):
        """Compute the vector-clocks of nodes in the exceution graph.
        @resources: if True, consider dependencies induces by resources
        Return a dictionary of vector clocks (keys: graph nodes)
        """
        vclocks = dict()
        vclocks[self.process_map[1], 0] = VectorClock(1)

        for node in networkx.algorithms.dag.topological_sort(graph):
            proc, index = self.split_node(node)
            vc = vclocks[(proc, index)]
            tick = False

            for nn in graph.neighbors(node):
                next, nindex = self.split_node(nn)

                # disregard resource dependencies if not @resource ?
                if not resources and 'resource' in graph.edge[node][nn]:
                    continue

                # need to creat vclock for this node ?
                if (next, nindex) not in vclocks:
                    vclocks[(next, nindex)] = VectorClock(next.pid, vc)
                else:
                    vclocks[(next, nindex)].merge(vc)

                # is this an edge that should cause a tick ?
                if next.pid != proc.pid:
                    if 'fork' in graph.edge[node][nn]:
                        tick = True
                    elif resources and 'resource' in graph.edge[node][nn]:
                        tick = True
                else:
                    # remember for below
                    tproc = next
                    tindex = nindex

            if tick:
                # tick before the merge, but w/o effect on @vc
                vctmp = VectorClock(proc.pid, vc)
                vctmp.tick(proc.pid)
                vclocks[(tproc, tindex)].merge(vctmp)

        return vclocks


    # YJF: improved version
    def crosscut_graph(self, graph, vclocks, node1, node2):
        """Given two nodes in the graph, find a consistent crosscut,
        such that both nodes are just about to be executed.
        Returns bookmarks dict of the cut, or None if none found
        """
        proc1, index1 = self.split_node(node1)
        proc2, index2 = self.split_node(node2)

        pid1 = proc1.pid
        pid2 = proc2.pid

        assert index1 > 0 and index2 > 0, \
            'Potential race before process creation (%d:%d, %d:%d)' % \
            (pid1, index1, pid2, index2)

        nodes = dict()
        nodes[pid1] = -index1
        nodes[pid2] = -index2

        vc1 = vclocks[(proc1, index1)]
        vc2 = vclocks[(proc2, index2)]

        logging.debug('find cut for clocks %s and %s' %
                      (vc1.clocks, vc2.clocks))

        # proc, local clock -> syscnt that first has this clock
        ticks = dict()
        for (proc, syscnt), vc in vclocks.iteritems():
            ticks[(proc, vc.get(proc.pid))] = syscnt

        for proc in self.process_list:
            if proc == proc1 or proc == proc2:
                continue

            pid = proc.pid
            # last time we heard from pid, its local clock is at c
            c = max([vc1.get(pid), vc2.get(pid)])
            
            # TODO: build clock -> event index map to speed up this lookup
            pindex = -1
            syscnt = 0
            while True:
                pindex = proc.next_syscall(pindex)
                p_ev = proc.events[pindex]
                vc = vclocks[(proc, p_ev.syscnt)]
                logging.debug('[pid %d] pindex %d vclock %s' %
                              (pid, pindex, vc.clocks))
                # first node with local clock > c, include it in cut
                if vc.get(pid) > c:
                    syscnt = p_ev.syscnt
                    break

                if p_ev.event.nr in unistd.Syscalls.SYS_exit:
                    logging.debug('exit ?')
                    pindex = -1 # no bookmark for exited process
                    break
            nodes[pid] = -syscnt;

        return nodes


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

                if self.i_to_event(i1).serial == self.i_to_event(i2).serial:
                    n += 1
                elif vc1.before(vc2):
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
        For each resource, iterate through its events and accumulate
        them in a per-process list - stored in @access dictionary,
        such that access[pid] is a list of (vclock, index) tuples of
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
                node = self.make_node(proc.pid, p_ev.syscnt)
                vc = vclocks[(proc, p_ev.syscnt)]
                access[proc.pid].append((vc, r_ev.index))

            races.extend(self.__races_accesses(access))

        return races

    def __init__(self):
        self.process_map = dict()
        self.process_list = list()
        self.resource_map = dict()
        self.resource_list = list()
        self.events_list = list()


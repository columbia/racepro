import sys
import mmap
import scribe
import unistd
import networkx

class Process:
    """Describe execution log of a single process.

    @pid: pid of the process
    @name: name of the program
    @events: (ordered) list of events performed by this process

    @sys, @reg: track current syscall/regs events (temporary)

    Events are: (info, event, i), where @info and @events are scribe's
    event description, and @i is the index of the event in the global
    events list.
    """

    def __init__(self, pid):
        self.pid = pid
        self.name = '-'
        self.events = list()
        self.sys = -1
        self.reg = -1
        
class Resource:
    """Describe execution log related to a resource isntance.

    @type: type of resource
    @id: unique identifier of the resource
    @events: (ordered) list of events affecting this resource

    Events are: (info, event, i, sys), where @info and @events are
    scribe's event description, @i is the index of the event in the
    global events list, and @sys is the index of the system call
    containing this event.
    """

    def __init__(self, event):
        self.type = event.type
        self.id = event.id
        self.events = list()

class Action:
    """Describe an action to be injected into a log"""

    def __init__(self, action = None, arg1 = None):
        self.action = action
        self.arg1 = arg1

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

    Event are: (info, event, proc, plen, resource, rlen, sys, reg),
    where: @info and @event are scribe's event description, @proc is
    the Process instance and @plen the index in its events list, and
    @resource is the resource index and @rlen the index in its events
    list.
    """

    # order of arguments: ebx, ecx, edx, esi ...

    def parse_syscall(self, i, j):
        """Parse a syscall event"""

        syscall = self.events_list[i][1]
        args = self.events_list[j][1].args
        data = self.events_list[i+1][1]
        ret = unistd.syscall_ret(syscall.ret)

        if syscall.nr == unistd.Syscalls.NR_open:
            print('[%d] open("%s", %#x, %#3o) = %ld' %
                  (i, data.data, args[1], args[2], ret))
        if syscall.nr == unistd.Syscalls.NR_close:
            print('[%d] close(%d) = %ld' %
                  (i, args[0], ret))
        if syscall.nr == unistd.Syscalls.NR_access:
            print('[%d] access("%s", %#3o) = %ld' %
                  (i, data.data, args[0], ret))
        if syscall.nr == unistd.Syscalls.NR_execve:
            print('[%d] execve("%s", %#x, %#x) = %ld' %
                  (i, data.data, args[0], args[1], ret))
        if syscall.nr == unistd.Syscalls.NR_stat:
            print('[%d] stat("%s", %#x) = %ld' %
                  (i, data.data, args[0], ret))
        if syscall.nr == unistd.Syscalls.NR_stat64:
            print('[%d] stat64("%s", %#x, %#x) = %ld' %
                  (i, data.data, args[0], args[1], ret))

    def print_process(self, pid):
        """Print all the events of a process"""
        try:
            proc = self.process_map[pid]
        except KeyError:
            print('No such process with pid %d' % (pid))
            return

        for (info, event, i) in proc.events:
            if isinstance(event, scribe.EventSyscallExtra):
                ev = self.events_list[i]
                self.parse_syscall(ev[6], ev[7])

    def load_events(self, logfile):
        """Parse the scribe log from @logfile"""

        m = mmap.mmap(logfile.fileno(), 0, prot=mmap.PROT_READ)
        e = list(scribe.EventsFromBuffer(m, remove_annotations=False))
        m.close()

        # @pid and @proc track current process
        # @i tracks current index in self.events
        proc = None
        pid = 0
        i = -1

        # parse events
        for (info, event) in e:
            i += 1

            if isinstance(event, scribe.EventPid):
                self.events_list.append((info, event, None, 0, None, 0, 0, 0))
                pid = info.pid
                try:
                    proc = self.process_map[pid]
                except:
                    proc = Process(pid)
                    self.process_map[pid] = proc
                    self.process_list.append(proc)
                continue

            if pid == 0:
                self.events_list.append((info, event, None, 0, None, 0, 0, 0))
                continue;

            if isinstance(event, scribe.EventRegs):
                proc.reg = i
            elif isinstance(event, scribe.EventSyscallExtra):
                proc.sys = i
            elif isinstance(event, scribe.EventSyscallEnd):
                proc.reg = -1
                proc.sys = -1

            if isinstance(event, scribe.EventResourceLockExtra):
                if event.id not in self.resource_map:
                    resource = Resource(event)
                    self.resource_map[event.id] = resource
                    self.resource_list.append(resource)
                resource = self.resource_map[event.id]
                resource.events.append((info, event, i, sys))

            plen = len(proc.events)
            proc.events.append((info, event, i))

            self.events_list.append((info, event,
                                     proc, plen,
                                     None, 0,
                                     proc.sys, proc.reg))

            if isinstance(event, scribe.EventQueueEof):
                proc = None

        # sort events per resource
        for resource in self.resource_list:
            i = 0
            resource.events.sort(key=lambda ev: ev[1].serial)
            for r in resource.events:
                i += 1
                ev = self.events_list[r[2]]
                # adjust pointers to event in Resource
                self.events_list[r[2]] = ev[0:4] + (resource, i) + ev[6:8]

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

        for (info, event) in (e[0:2] for e in self.events_list):
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

    def __make_node(self, pid, syscall):
        return str(pid) + ':' + str(syscall)

    def __build_graph(self, graph, proc):
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
        syscall = 0
        pid = proc.pid
        ancestor = str(pid)
        for info, event, i in proc.events:
            if not isinstance(event, scribe.EventSyscallExtra):
                continue
            syscall += 1
            if event.nr in unistd.Syscalls.SYS_fork and event.ret >= 0:
                newpid = event.ret
                parent = self.__make_node(pid, syscall)
                graph.add_node(parent, index=str(i))
                graph.add_edge(ancestor, parent)
                child = str(newpid)
                graph.add_node(child)
                graph.add_edge(parent, child)
                graph = self.__build_graph(graph, self.process_map[newpid])
                ancestor = parent
            elif event.nr in unistd.Syscalls.SYS_wait and event.ret >= 0:
                newpid = event.ret
                node = self.__make_node(pid, syscall)
                graph.add_node(node, index=str(i))
                graph.add_edge(ancestor, node)
                child = self.__make_node(newpid, 'exit')
                graph.add_edge(child, node)
                ancestor = node
            elif event.nr in unistd.Syscalls.SYS_exit:
                node = self.__make_node(pid, 'exit')
                graph.add_node(node, index=str(i))
                graph.add_edge(ancestor, node)
        return graph

    def make_graph(self):
        graph = networkx.DiGraph()
        graph.add_node('1')
        self.__build_graph(graph, self.process_list[0])  # processes
        return graph

    def __init__(self):
        self.process_map = dict()
        self.process_list = list()
        self.resource_map = dict()
        self.resource_list = list()
        self.events_list = list()


##############################################################################
# generate thread calls graph (fork,exit,wait)
#

import pygraphviz as pgv

def node_name(pid, syscall, arg):
    return str(pid) + ': ' + syscall + '(' + str(arg) + ')'

def _process_graph(session, graph, proc):
    pid = proc.pid
    ancestor = str(pid)
    for info, event, i in proc.events:
        if not isinstance(event, scribe.EventSyscallExtra):
            continue
        ret = unistd.syscall_ret(event.ret)
        if event.nr in unistd.Syscalls.SYS_fork and ret >= 0:
            newpid = event.ret
            parent = node_name(pid, 'fork', newpid)
            child = str(newpid)
            graph.add_node(parent, fontsize='8', width='0.2', height='0.2')
            graph.add_edge((ancestor, parent))
            graph.add_node(child, color='blue', style='filled')
            graph.add_edge((parent, child), label='fork')
            graph = _process_graph(session, graph, session.process_map[newpid])
            ancestor = parent
        elif event.nr in unistd.Syscalls.SYS_wait and ret >= 0:
            newpid = event.ret
            node = node_name(pid, 'wait', newpid)
            child = node_name(newpid, 'exit', '')
            graph.add_node(node, fontsize='8', width='0.2', height='0.2')
            graph.add_edge((ancestor, node))
            graph.add_edge((child, node), label='wait')
            ancestor = node
        elif event.nr in unistd.Syscalls.SYS_exit:
            node = node_name(pid, 'exit', '')
            graph.add_node(node, fontsize='8', width='0.2', height='0.2')
            graph.add_edge((ancestor, node))
    return graph

def process_graph(session):
    graph = pgv.AGraph(directed=True)
    graph.add_node('1', fillcolor='blue', style='filled')
    graph = _process_graph(session, graph, session.process_list[0])
    return graph


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
        g = process_graph(s)
        g.layout(prog='dot')
        g.draw(options.outfile)
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

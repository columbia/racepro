import sys
import mmap
import scribe
import unistd

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
            print('[%d] open("%s", %#x, 0%03u) = %ld' %
                  (i, data.data, args[1], args[2], ret))
        if syscall.nr == unistd.Syscalls.NR_close:
            print('[%d] close(%d) = %ld' %
                  (i, args[0], ret))
        if syscall.nr == unistd.Syscalls.NR_access:
            print('[%d] access("%s", 0%03u) = %ld' %
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
                self.events_list[r[2]] = (ev[0:3], resource, i)

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

        if event.nr in unistd.Syscalls.SYS_fork and ret < 0:
            newpid = event.ret
            parent = node_name(pid, 'fork', newpid)
            child = str(newpid)
            graph.add_node(parent, fontsize='8', width='0.2', height='0.2')
            graph.add_edge((ancestor, parent))
            graph.add_node(child, color='blue', style='filled')
            graph.add_edge((parent, child), label='fork')
            graph = _process_graph(session, graph, session.process_map[newpid])
            ancestor = parent
        elif event.nr in unistd.Syscalls.SYS_wait and ret < 0:
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

    if len(sys.argv) != 3:
        print('Usage: racepro.py logfile image')
        print('  @logfile: input log file')
        print('  @image: output process call graph')
        exit(1)

    try:
        f = open(sys.argv[1], 'r')
    except:
        print('Failed to open log file')
        exit(1)

    s = Session()
    s.load_events(f)
    g = process_graph(s)
    g.layout(prog='dot')
    g.draw(sys.argv[2])

    exit(0)

import sys
import pygraphviz as pgv
import mmap
import scribe

class Process:
    def __init__(self, pid):
        self.pid = pid
        self.name = '-'
        self.events = list()
        self.syscall = None
        
class Resource:
    def __init__(self, event):
        self.type = event.type
        self.id = event.id
        self.events = list()

class Session:

    NR_fork = 2
    NR_clone = 120
    NR_vfork = 190
    NR_exit = 1
    NR_exit_group = 252
    NR_waitpid = 7
    NR_wait4 = 114
    NR_waitid = 284

    __sys_fork = set([NR_fork, NR_clone, NR_vfork])
    __sys_exit = set([NR_exit, NR_exit_group])
    __sys_wait = set([NR_waitpid, NR_wait4, NR_waitid])

    def __init__(self, logfile):
        self.process_map = dict()
        self.process_list = list()
        self.resource_map = dict()
        self.resource_list = list()
        self.event_list = list()

        m = mmap.mmap(logfile.fileno(), 0, prot=mmap.PROT_READ)
        e = list(scribe.EventsFromBuffer(m, remove_annotations=False))
        m.close()

        # @pid and @proc track current process
        # @i tracks current index in self.events

        proc = None
        pid = 0
        i = -1

        for (info, event) in e:

            i += 1

            if isinstance(event, scribe.EventPid):
                self.event_list.append((info, event, None, 0, None, 0))
                pid = info.pid
                try:
                    proc = self.process_map[pid]
                except:
                    proc = Process(pid)
                    self.process_map[pid] = proc
                    self.process_list.append(proc)
                continue

            if pid == 0:
                self.event_list.append((info, event, None, 0, None, 0))
                continue;

            if isinstance(event, scribe.EventSyscallExtra):
                proc.syscall = i
            elif isinstance(event, scribe.EventSyscallEnd):
                proc.syscall = -1

            if isinstance(event, scribe.EventResourceLockExtra):
                if event.id not in self.resource_map:
                    resource = Resource(event)
                    self.resource_map[event.id] = resource
                    self.resource_list.append(resource)
                resource = self.resource_map[event.id]
                resource.events.append((info, event, i, proc.syscall))

            plen = len(proc.events)
            proc.events.append((info, event, i))

            self.event_list.append((info, event, proc, plen, None, 0))

            if isinstance(event, scribe.EventQueueEof):
                proc = None

        for resource in self.resource_list:
            i = 0
            resource.events.sort(key=lambda ev: ev[1].serial)
            for r in resource.events:
                i += 1
                ev = self.event_list[r[2]]
                self.event_list[r[2]] = (ev[0:3], resource, i)

    def node_name(self, pid, syscall, arg):
        return str(pid) + ': ' + syscall + '(' + str(arg) + ')'

    def _process_graph(self, graph, proc):
        pid = proc.pid
        ancestor = str(pid)
        for info, event, i in proc.events:
            if not isinstance(event, scribe.EventSyscallExtra):
                continue
            if event.nr in Session.__sys_fork and event.ret > 0:
                newpid = event.ret
                parent = self.node_name(pid, 'fork', newpid)
                child = str(newpid)
                graph.add_node(parent, fontsize='8', width='0.2', height='0.2')
                graph.add_edge((ancestor, parent))
                graph.add_node(child, color='blue', style='filled')
                graph.add_edge((parent, child), label='fork')
                graph = self._process_graph(graph, self.process_map[newpid])
                ancestor = parent
            elif event.nr in Session.__sys_wait and event.ret < sys.maxint:
                newpid = event.ret
                node = self.node_name(pid, 'wait', newpid)
                child = self.node_name(newpid, 'exit', '')
                graph.add_node(node, fontsize='8', width='0.2', height='0.2')
                graph.add_edge((ancestor, node))
                graph.add_edge((child, node), label='wait')
                ancestor = node
            elif event.nr in Session.__sys_exit:
                node = self.node_name(pid, 'exit', '')
                graph.add_node(node, fontsize='8', width='0.2', height='0.2')
                graph.add_edge((ancestor, node))
        return graph

    def process_graph(self):
        graph = pgv.AGraph(directed=True)
        graph.add_node('1', fillcolor='blue', style='filled')
        graph = self._process_graph(graph, self.process_list[0])
        return graph

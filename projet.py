from dataclasses import dataclass
import io
from collections import namedtuple
from os import name
import struct
import re

# word = HEXDIGIT HEXDIGIT
# space = " "
# backline = "\n"
# BOF = ?
# frame = (BOF / backline) "0" "0" space *[(*[word space] [word] / word) backline]

# eth_src = 48
# eth_dst = 48
# eth_type = 16
# eth_data = 368, 120000

ETH_HEADER = (
    ('DST', '6s'),
    ('SRC', '6s'),
    ('PTO', 'H')
)

ETH_PTO = (
    ('IPV4', 0x8000)
)

class EthReader:
    pass


@dataclass
class EthFrame:
    src: bytes
    dst: bytes
    ethtype: bytes
    data: bytes

    @classmethod
    def fromhex(cls, s): # on multiplie le nombre d'octets par 3 car <atom> ::= <hex>,<hex>," "
        src = bytes.fromhex(s[0:18])
        dst = bytes.fromhex(s[18:36])
        ethtype = bytes.fromhex(s[36:42])
        data = bytes.fromhex(s[42:])
        return cls(src, dst, ethtype, data)

@dataclass
class IPV4Packet:
    ver: bytes
    hl: bytes
    tos: bytes
    tl: bytes
    id: bytes
    frag: bytes # includes flags
    ttl: bytes
    proto: bytes
    chksum: bytes
    src: bytes
    dst: bytes
    opt: bytes
    data: bytes
    
    def frombytes(cls, b):
        pass

    @classmethod
    def fromhex(cls, s):
        ver = bytes.fromhex(s[0:1])

        hl = bytes.fromhex(s[12:24])
        tos = bytes.fromhex(s[24:48])
        tl = bytes.fromhex(s[48:96])
        id = bytes.fromhex(s[96:144])
        df = bytes.fromhex(s[147:150])
        mf = bytes.fromhex(s[151:153])
        frag = bytes.fromhex(s[153:192])
        ttl = bytes.fromhex(s[192:216])
        proto = bytes.fromhex(s[216:240])
        chksum = bytes.fromhex(s[240:288])
        src = bytes.fromhex(s[288:384])
        dst = bytes.fromhex(s[384:480])
        opt = bytes.fromhex(s[480:576])
        data = bytes.fromhex(s[576:])
        return cls(ver, hl, tos, tl, id, df, mf, frag, ttl, proto, chksum, src, dst, opt, data)

    # ex de méthodes utiles :

    def nb_opt(self):
        raise NotImplementedError

    def get_nth_opt(self):
        raise NotImplementedError

# XXX: defining these as constants would probably make debugging easier
terminals = (
    'frame_fragment_offset',
    'frame_fragment_data',
    'garbage',
    'end_of_frame_fragment',
    'end_of_frame'
)

# frames really are "partial frames"
non_terminals = (
    'frame',
    'trace',
    'frame_fragment'
)

# Grammar
# S -> T
# T -> F end_of_frame T | empty
# F -> G F | empty
# G -> frame_fragment_offset frame_fragment_data garbage end_of_fragment
# $ -> EOF

axiom = 'trace' # S -> T

end_of_input = '$'

# production rules are of the form ('element on the stack', 'element on the input'):['leftmost element', ..., 'rightmost element']
productions = { ('trace', 'frame_fragment_offset'):['frame', 'end_of_frame', 'trace']
        , ('trace', '$'):[]
        , ('trace', 'end_of_frame'):['frame', 'end_of_frame', 'trace']
        , ('frame', 'frame_fragment_offset'):['frame_fragment', 'end_of_frame_fragment', 'frame']
        , ('frame', 'end_of_frame'):[]
        , ('frame_fragment', 'frame_fragment_offset'):['frame_fragment_offset', 'frame_fragment_data', 'garbage']
        }

# XXX: children as dict makes it so useless children nodes are appended such as delimiters
class TraceAST:
    def __init__(self, trace=None):
        self.children = {'trace':trace}

class TraceNode:
    def __init__(self, frame=None, trace=None): # a trace can be empty
        self.children = {'frame':frame, 'trace':trace}
        self.parent = None

class FrameNode:
    def __init__(self, frame_fragment=None, frame=None): # so can a frame
        self.children = {'frame_fragment':frame_fragment, 'frame':frame}
        self.parent = None

class FragmentNode:
    def __init__(self, frame_fragment_offset=None, frame_fragment_data=None, garbage=None): # but a fragment need at least an offset, owtherwise it doesn't exists
        self.children = {'frame_fragment_offset':frame_fragment_offset , 'frame_fragment_data':frame_fragment_data, 'garbage':garbage}
        self.parent = None

# classes associated to each nt
# XXX: worth exploring classes as key of the dict?
# TODO: nt->ast/ast_node
nt_classes = {'frame':FrameNode, 'trace':TraceNode, 'frame_fragment':FragmentNode, 'ast':TraceAST}

#tokens that indicate the limit of associated nt
nt_delimiters = {'end_of_frame_fragment':'frame', 'end_of_frame':'trace', '$':'ast'}

# regex string to tokenize lines of the file
e = r"^(?P<frame_fragment_offset>[0-9A-Fa-f]*)\s(?P<frame_fragment_data>([0-9A-Fa-f]{2}\s)*[0-9A-Fa-f]{2}|[0-9A-Fa-f]{2})?(?P<garbage>.*)(?P<end_of_frame_fragment>\n?|$)"

class TraceParser033:
    def lex(self, tracefile):
        '''Tokenize the tracefile and handles incorrect values
        '''
        tokens = []
        while(l := tracefile.readline()):
            m = re.match(e, l)
            if m:
                for g in m.groupdict().items():
                    tokens.append(g)
            p = tracefile.tell() # save current cursor pos
            c = tracefile.read(1)
            if c == '': # test for eof by reading 1 charcter
                    tokens.append(('end_of_frame', None))
                    break
            while(True): # lookahead of 1 "word" after new line if it is offset 0 then insert end_of_fragment token                
                if(c != '0' and c != ' '): break
                if(c == ' '): tokens.append(('end_of_frame', None))
                c = tracefile.read(1)
            tracefile.seek(p) # rewind to saved pos
        tokens.append(('$', None))

        return tokens

    def parse(self, tokens):
        '''Validates the input and builds the Abstract Syntax Tree of the file
        '''
        stack = ['$', 'trace']
        i = 0

        nodestack = []
        root = TraceAST()
        nodestack.append(root)

        while len(stack)>0:
            s = stack.pop()
            if s in terminals or s == '$':
                if tokens[i][0] == s: # if token identifier matches element on top of the stack
                    i += 1
                else:
                    raise ValueError("Bad input")

                # AST logic
                if s in nt_delimiters:
                    while not isinstance(nodestack[-1], nt_classes[nt_delimiters[s]]): # pop stack while class of node is not class of nt associated delimiter
                        nodestack.pop() # pop node children
                else:
                    nodestack[-1].children[s] = tokens[i-1][1] # update value of key = elemnt of stack

            elif s in non_terminals:
                rule = (s, tokens[i][0])
                # print("rule:",rule)
                if rule in productions:
                    for r in reversed(productions[rule]): # reversed because leff hand elements must be evaluated first
                        stack.append(r)
                else:
                    raise ValueError("Bad rule")

                # AST logic 
                node = nt_classes[s]()
                node.parent = nodestack[-1] # parent is node on top of the stack
                nodestack.append(node)
                nodestack[-1].parent.children[s] = nodestack[-1] # update parents ref to child node

        print("Succesfully parsed input")
        return nodestack[0]

def extend_pack_into(format, buffer, offset, *v):
    if len(buffer) < offset + struct.calcsize(format):
        buffer = buffer.ljust(offset + struct.calcsize(format), b'\xff')
    struct.pack_into(format, buffer, offset, *v)
    return buffer


class TraceAnalyser033:
    def extract_trace_data(self, tracenode):
        '''Extracts captured traffic data TraceNode object
        '''
        trace_data = []
        while tracenode != None:
            if tracenode.children['trace'] == None:
                break
            else:
                frame_data = self.extract_framenode_data(tracenode.children['frame'])
                trace_data.append(frame_data)
                tracenode = tracenode.children['trace']

        return trace_data

    def extract_framenode_data(self, framenode):
        '''Extracts data of a FrameNode object
        '''
        frame_data = ""
        frame_data2 = bytearray()
        while framenode != None:
            if framenode.children['frame'] == None:
                break
            else:
                frame_data += framenode.children['frame_fragment'].children['frame_fragment_data'] + " "
                raw_data = framenode.children['frame_fragment'].children['frame_fragment_data']
                partial_data = bytes.fromhex(raw_data)
                frame_data2 = extend_pack_into("{}s".format(len(partial_data)), frame_data2, int(bytes.fromhex(framenode.children['frame_fragment'].children['frame_fragment_offset']).hex(),16), partial_data)
                framenode = framenode.children['frame']

        #return bytes.fromhex(frame_data)
        return frame_data2
            
        

def main():
    with io.open('extr.txt') as f:
        tp = TraceParser033()
        t = tp.lex(f)
        tree = tp.parse(t)
        an = TraceAnalyser033()
        d = an.extract_trace_data(tree.children['trace'])
        print("")


if __name__ == "__main__":
    main()
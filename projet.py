from dataclasses import dataclass, InitVar, field
import io
from collections import namedtuple
import struct
import re
from typing import List

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

# AST structures definitions
class TraceAST033:
    '''Represents the root of the AST'''
    def __init__(self, trace=None):
        self.children = {'trace':trace}

class TraceNode033:
    '''Represents a trace node in the AST'''
    def __init__(self, frame=None, trace=None): # a trace can be empty
        self.children = {'frame':frame, 'trace':trace}
        self.parent = None

class FrameNode033:
    '''Represents a frame node in the AST'''
    def __init__(self, frame_fragment=None, frame=None): # so can a frame
        self.children = {'frame_fragment':frame_fragment, 'frame':frame}
        self.parent = None

class FragmentNode033:
    '''Represents a fragment node in the AST'''
    def __init__(self, frame_fragment_offset=None, frame_fragment_data=None, garbage=None): # but a fragment need at least an offset, owtherwise it doesn't exists
        self.children = {'frame_fragment_offset':frame_fragment_offset , 'frame_fragment_data':frame_fragment_data, 'garbage':garbage}
        self.parent = None

# classes associated to each nt
# XXX: worth exploring classes as key of the dict?
# TODO: rename nt->ast/ast_node
nt_classes = {'frame':FrameNode033, 'trace':TraceNode033, 'frame_fragment':FragmentNode033, 'ast':TraceAST033}

#tokens that indicate the limit of associated nt
nt_delimiters = {'end_of_frame_fragment':'frame', 'end_of_frame':'trace', '$':'ast'}

# regex string to tokenize lines of the file
e = r"^(?P<frame_fragment_offset>[0-9A-Fa-f]*)\s(?P<frame_fragment_data>([0-9A-Fa-f]{2}\s)*[0-9A-Fa-f]{2}|[0-9A-Fa-f]{2})?(?P<garbage>.*)(?P<end_of_frame_fragment>\n?|$)"

class TraceFileParser033:
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
        root = TraceAST033()
        nodestack.append(root)

        while len(stack)>0:
            s = stack.pop()
            if s in terminals or s == '$':
                if tokens[i][0] == s: # if token identifier matches element on top of the stack
                    i += 1
                else:
                    raise ValueError("Bad input")

                # AST logic
                if s in nt_delimiters: # catch delimiter tokens and change position in AST to matching node
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

ETHERTYPES = {
    0x0800: 'Internet Protocol version 4',
    0x0806: 'Adresse Resolution Protocol',
    0x8100: 'IEE 802.1Q / IEEE 802.1aq'
}

ETHFRAME_HEADER_FORMATS = {
    0x0800: '!6s6sH',
    0x0806: '!HHBBHI???', #invalid
    0x8100: '!6s6sHHH'
}

def extend_pack_into(format, buffer, offset, *v):
    '''Write bytes values into bytearray at given offset, extends the bytearray to fit the values if necessary'''
    if len(buffer) < offset + struct.calcsize(format):
        buffer = buffer.ljust(offset + struct.calcsize(format), b'\xff') # padding character is 0xff
    struct.pack_into(format, buffer, offset, *v)
    return buffer

@dataclass
class IPv4Packet033:
    header: struct.Struct
    data: bytes

@dataclass
class EthFrame033:
    frame_data: InitVar[bytes]
    payload: bytes = field(init=False)
    header: bytes = field(init=False)
    # hl: int = field(init=False)

    def __post_init__(self, frame_data):
        et = struct.unpack_from("!H", frame_data, 12)[0]
        if et in ETHERTYPES:
            fmt = ETHFRAME_HEADER_FORMATS[et]
            hl = struct.calcsize(fmt)
            self.header = struct.unpack_from(fmt, frame_data, 0)
            self.payload = ...
        else:
            raise ValueError("Unrecognized ethernet type")

@dataclass
class Trace033:
    frames: List[EthFrame033]

class Graph033:
    def __init__(self, trace_data):
        frames = []
        for frame_data in trace_data:
            frames.append(EthFrame033(frame_data))
        self.root = Trace033(frames)


class TraceAnalyser033:
    def extract_trace_data(self, tracenode):
        '''Extracts captured traffic data TraceNode033 object
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
        '''Extracts data of a FrameNode033 object
        '''
        frame_data = bytearray()
        while framenode != None:
            if framenode.children['frame'] == None:
                break
            else:
                raw_data = framenode.children['frame_fragment'].children['frame_fragment_data']
                partial_data = bytes.fromhex(raw_data)
                # in this part the frame data is reorderred
                frame_data = extend_pack_into("{}s".format(len(partial_data))
                            , frame_data
                            , int(bytes.fromhex(framenode.children['frame_fragment'].children['frame_fragment_offset']).hex(),16)
                            , partial_data)
                framenode = framenode.children['frame']

        return frame_data




def main():
    with io.open('extr.txt') as f:
        tp = TraceFileParser033()
        t = tp.lex(f)
        tree = tp.parse(t)
        an = TraceAnalyser033()
        d = an.extract_trace_data(tree.children['trace'])
        f1 = d[0]
        ethf = EthFrame033(f1)
        print("")

if __name__ == "__main__":
    main()
from dataclasses import astuple, dataclass, InitVar, field
import io
from collections import namedtuple
from os import name
import struct
import re
from struct import pack
from typing import List, NamedTuple, Optional, Any, Union
import weakref
# import tinker

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

@dataclass
class FragmentASTNode033:
    '''Represents a fragment node in the AST'''

    parent: weakref.ReferenceType
    frame_fragment_offset: Optional[str] = None
    frame_fragment_data: Optional[str] = None
    garbage: Optional[str] = None

@dataclass
class FrameASTNode033:
    '''Represents a frame node in the AST'''

    parent: weakref.ReferenceType
    frame_fragment: Optional[FragmentASTNode033] = None
    frame: Optional[Any] = None # should be of type FrameNode033 but since you can't forward declare... fuck python
    

@dataclass
class TraceASTNode033:
    '''Represents a trace node in the AST'''

    parent: Optional[weakref.ReferenceType] = None
    frame: Optional[FrameASTNode033] = None
    trace: Optional[Any] = None # fuck python

@dataclass
class TraceAST033:
    '''Represents the root of the AST'''

    root: Optional[TraceASTNode033] = None

    def set_root(self, root):
        self.root = root

# classes associated to each nt
# XXX: worth exploring classes as key of the dict?
# TODO: rename nt->ast/ast_node
nt_classes = {'frame':FrameASTNode033, 'trace':TraceASTNode033, 'frame_fragment':FragmentASTNode033, 'ast':TraceAST033}

#tokens that indicate the limit of associated nt
nt_delimiters = {'end_of_frame_fragment':'frame', 'end_of_frame':'trace', '$':'ast'}

# regex string to tokenize lines of the file
e = r"^(?P<frame_fragment_offset>[0-9A-Fa-f]{2,})\s*(?P<frame_fragment_data>((?<=\s)([0-9A-Fa-f]{2}\s)*[0-9A-Fa-f]{2})|[0-9A-Fa-f]{2})?\s*(?P<garbage>(?<=\s)[^\n]+)?(?P<end_of_frame_fragment>\n|(?<!\n)$)"

class TraceFileParser033:
    def lex(self, tracefile):
        '''Tokenize the tracefile and handles incorrect values
        '''
        tokens = []
        while(l := tracefile.readline()):
            m = re.match(e, l)
            if m: # if line read is matched by e
                for g in m.groupdict().items(): # for all the key/value pair in the matchname/matchvalue
                    tokens.append(g)

            p = tracefile.tell() # save current cursor pos
            c = tracefile.read(1)

            if(c == '\n'):
                tracefile.seek(p) # rewind to saved pos
                continue # if next line is blank, continue

            while(True): # lookahead of 1 "word" after new line if it is offset 0 then insert end_of_fragment token            
                if(c != '0' and c != ' '): break
                if(c == ' '): 
                    tokens.append(('end_of_frame', None))
                    break # bodgy
                c = tracefile.read(1)
            tracefile.seek(p) # rewind to saved pos
        tokens.append(('end_of_frame', None))
        tokens.append(('$', None))

        return tokens

    def parse(self, tokens):
        '''Validates the input and builds the Abstract Syntax Tree of the file
        '''
        stack = ['$', 'trace'] # rightmost element is on the left
        i = 0

        nodestack = []
        ast = TraceAST033()

        print("Parser goes brrr")
        while len(stack)>0:
            s = stack.pop()
            if s in terminals:
                if tokens[i][0] == s: # if token identifier matches element on top of the stack
                    i += 1
                else:
                    raise ValueError("bad token")

                # AST logic
                if s in nt_delimiters: # catch delimiter tokens and change position in AST to matching node
                    while not isinstance(nodestack[-1], nt_classes[nt_delimiters[s]]): # pop stack while class of node is not class of nt associated delimiter
                        try:
                            nodestack.pop() # pop node children
                        except IndexError as e:
                            raise Exception('there is no node corresponding to this delimiter:' + s) from e
                else:
                    setattr(nodestack[-1], s, tokens[i-1][1]) # update value of key = elemnt of stack

            elif s in non_terminals:
                rule = (s, tokens[i][0])
                # print("rule:",rule)
                if rule in productions:
                    for r in reversed(productions[rule]): # reversed because leff hand elements must be evaluated first
                        stack.append(r)
                else:
                    raise ValueError("bad rule")

                # AST logic 
                
                if len(nodestack) == 0:
                    node = nt_classes[s]()
                    ast.set_root(node)
                else:
                    node = nt_classes[s](None) # TODO: find a way to get a hold of parent ref
                    #node.parent = weakref.proxy(nodestack[-1]) # parent is node on top of the stack
                    setattr(nodestack[-1], s, node) # update parents ref to child node
                nodestack.append(node)

        print("Succesfully parsed input")
        return ast


def extend_pack_into(format, buffer, offset, *v):
    '''Write bytes values into bytearray at given offset, extends the bytearray to fit the values if necessary'''
    if len(buffer) < offset + struct.calcsize(format):
        buffer = buffer.ljust(offset + struct.calcsize(format), b'\xff') # padding character is 0xff
    struct.pack_into(format, buffer, offset, *v)
    return buffer

ETH_TYPE = {
    0x0800: 'Internet Protocol version 4',
    0x0806: 'Adresse Resolution Protocol',
    0x8100: 'IEE 802.1Q / IEEE 802.1aq'
}

ETH_HDR_STRUCT_FMT = {
    0x0800: '!6s6sH',
    0x0806: '!HHBBHI???', #invalid
    0x8100: '!6s6sHHH'
}

ETH_HDR = {
    0x0800: namedtuple('H0800', ['dst', 'src', 'type'])
}

IP4_PROTO = {
    0x06: 'Transmission Control Protocol'
}

IP4_HDR_STRUCT_FMT = '!BBHHHBBHII'

IP4_HDR = namedtuple('HIP4', ['version', 'ihl', 'tos', 'tlength', 'id', 'flags', 'frag_offset', 'ttl', 'proto', 'checksum', 'src', 'dst'])

IP4_OPT_LENGTH = {
    0: 1,
    1: 1,
    2: 11,
    3: -1,
    7: -1,
    9: -1,
    4: -1,
    18: 12
}

TCP_HDR_STRUCT_FMT = '!HHIIBBHHH'

TCP_HDR = namedtuple('HTCP', ['src_port', 'dst_port', 'seq', 'ack', 'hl', 'flags', 'win', 'chksum', 'urg'])


@dataclass
class TCPSegment:
    header: NamedTuple
    opt: bytes
    payload: bytes

    @classmethod
    def from_bytes(cls, tcp_data):
        l = (struct.unpack_from('!B', tcp_data, 12)[0] >> 4) * 4
        h = struct.unpack_from(TCP_HDR_STRUCT_FMT, tcp_data, 0)
        h = h[0:4] + (h[4] & 0xE0,) + (h[5],) + h[6:]
        segment_header = TCP_HDR._make(h)
        segment_opt = h[struct.calcsize(TCP_HDR_STRUCT_FMT):l]
        segment_payload = tcp_data[l:]
        
        return cls(segment_header, segment_opt, segment_payload)

# TODO: fix flags offsets
@dataclass
class IPv4Packet033:
    header: NamedTuple
    opt: bytes
    payload: Union[bytes, TCPSegment]

    @classmethod
    def from_bytes(cls, packet_data):
        ''''''
        p = struct.unpack_from('!B', packet_data, 9)[0]
        if p in IP4_PROTO:
            h = struct.unpack_from(IP4_HDR_STRUCT_FMT, packet_data, 0)
            h = (h[0] & 0xF0, h[0] & 0x0F) + h[1:4] + (h[4] & 0xE0, h[4] & 0x1F) + h[5:] # extracts data from the fields taht are less than 1 byte long, /!\ missing first flag because not in same byte
            packet_header = IP4_HDR._make(h)

            packet_opt = packet_data[struct.calcsize(IP4_HDR_STRUCT_FMT):packet_header.ihl]
            packet_payload = TCPSegment.from_bytes(packet_data[packet_header.ihl*4:])
        else:
            return packet_data

        return cls(packet_header, packet_opt, packet_payload)


@dataclass
class EthFrame033:
    header: NamedTuple
    payload: Union[bytes, IPv4Packet033]

    @classmethod
    def from_bytes(cls, frame_data):
        '''Builds a EthFrame033 object from a string of bytes'''
        e = struct.unpack_from('!H', frame_data, 12)[0] # attempts to read the ethernet type of the packet from the data
        if e in ETH_TYPE: # if header format is known initialize the header
            frame_header = ETH_HDR[e]._make(struct.unpack_from(ETH_HDR_STRUCT_FMT[e], frame_data, 0))
            frame_payload = IPv4Packet033.from_bytes(frame_data[struct.calcsize(ETH_HDR_STRUCT_FMT[e]):])
        else:
            return frame_data # if the header format is not understood, returns the frame data instead
        
        return cls(frame_header, frame_payload)

@dataclass
class Trace033:
    frames: List[Union[bytes, EthFrame033]]

class TraceAnalyser033:
    def extract_trace_data(self, tracenode):
        '''Extracts captured traffic data TraceNode033 object
        '''
        trace_data = []
        while tracenode != None:
            if tracenode.trace == None:
                break
            else:
                frame_data = self.extract_framenode_data(tracenode.frame)
                trace_data.append(frame_data)
                tracenode = tracenode.trace

        return trace_data

    def extract_framenode_data(self, framenode):
        '''Extracts data of a FrameNode033 object
        '''
        frame_data = bytearray()
        while framenode != None:
            if framenode.frame == None:
                break
            else:
                raw_data = framenode.frame_fragment.frame_fragment_data
                partial_data = bytes.fromhex(raw_data)
                # in this part the frame data is reorderred
                frame_data = extend_pack_into("{}s".format(len(partial_data))
                            , frame_data
                            , int(bytes.fromhex(framenode.frame_fragment.frame_fragment_offset).hex(),16)
                            , partial_data)
                framenode = framenode.frame

        return frame_data

    def derive_tree(self, ast):
        '''Derive a tree representing the trace from the AST produced by the parse method'''
        trace_data = self.extract_trace_data(ast.root)
        frames = []
        for frame_data in trace_data:
            try:
                frames.append(EthFrame033.from_bytes(frame_data))
            except ValueError as e:
                pass
                
        return Trace033(frames)

def main():
    with io.open('textcap.txt') as f:
        tp = TraceFileParser033()
        t = tp.lex(f)
        tree = tp.parse(t)
        an = TraceAnalyser033()
        d = an.extract_trace_data(tree.root)
        f1 = d[0]
        frb = EthFrame033.from_bytes(f1)
        g = an.derive_tree(tree)
        print("")

        

if __name__ == "__main__":
    main()

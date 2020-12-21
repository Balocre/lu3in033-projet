import sys
import argparse
from dataclasses import astuple, dataclass, InitVar, field
import io
from collections import namedtuple
from os import name
import struct
import re
from struct import pack
from typing import List, NamedTuple, Optional, Any, Union
import warnings
import weakref
import curses

# context-free LL1 grammar associated with the trace file

# Grammar
# S -> T
# T -> F end_of_frame T | empty
# F -> G F | empty
# G -> frame_fragment_offset frame_fragment_data garbage end_of_fragment
# $ -> EOF

# set of terminal symbols of the grammar
terminals = {
    'frame_fragment_offset',
    'frame_fragment_data',
    'garbage',
    'end_of_frame_fragment',
    'end_of_frame'
}

# set of non-terminal symbols of the grammar
non_terminals = {
    'frame',
    'trace',
    'frame_fragment'
}

# axiom of the grammar (not used)
axiom = 'trace' # S -> T

# end-of-input special symbol
end_of_input = '$'

# production rules
# they are of the form ('element on the stack', 'element on the input'):['leftmost element', ..., 'rightmost element']
productions = { ('trace', 'frame_fragment_offset'):['frame', 'end_of_frame', 'trace']
        , ('trace', '$'):[]
        , ('trace', 'end_of_frame'):['frame', 'end_of_frame', 'trace']
        , ('frame', 'frame_fragment_offset'):['frame_fragment', 'end_of_frame_fragment', 'frame']
        , ('frame', 'end_of_frame'):[]
        , ('frame_fragment', 'frame_fragment_offset'):['frame_fragment_offset', 'frame_fragment_data', 'garbage']
        }


# AST structures definitions
# the following classes represents the various nodes that can be found in the
# Abstract Syntax Tree derived from the parsing of the trace file

@dataclass
class FragmentASTNode033:
    '''Represents a frame fragment node in the AST
    
    Args:
        parent (weakref.ReferenceType): Reference to the parent of the node
        frame_fragment_offset (str, optional): Byte string whose value is
            the offset of the frame fragment in the frame
        frame_fragment_data (str, optional): Byte string whose value is the
            data conatined by the frame fragment
        garbage (str, optional): Byte string that represents the ascii text that
            can be found at the end of the lines
    '''

    parent: weakref.ReferenceType
    frame_fragment_offset: Optional[str] = None
    frame_fragment_data: Optional[str] = None
    garbage: Optional[str] = None


@dataclass
class FrameASTNode033:
    '''Represents a frame node in the AST
    
    Args:
        parent (weakref.ReferenceType): Reference to the parent of the node
        frame_fragment (FragmentASTNode033, optional): Represents the leftmost
            part of a frame in the production rule F
        frame (Any, optional) : Represents the rightmost part of the frame in
            the production rule F

    Note:
        The type of frame should be FrameASTNode033, but python does not support
            forward declaration
    '''

    parent: weakref.ReferenceType
    frame_fragment: Optional[FragmentASTNode033] = None
    frame: Optional[Any] = None # should be of type FrameNode033 but since you can't forward declare... fuck python
    

@dataclass
class TraceASTNode033:
    '''Represents a trace node in the AST
    
    Args:
        parent (weakref.ReferenceType): Reference to the parent of the node
        frame (FrameASTNode033, optional) : Represents the frame in the
            production rule T
        trace (Any, optional): represents the rest of the trace in the
            production rule T
    '''

    parent: Optional[weakref.ReferenceType] = None
    frame: Optional[FrameASTNode033] = None
    trace: Optional[Any] = None # fuck python

@dataclass
class TraceAST033:
    '''Represents the AST
    
    Args:
        root (:obj:`TraceASTNode033`): The root of the AST
    '''

    root: Optional[TraceASTNode033] = None

# classes associated to each nt
# XXX: worth exploring classes as key of the dict?
# TODO: rename nt->ast/ast_node
nt_classes = {'frame':FrameASTNode033, 'trace':TraceASTNode033, 'frame_fragment':FragmentASTNode033, 'ast':TraceAST033}

#tokens that indicate the limit of associated nt
nt_delimiters = {'end_of_frame_fragment':'frame', 'end_of_frame':'trace', '$':'ast'}

# regex used to tokenize the lines
e = r"^(?P<frame_fragment_offset>[0-9A-Fa-f]{2,})\s*(?P<frame_fragment_data>((?<=\s)([0-9A-Fa-f]{2}\s)*[0-9A-Fa-f]{2})|[0-9A-Fa-f]{2})?\s*(?P<garbage>(?<=\s)[^\n]+)?(?P<end_of_frame_fragment>\n|(?<!\n)$)"

class TraceFileParser033:
    def lex(self, tracefile):
        '''Tokenize the tracefile and handles incorrect values

        Args:
            tracefile (:obj:`io.FileIO`): File object of the trace
        '''

        print("Lexer goes brrt")
        tokens = []

        while True: # skip lines until beginning of first frame is found
            p = tracefile.tell()
            l = tracefile.readline()
            m = re.match(e, l)
            if m != None:
                tracefile.seek(p)
                break

        while(l := tracefile.readline()):
            m = re.match(e, l)
            if m: # if line read is matched by e
                for g in m.groupdict().items(): # for all the key/value pair in the matchname/matchvalue
                    tokens.append(g)

            p = tracefile.tell() # save current cursor pos
            c = tracefile.read(1)

            if(c == '\n'): # if next line is blank, continue
                tracefile.seek(p) # rewind to saved pos
                continue

            while(True): # look for a sequence of contiguous zeros        
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

        Args:
            tokens (:obj:`list` of :obj:`str`): List of tokens returned by the
                lexer
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
                    ast.root = node
                else:
                    node = nt_classes[s](None) # TODO: find a way to get a hold of parent ref
                    #node.parent = weakref.proxy(nodestack[-1]) # parent is node on top of the stack
                    setattr(nodestack[-1], s, node) # update parents ref to child node
                nodestack.append(node)

        print("Succesfully parsed input")
        return ast

@dataclass
class HttpMessage:
    header_data: bytes
    message_data: bytes

    PROTO="http"
    
    @property
    def size(self):
        return len(self.header_data) \
                + len(self.message_data) if self.message_data != None else 0

    @property
    def header(self):
        return self.header_data.decode("utf-8")

    @classmethod
    def from_bytes(cls, http_data):

        split = http_data.split(b'\r\n\r\n', 1)
        if len(split) == 2:
            http_header, http_message = split
        else:
            http_header = split[0]
            http_message = None

        return cls(http_header, http_message)

# list of well known application ports
TCP_KNOWN_PORTS = {
    80: HttpMessage
}

TCP_HDR_STRUCT_FMT = '!2s2s4s4s2s2s2s2s'

TcpHdr = namedtuple('HTCP', ['src_port', 'dst_port', 'seq', 'acknum', 'hl', 'flags', 'ecn', 'cwr', 'ece', 'urg', 'ack', 'psh', 'rst', 'syn', 'fin', 'win', 'chksum', 'urgp'])
@dataclass
class TCPSegment033:
    '''Represents a TCP segment

    Args:

    '''
    header_data: bytes
    opt_data: bytes
    payload: Union[bytes, HttpMessage]

    PROTO = "tcp"

    @property
    def size(self):
        return len(self.header_data) \
                + self.payload.size if not isinstance(self.payload, bytes) and self.payload != None \
                                    else len(self.payload) if self.payload != None else 0

    @property
    def header(self):
        h = struct.unpack(TCP_HDR_STRUCT_FMT, self.header_data)

        # expand header length and flags
        h = h[0:4] \
            + (bytes([(h[4][0] & 0xF0) >> 4]),) \
            + (bytes([h[4][0] & 0x0F, h[4][1] & 0xFF]),) \
            + (bytes([(h[4][0] & 0x01)]),) \
            + (bytes([(h[4][1] & 0x80) >> 7]),) \
            + (bytes([(h[4][1] & 0x40) >> 6]),) \
            + (bytes([(h[4][1] & 0x20) >> 5]),) \
            + (bytes([(h[4][1] & 0x10) >> 4]),) \
            + (bytes([(h[4][1] & 0x08) >> 3]),) \
            + (bytes([(h[4][1] & 0x04) >> 2]),) \
            + (bytes([(h[4][1] & 0x02) >> 1]),) \
            + (bytes([(h[4][1] & 0x01)]),) \
            + h[5:]
        return TcpHdr._make(h)

    @classmethod
    def from_bytes(cls, tcp_data):
        if len(tcp_data) < 20:
            warnings.warn("Malformed segment: header is incomplete, can't parse segment", BytesWarning)
            return bytes(tcp_data)

        hl = (struct.unpack_from('!B', tcp_data, 12)[0] >> 4) * 4
        src = struct.unpack_from('!H', tcp_data, 0)[0]
        dst = struct.unpack_from('!H', tcp_data, 2)[0]
       
        segment_header = bytes(tcp_data[0:20])
        segment_opt = bytes(tcp_data[20:hl])

        if not tcp_data[hl:]:
            return cls(segment_header, segment_opt, None)

        if src in TCP_KNOWN_PORTS:
            segment_payload = TCP_KNOWN_PORTS[src].from_bytes(tcp_data[hl:])
        elif dst in TCP_KNOWN_PORTS:
            segment_payload = TCP_KNOWN_PORTS[dst].from_bytes(tcp_data[hl:])
        else:
            segment_payload = bytes(tcp_data[hl:])

        return cls(segment_header, segment_opt, segment_payload)
        

# dict of know transport protocols
IP4_PROTO = {
    0x06: TCPSegment033
}

IP4_HDR_STRUCT_FMT = '!cc2s2s2scc2s4s4s'

# dict of know option length
# length = -1 is variable
IP4_OPT_LEN = {
    0: 1,
    1: 1,
    2: 11,
    3: -1,
    7: -1,
    9: -1,
    4: -1,
    18: 12
}

Ipv4Header033 = namedtuple('Ipv4Header033', ['version', 'ihl', 'tos', 'tlength', 'id', 'flags', 'frag_offset', 'ttl', 'proto', 'checksum', 'src', 'dst'])

# TODO: fix flags offsets
@dataclass
class IPv4Packet033:
    header_data: bytes
    opt_data: bytes
    payload: Union[bytes, TCPSegment033]

    PROTO = "ipv4"

    @property
    def size(self):
        return len(self.header_data) \
                + len(self.opt_data) \
                + self.payload.size if not isinstance(self.payload, bytes) else len(self.payload)

    @property
    def header(self):
        ''''''
        h = struct.unpack(IP4_HDR_STRUCT_FMT, self.header_data)
        h = (bytes([h[0][0] >> 4]), bytes([h[0][0] & 0x0F])) \
            + h[1:4] \
            + (bytes([h[4][0] & 0xE0]), bytes([h[4][0] & 0x1F])) \
            + h[5:]
        return Ipv4Header033._make(h)

    @classmethod
    def from_bytes(cls, packet_data):
        ''''''
        tl = struct.unpack_from('!H', packet_data, 2)[0]
        if len(packet_data) < 20:
            warnings.warn("Malformed packet: header is incomplete, can't parse packet", BytesWarning)
            return bytes(packet_data)
        if len(packet_data) != tl:
            warnings.warn("Malformed packet: some data is missing, can't parse packet", BytesWarning)
            return bytes(packet_data)

        hl = (struct.unpack_from('!B', packet_data, 0)[0] & 0x0F) * 4
        proto = struct.unpack_from('!B', packet_data, 9)[0]

        packet_header = bytes(packet_data[0:20])
        packet_opt = bytes(packet_data[20:hl])

        if proto in IP4_PROTO:
            packet_payload = IP4_PROTO[proto].from_bytes(packet_data[hl:])
        else:
            packet_payload = bytes(packet_data[hl:])
        
        return cls(packet_header, packet_opt, packet_payload)

ETH_TYPE = {
    0x0800: 'Internet Protocol version 4',
}

ETH_HDR_STRUCT_FMT = {
    0x0800: '!6s6s2s', # '!6s6sH'
}

EthHdr = {
    0x0800: namedtuple('EthernetHeader', ['dst', 'src', 'type'])
}

@dataclass
class EthFrame033:
    header_data: bytes
    payload: Union[bytes, IPv4Packet033]

    PROTO = "ethernet"

    @property
    def size(self):
        return struct.calcsize(ETH_HDR_STRUCT_FMT[0x0800]) + self.payload.size if not isinstance(self.payload, bytes) else len(self.payload)

    @property
    def header(self):
        '''Builds a EthFrame033 object from a string of bytes'''

        e = struct.unpack_from('!H', self.header_data, 12)[0] # attempts to read the ethernet type of the packet from the data
        if e in ETH_TYPE: # if header format is known initialize the header
            return EthHdr[e]._make(struct.unpack(ETH_HDR_STRUCT_FMT[e], self.header_data))
        else:
            warnings.warn("Unknow ether type: can't parse frame")
            return self.header_data # if the header format is not understood, returns the frame data instead

    @classmethod
    def from_bytes(cls, frame_data):
        '''Builds a EthFrame033 object from a string of bytes'''

        etype = struct.unpack_from('!H', frame_data, 12)[0] # attempts to read the ethernet type of the packet from the data
        if etype in ETH_TYPE: # if header format is known initialize the header
            h_size = struct.calcsize(ETH_HDR_STRUCT_FMT[etype])
            fh = bytes(frame_data[0:h_size])
            fp = IPv4Packet033.from_bytes(frame_data[h_size:])
            return cls(fh, fp)
        else:
            return bytes(frame_data) # if the header format is not understood, returns the frame data instead
        
    
@dataclass
class Trace033:
    frames: List[Union[bytes, EthFrame033]]


def extend_pack_into(format, buffer, offset, *v):
    '''Write bytes values into bytearray at given offset, extends the bytearray to fit the values if necessary'''
    if len(buffer) < offset + struct.calcsize(format):
        buffer = buffer.ljust(offset + struct.calcsize(format), b'\xff') # padding character is 0xff
    struct.pack_into(format, buffer, offset, *v)
    return buffer

class TraceAnalyser033:
    # TODO: add verification of contiguous data and return error if gap
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

                if framenode.frame.frame_fragment != None: # if next frame contains no fragment that means code reached end of frame structure
                    nextoff = int(framenode.frame.frame_fragment.frame_fragment_offset, 16)
                    curoff = int(framenode.frame_fragment.frame_fragment_offset, 16)
                    if curoff + len(partial_data) != nextoff:
                        raise ValueError("Frame data is not contiguous")
                        warnings.warn("Frame is incomplete, some data is missing")

                # in this part the frame data is reorderred
                frame_data = extend_pack_into("{}s".format(len(partial_data))
                            , frame_data
                            , int(bytes.fromhex(framenode.frame_fragment.frame_fragment_offset).hex(),16)
                            , partial_data)
                framenode = framenode.frame

        return frame_data

    def extract_trace_data(self, tracenode):
        '''Extracts captured traffic data TraceNode033 object
        '''
        trace_data = []
        i = 0
        while tracenode != None:
            if tracenode.trace == None:
                break
            else:
                try:
                    frame_data = self.extract_framenode_data(tracenode.frame)
                    trace_data.append(frame_data)
                except ValueError as e:
                    warnings.warn(f"Can't parse frame {i:x}")
                finally:
                    tracenode = tracenode.trace
                    i += 1

                    

        return trace_data

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


# code adapted from https://www.geoffreybrown.com/blog/a-hexdump-program-in-python/
def hexdump(bytes):
    try:
        with io.BytesIO(bytes) as b:
            n = 0
            s = b.read(16)

            while s:
                s1 = " ".join([f"{i:02x}" for i in s]) # hex string
                s1 = s1[0:23] + " " + s1[23:]          # insert extra space between groups of 8 hex values

                s2 = "".join([chr(i) if 32 <= i <= 127 else "." for i in s]) # ascii string; chained comparison

                print(f"{n * 16:08x}  {s1:<48}  |{s2}|")

                n += 1
                s = b.read(16)
    except Exception as e:
        pass


UP = -1
DOWN = 1

pretty_names = {
    EthFrame033: {"src": "src: 0x{1:x} - {0[0]:x}:{0[1]:x}:{0[2]:x}:{0[3]:x}:{0[4]:x}:{0[5]:x}"
                    , "dst": "dst: 0x{1:x} - {0[0]:x}:{0[1]:x}:{0[2]:x}:{0[3]:x}:{0[4]:x}:{0[5]:x}"
                    , "type": "eth type: 0x{1:x} - {1:d}"}
    , IPv4Packet033: {"version": "version: 0x{1:x} - {1:d}"
                        , "ihl": "header length: 0x{1:x} - {1:d}"
                        , "tos": "tos: 0x{1:x}"
                        , "tlength": "total length: 0x{1:x} - {1:d}"
                        , "id": "id: 0x{1:x} - {1:d}"
                        , "flags": "flags: 0x{1:x}"
                        , "frag_offset": "fragment offset: 0x{1:x} - {1:d}"
                        , "ttl" : "ttl: 0x{1:x} - {1:d}"
                        , "proto": "protocol: 0x{1:x} - {1:d}"
                        , "checksum": "checksum: 0x{1:x} - {1:d}"
                        , "src": "source adress: 0x{1:x} - {0[0]:d}.{0[1]:d}.{0[2]:d}.{0[3]:d}"
                        , "dst": "destination adress: 0x{1:x} - {0[0]:d}.{0[1]:d}.{0[2]:d}.{0[3]:d}"}
    , TCPSegment033: {"src_port": "source port: 0x{1:x} - {1:d}"
                        , "dst_port": "destination port: 0x{1:x} - {1:d}"
                        , "seq": "sequence number: 0x{1:x} - {1:d}"
                        , "acknum": "acknowledgement number: 0x{1:x} - {1:d}"
                        , "hl": "header length: 0x{1:x} - {1:d}"
                        , "flags": "flags: 0x{1:x} - {1:d}"
                        , "ecn": "...{1:d} .... .... - Nonce"
                        , "cwr": ".... {1:d}... .... - Congestion Window Reduced"
                        , "ece": ".... .{1:d}.. .... - ECN-Echo"
                        , "urg": ".... ..{1:d}. .... - Urgent"
                        , "ack": ".... ...{1:d} .... - Acknowledgement"
                        , "psh": ".... .... {1:d}... - Push"
                        , "rst": ".... .... .{1:d}.. - Reset"
                        , "syn": ".... .... ..{1:d}. - Syn"
                        , "fin": ".... .... ...{1:d} - Fin"
                        , "win": "window: 0x{1:x} - {1:d}"
                        , "chksum": "checksum: 0x{1:x} - {1:d}"
                        , "urgp": "urgent pointer: 0x{1:x} - {1:d}"}
}

def run_cursed_ui(stdscr, tracetree):
    stdscrh, stdscrw = stdscr.getmaxyx()

    # frame menu
    frmwinh = stdscrh-2
    frmwinw = 50
    frmwinx = 0
    frmwiny = 0
    
    frmwin = stdscr.subwin(frmwinh, frmwinw, frmwiny, frmwinx)
    frmwin.border()

    frmpadh = len(tracetree.frames)
    frmpadw = frmwinw-2
    frmpadtl = (frmwiny+1, frmwinx+1) # position of top left corner of pad on screen
    frmpadbr = (frmwinh-2, frmwinw-2) # position of bottom right corner

    frmpad = curses.newpad(frmpadh, frmpadw)
    frmpad_refresh = lambda: frmpad.refresh(topfrmidx, 0, *frmpadtl, *frmpadbr)

    # header menu
    hdrwinh = stdscrh-2
    hdrwinw = 20
    hdrwinx = frmwinx+frmwinw
    hdrwiny = 0

    hdrwin = stdscr.subwin(hdrwinh, hdrwinw, hdrwiny, hdrwinx)
    hdrwin.border()

    hdrpadh = hdrwinh-2
    hdrpadw = hdrwinw-2
    hdrpadtl = (hdrwiny+1, hdrwinx+1)
    hdrpadbr = (hdrwinh-2, hdrwinx+hdrwinw-2)

    hdrpad = curses.newpad(hdrpadh, hdrpadw)
    hdrpad_refresh = lambda: hdrpad.refresh(0, 0, *hdrpadtl, *hdrpadbr)

    # field infos
    fldwinh = stdscrh-2
    fldwinw = stdscrw-(hdrwinx+hdrwinw)
    fldwinx = hdrwinw+hdrwinx
    fldwiny = 0

    fldpadh = fldwinh-2
    fldpadw = fldwinw-2
    fldpadtl = (fldwiny+1, fldwinx+1)
    fldpadbr = (fldwinh-2, fldwinx+fldwinw-2)

    fldpad = curses.newpad(fldpadh, fldpadw)
    fldpad_refresh = lambda: fldpad.refresh(0, 0, *fldpadtl, *fldpadbr)

    fldwin = stdscr.subwin(fldwinh, fldwinw, fldwiny, fldwinx)
    fldwin.border()

    topfrmidx = 0
    selfrmidx = 0
    maxfrmidx = len(tracetree.frames)
  
    # populate the frame list into the the frame pad
    frames = []
    frames = tracetree.frames
    i = 0
    for f in frames:
        p = f
        protos = ""
        while True:
            protos += p.PROTO if hasattr(p, "PROTO") else "unknown"
            if hasattr(p, "payload") and p.payload != None:
                protos += ":"
                p = p.payload
            else:
                break
        s = f"0x{i:04x} " + protos + f" {f.size}"
        frmpad.addstr(i, 0, s)
        i += 1
    frmpad.chgat(selfrmidx, 0, frmpadw, curses.A_STANDOUT)
    
    stdscr.refresh()
    frmpad_refresh()

    print(hdrpadh, hdrpadw, hdrpadtl, hdrpadbr) # debug

    # main UI loop
    while True:
        selhdridx = 0

        hdrpad.erase()
        fldpad.erase()
    
        # build the protocol stack for selected frame
        protocol_stack = []
        pl = tracetree.frames[selfrmidx]
        i = 0
        while True:
            protocol_stack.append(pl)
            if hasattr(pl, "payload") and (pl.payload != None and not isinstance(pl.payload, bytes)):
                pl = pl.payload
            else:
                break
            i += 1 

        # populate the header pad
        i = 0
        for proto in protocol_stack:
            proto_name = proto.PROTO if hasattr(proto, "PROTO") else "unknown"
            hdrpad.addstr(i, 0, proto_name)
            i += 1
       
        hdrpad_refresh()
        fldpad_refresh()

        k = stdscr.getkey()
        
        if k == "KEY_A2":   
            frmpad.chgat(selfrmidx, 0, frmpadw, curses.A_NORMAL)
            selfrmidx = max(0, selfrmidx-1)
            topfrmidx = min(selfrmidx, topfrmidx)
            frmpad.chgat(selfrmidx, 0, frmpadw, curses.A_STANDOUT)

        elif k == "KEY_C2":
            frmpad.chgat(selfrmidx, 0, frmpadw, curses.A_NORMAL)
            selfrmidx = min(frmpadh-1, selfrmidx+1)
            topfrmidx = max(max(selfrmidx-frmwinh+3,0), topfrmidx)
            frmpad.chgat(selfrmidx, 0, frmpadw, curses.A_STANDOUT)

        elif k == "\n" or k == "KEY_B3": # enter header menu
            maxhdridx = len(protocol_stack)-1 # maybe rename layer
            hdrpad.chgat(selhdridx, 0, hdrpadw, curses.A_STANDOUT)
            hdrpad_refresh()

            while True:
                fldpad.erase()
                fldpad_refresh()

                # populate the field pad
                p = protocol_stack[selhdridx]
                fldidx = 0
                h = p.header
                
                if type(p) == HttpMessage:
                    buf = io.StringIO(p.header)
                    n = 0
                    while l := buf.readline(fldpadw):
                        n+=1
                    buf.seek(0)
                    fldpad.resize(n, fldpadw)
                    i = 0
                    while l := buf.readline(fldpadw):
                        fldpad.addstr(i, 0, l)
                        i+=1
                else:
                    fldpad.resize(len(h._asdict()), fldpadw)
                    for field_name, field_value in h._asdict().items():
                        s = pretty_names.get(type(p)) \
                                    .get(field_name, f"{field_name} : {field_value.hex()}") \
                                    .format(field_value, int(field_value.hex(), 16))
                        fldpad.addstr(fldidx, 0, s)
                        fldidx += 1

                fldpad_refresh()

                k = stdscr.getkey()

                if k == "KEY_A2":   
                    hdrpad.chgat(selhdridx, 0, hdrpadw, curses.A_NORMAL)
                    selhdridx = max(0, selhdridx-1)
                    hdrpad.chgat(selhdridx, 0, hdrpadw, curses.A_STANDOUT)
                elif k == "KEY_C2":
                    hdrpad.chgat(selhdridx, 0, hdrpadw, curses.A_NORMAL)
                    selhdridx = min(maxhdridx, selhdridx+1)
                    hdrpad.chgat(selhdridx, 0, hdrpadw, curses.A_STANDOUT)
                elif k == "KEY_B1":
                    break
                elif k == "q":
                    exit(0)

                hdrpad_refresh()
            continue
        elif k == "q":
            exit(0)
        else: # debug
            print(k)

        stdscr.move(stdscrh-1, 0)
        stdscr.clrtoeol()
        stdscr.addstr(stdscrh-1, 0, "sf:{} tf:{}".format(selfrmidx, topfrmidx))
        frmpad_refresh()
        
        
def main(path):
    ftrace = io.open(path, 'r')

    parser = TraceFileParser033()
    analyser = TraceAnalyser033()

    traceast = parser.parse(parser.lex(ftrace))
    tracetree = analyser.derive_tree(traceast)

    curses.wrapper(run_cursed_ui, tracetree)

    print(len(tracetree.frames)+1)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Analyze captured traffic")

    ap.add_argument('Trace'
                        , metavar='path'
                        , type=str
                        , help='path to the trace file')

    args = ap.parse_args()

    path = args.Trace

    main(path)


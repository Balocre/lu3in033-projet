from dataclasses import dataclass
import io
from collections import namedtuple
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


class Trace:
    def __init__(self, *frames):
        self.body = []
        for frame in frames:
            self.body.append(frame)

class Frame:
    def __init__(self, *fragments):
        self.body = []
        for frag in fragments:
            self.body.append(frag)

class Fragment:
    def __init__(self, offset, data, garbage):
        self.offset = offset
        self.data = data
        self.garbage = garbage

terminals = (
    'frame_fragment_offset',
    'frame_fragment_data',
    'garbage',
    'end_of_frame_fragment',
    'end_of_frame'
)

non_terminals = (
    'frame',
    'trace',
    'frame_fragment'
)

axiom = 'axiom'

end_of_input = '$'

productions = { ('trace', 'frame_fragment_offset'):['frame', 'end_of_frame', 'trace']
        , ('trace', 'end_of_input'):[]
        , ('trace', 'end_of_frame'):['frame', 'end_of_frame', 'trace']
        , ('frame', 'frame_fragment_offset'):['frame_fragment', 'end_of_frame_fragment', 'frame']
        , ('frame', 'end_of_frame'):[]
        , ('frame_fragment', 'frame_fragment_offset'):['frame_fragment_offset', 'frame_fragment_data', 'garbage']
        }

# Grammar
# S -> T
# T -> F end_of_frame T | empty
# F -> G F | empty
# G -> frame_fragment_offset frame_fragment_data garbage end_of_fragment

# $ -> EOF

e = r"^(?P<frame_fragment_offset>[0-9A-Fa-f]*)\s(?P<frame_fragment_data>([0-9A-Fa-f]{2}\s)*[0-9A-Fa-f]{2}|[0-9A-Fa-f]{2})?(?P<garbage>.*)(?P<end_of_frame_fragment>\n?|$)"

class TraceParser033:
    def lex(self, tracefile):
        tokens = []
        while(l := tracefile.readline()):
            m = re.match(e, l)
            if m:
                for g in m.groupdict().items():
                    tokens.append(g)
            p = tracefile.tell() # save current cursor pos
            c = tracefile.read(1)
            if c == '': # thet for eof by reading 1 charcter
                    tokens.append(('end_of_frame',))
                    break
            while(True): # lookahead of 1 "word" after new line if it is offset 0 then insert end_of_fragment token                
                if(c != '0' and c != ' '): break
                if(c == ' '): tokens.append(('end_of_frame',))
                c = tracefile.read(1)
            tracefile.seek(p) # rewind to saved pos
        tokens.append(('end_of_input', '$'))

        return tokens

    def parse(self, tokens):
        stack = []
        stack.append('trace')
        i = 0
        for t in tokens: print("tvalue:",t[0])
        while len(stack)>0:
            print("stack1:",stack)
            s = stack.pop()
            print("stack2:",stack)
            print("s:",s)
            print("token:",tokens[i])
            if s in terminals or s == '$':
                if tokens[i][0] == s:
                    i += 1
                else:
                    raise ValueError("Bad input")
            elif s in non_terminals:
                rule = (s, tokens[i][0])
                print("rule:",rule)
                if rule in productions:
                    for r in reversed(productions[rule]):
                        stack.append(r)
                else:
                    raise ValueError("Bad rule")

def main():
    with io.open('extr.txt') as f:
        tp = TraceParser033()
        print(f)
        t = tp.lex(f)
        print(t)
        tp.parse(t)

if __name__ == "__main__":
    main()
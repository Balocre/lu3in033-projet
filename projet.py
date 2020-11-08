from dataclasses import dataclass
import io

# EthFrame = namedtuple('src', 6, 'dst', 6, 'type', 6, 'data', 46-1500)
# IPV4Packet = namedtuple('version', 'hl', 'tos', 'length', 'id', 'frag', 'ttl', 'proto', 'chksum', 'src', 'dst', 'opt', 'data')
# TCPSegment = namedtuple('tcp')
# HTTPMessage = namedtuple('http')

@dataclass
class EthFrame:
    src: bytes
    dst: bytes
    ethtype: bytes
    data: bytes

    @classmethod
    def fromhex(cls, s): # on multiplie le nombre d'octets par 3 car dans une chaine de hex 1 octet = 2 hex + 1 espace
        src = bytes.fromhex(s[:18])
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
    df: bytes
    mf: bytes
    frag: bytes
    ttl: bytes
    proto: bytes
    chksum: bytes
    src: bytes
    dst: bytes
    opt: bytes
    data: bytes
        
    @classmethod
    def fromhex(cls, s):
        ver = bytes.fromhex(s[:12])
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

class TraceParser033:
    def __init__(self, f):
        self.tracefile = io.open(f, 'r')

    def readfisrtframe(self):
        buf = io.StringIO()
        o, d = self.tracefile.readline().split(' ', 1)
        buf.write(d.rstrip() + ' ')
        while(l := self.tracefile.readline()):
            o, d = l.split(' ', 1)
            if(int(o, 16) == 0):
                break
            buf.write(d.rstrip() + ' ')

        return EthFrame.fromhex(buf.getvalue())

def main():
    t = TraceParser033('extr.txt')
    frame = t.readfisrtframe()

    print("src: ", frame.src.hex())
    print("dst :", frame.dst.hex())
    print("ethtype :", frame.ethtype.hex())
    print("data :", frame.data.hex())

if __name__ == "__main__":
    main()
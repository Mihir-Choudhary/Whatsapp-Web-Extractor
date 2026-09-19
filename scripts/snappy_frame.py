import sys, struct
sys.path.insert(0,'scripts'); from snappy_pure import uncompress
def unframe(data):
    assert data[:4]==b'\xff\x06\x00\x00' and data[4:10]==b'sNaPpY', "not framed snappy"
    out=bytearray(); p=10
    while p < len(data):
        t=data[p]; ln=int.from_bytes(data[p+1:p+4],'little'); p+=4
        chunk=data[p:p+ln]; p+=ln
        if t==0x00:      out+=uncompress(chunk[4:])   # compressed (skip 4B CRC)
        elif t==0x01:    out+=chunk[4:]               # uncompressed
        elif t==0xff:    pass                          # stream id (already handled)
        elif t>=0x80:    pass                          # padding/skippable
        else:            pass
    return bytes(out)
if __name__=='__main__':
    d=open(sys.argv[1],'rb').read()
    sys.stdout.buffer.write(unframe(d))

// Wire-01 strict cross-language CBOR verifier. Standard Go library only.
// Produces NO policy authorization; validates canonical framing/transcript.
package main

import (
    "bytes"
    "encoding/binary"
    "encoding/hex"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

const maxEvent = 64 * 1024
const maxPayload = 60 * 1024
const domain = "LOOM:SECURITY-EVENT:V1\x00"

type reader struct { b []byte; pos int }
func (r *reader) take(n uint64) ([]byte, error) {
    if n > uint64(len(r.b)-r.pos) { return nil, errors.New("truncated") }
    s := r.b[r.pos:r.pos+int(n)]
    r.pos += int(n)
    return s, nil
}
func (r *reader) head(major byte) (uint64, error) {
    p, err := r.take(1); if err != nil { return 0, err }
    if p[0] >> 5 != major { return 0, errors.New("wrong type") }
    v := uint64(p[0] & 31)
    switch {
    case v <= 23: return v, nil
    case v == 24:
        n,e := r.take(1); if e != nil { return 0,e }
        if n[0] < 24 { return 0,errors.New("overlong") }
        return uint64(n[0]),nil
    case v == 25:
        n,e := r.take(2); if e != nil { return 0,e }
        x:=uint64(binary.BigEndian.Uint16(n))
        if x <= 255 { return 0,errors.New("overlong") }; return x,nil
    case v == 26:
        n,e := r.take(4); if e != nil { return 0,e }
        x:=uint64(binary.BigEndian.Uint32(n))
        if x <= 65535 { return 0,errors.New("overlong") }; return x,nil
    case v == 27:
        n,e := r.take(8); if e != nil { return 0,e }
        x:=binary.BigEndian.Uint64(n)
        if x <= 4294967295 { return 0,errors.New("overlong") }; return x,nil
    default: return 0,errors.New("indefinite/reserved")
    }
}
func (r *reader) uint() (uint64,error) { return r.head(0) }
func (r *reader) bin(limit uint64) ([]byte,error) {
    n,e:=r.head(2); if e != nil{return nil,e}
    if n>limit {return nil,errors.New("length")}
    return r.take(n)
}
func decode(b []byte) error {
    if len(b)>maxEvent {return errors.New("event too large")}
    r:=reader{b:b}
    n,e:=r.head(5); if e!=nil || n!=9 {return errors.New("map length")}
    for k:=uint64(0); k<=8; k++ {
        field,err:=r.uint(); if err!=nil || field!=k{return errors.New("unsorted/duplicate key")}
        switch k {
        case 0:
            v,e:=r.uint(); if e!=nil||v!=1{return errors.New("version")}
        case 1:
            v,e:=r.uint(); if e!=nil||v<1||v>5{return errors.New("kind")}
        case 2,3:
            sz:=uint64(16); if k==3{sz=32}
            v,e:=r.bin(sz); if e!=nil||uint64(len(v))!=sz{return errors.New("identity length")}
        case 4,7:
            if _,e:=r.uint();e!=nil{return e}
        case 5:
            if _,e:=r.uint();e!=nil{return e}
        case 6:
            if _,e:=r.uint();e!=nil{return e}
        case 8:
            if _,e:=r.bin(maxPayload);e!=nil{return e}
        }
    }
    if r.pos!=len(b){return errors.New("trailing data")}
    // Independently check issued/expires rather than trusting byte shape.
    r=reader{b:b}; _,_=r.head(5)
    var issued,expires uint64
    for k:=uint64(0);k<=8;k++ {
        _,_=r.uint()
        switch k {
        case 0,1,4,7: _,_=r.uint()
        case 2,3,8: _,_=r.bin(maxEvent)
        case 5: issued,_=r.uint()
        case 6: expires,_=r.uint()
        }
    }
    if issued>=expires {return errors.New("invalid lifetime")}
    return nil
}
func transcript(b []byte) ([]byte,error) {
    if err:=decode(b);err!=nil{return nil,err}
    result:=append([]byte(domain),0,0,0,0)
    binary.BigEndian.PutUint32(result[len(domain):],uint32(len(b)))
    return append(result,b...),nil
}
func fileHex(root,name string) []byte {
    p:=filepath.Join(root,"test-vectors","wire-v1",name)
    raw,e:=os.ReadFile(p);if e!=nil{panic(e)}
    b,e:=hex.DecodeString(strings.TrimSpace(string(raw)));if e!=nil{panic(e)}
    return b
}
func mustReject(name string,b []byte) {
    if decode(b)==nil{panic("accepted "+name)}
}
func main() {
    root:=".";if len(os.Args)>1{root=os.Args[1]}
    for _, name := range []string{"event-01","event-02","event-03"} {
        wire := fileHex(root,name+".cbor.hex")
        expected := fileHex(root,name+".signing.hex")
        actual,e := transcript(wire)
        if e!=nil||!bytes.Equal(expected,actual){panic("golden signing mismatch "+name)}
    }
    b:=fileHex(root,"event-01.cbor.hex")
    for i:=0;i<len(b);i++ {mustReject("truncation",b[:i])}
    scenarios:=map[string][]byte{}
    mutate:=func(name string,at int,value byte){x:=bytes.Clone(b);x[at]=value;scenarios[name]=x}
    mutate("indefinite map",0,0xbf)
    mutate("extra map field",0,0xaa)
    mutate("duplicate key",3,0)
    mutate("unsupported version",2,2)
    mutate("unsupported kind",4,7)
    mutate("tag",0,0xc9)
    x:=append(bytes.Clone(b),0);scenarios["trailing"]=x
    x=bytes.Clone(b);x=append(x[:2],append([]byte{0x18,0x01},x[3:]...)...);scenarios["overlong version"]=x
    x=bytes.Clone(b);x[25]=0x1f;scenarios["identity structure"]=x
    for name,bad:=range scenarios{mustReject(name,bad)}
    fmt.Printf("WIRE-01 Go PASS: canonical golden transcript, %d truncated and %d negative samples\n",len(b),len(scenarios))
}

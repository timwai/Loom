//go:build ignore
// Independent Go stdlib emitter/verifier for Loom's candidate security-event V1.
// Execute: go run ./test-vectors/wire-v1/check.go
package main
import (
  "bytes"
  "crypto/ed25519"
  "crypto/sha256"
  "encoding/binary"
  "encoding/hex"
  "fmt"
  "os"
  "path/filepath"
  "strings"
)

func arg(out *bytes.Buffer, major byte, value uint64) {
  marker:=major<<5
  switch {
  case value<24: out.WriteByte(marker|byte(value))
  case value<=255: out.Write([]byte{marker|24,byte(value)})
  case value<=65535: out.WriteByte(marker|25);_ = binary.Write(out,binary.BigEndian,uint16(value))
  case value<=4294967295: out.WriteByte(marker|26);_ = binary.Write(out,binary.BigEndian,uint32(value))
  default: out.WriteByte(marker|27);_ = binary.Write(out,binary.BigEndian,value)
  }
}
func bytesField(out *bytes.Buffer, b []byte) {arg(out,2,uint64(len(b)));out.Write(b)}
func fixture(name string) []byte {
  path:=filepath.Join("test-vectors","wire-v1",name)
  raw,err:=os.ReadFile(path);if err!=nil {panic(err)}
  data,err:=hex.DecodeString(strings.TrimSpace(string(raw)));if err!=nil {panic(err)}
  return data
}
func requireEqual(label string,a,b []byte) {
  if !bytes.Equal(a,b){panic(fmt.Sprintf("%s mismatch: %x != %x",label,a,b))}
}
func main(){
  var encoded bytes.Buffer
  arg(&encoded,5,9)
  var space,signer []byte
  for i:=0;i<16;i++ {space=append(space,byte(i))}
  for i:=16;i<48;i++ {signer=append(signer,byte(i))}
  arg(&encoded,0,0);arg(&encoded,0,1)
  arg(&encoded,0,1);arg(&encoded,0,3)
  arg(&encoded,0,2);bytesField(&encoded,space)
  arg(&encoded,0,3);bytesField(&encoded,signer)
  arg(&encoded,0,4);arg(&encoded,0,2)
  arg(&encoded,0,5);arg(&encoded,0,1710000000123)
  arg(&encoded,0,6);arg(&encoded,0,1710000030123)
  arg(&encoded,0,7);arg(&encoded,0,8)
  arg(&encoded,0,8);bytesField(&encoded,[]byte{0xa1,0x01,0xf5})
  requireEqual("canonical CBOR",encoded.Bytes(),fixture("event-01.cbor.hex"))
  var transcript bytes.Buffer
  transcript.Write([]byte("LOOM:SECURITY-EVENT:V1\x00"))
  _ = binary.Write(&transcript,binary.BigEndian,uint32(encoded.Len()))
  transcript.Write(encoded.Bytes())
  requireEqual("signing transcript",transcript.Bytes(),fixture("event-01.signing.hex"))
  hasher:=sha256.New();hasher.Write([]byte("LOOM:EVENT-ID:V1\x00"));hasher.Write(encoded.Bytes())
  requireEqual("event id",hasher.Sum(nil),fixture("event-01.event-id.hex"))
  seed:=make([]byte,32);for i:=range seed{seed[i]=byte(i)}
  secret:=ed25519.NewKeyFromSeed(seed)
  requireEqual("public key",secret.Public().(ed25519.PublicKey),fixture("event-01.pubkey.hex"))
  signature:=ed25519.Sign(secret,transcript.Bytes())
  requireEqual("signature",signature,fixture("event-01.signature.hex"))
  if !ed25519.Verify(secret.Public().(ed25519.PublicKey),transcript.Bytes(),signature){panic("invalid signature")}
  forged:=append([]byte(nil),transcript.Bytes()...);forged[len(forged)-1]^=1
  if ed25519.Verify(secret.Public().(ed25519.PublicKey),forged,signature){panic("forged transcript accepted")}
  fmt.Println("Go canonical CBOR, transcript, event id and Ed25519 signature: PASS")
}

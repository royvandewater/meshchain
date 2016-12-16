// Code generated by protoc-gen-go.
// source: seal.proto
// DO NOT EDIT!

package encoding

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type Seal struct {
	Hash      []byte `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
	Signature []byte `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (m *Seal) Reset()                    { *m = Seal{} }
func (m *Seal) String() string            { return proto.CompactTextString(m) }
func (*Seal) ProtoMessage()               {}
func (*Seal) Descriptor() ([]byte, []int) { return fileDescriptor2, []int{0} }

func (m *Seal) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

func (m *Seal) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

func init() {
	proto.RegisterType((*Seal)(nil), "encoding.Seal")
}

func init() { proto.RegisterFile("seal.proto", fileDescriptor2) }

var fileDescriptor2 = []byte{
	// 95 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xe2, 0xe2, 0x2a, 0x4e, 0x4d, 0xcc,
	0xd1, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x48, 0xcd, 0x4b, 0xce, 0x4f, 0xc9, 0xcc, 0x4b,
	0x57, 0xb2, 0xe0, 0x62, 0x09, 0x4e, 0x4d, 0xcc, 0x11, 0x12, 0xe2, 0x62, 0xc9, 0x48, 0x2c, 0xce,
	0x90, 0x60, 0x54, 0x60, 0xd4, 0xe0, 0x09, 0x02, 0xb3, 0x85, 0x64, 0xb8, 0x38, 0x8b, 0x33, 0xd3,
	0xf3, 0x12, 0x4b, 0x4a, 0x8b, 0x52, 0x25, 0x98, 0xc0, 0x12, 0x08, 0x81, 0x24, 0x36, 0xb0, 0x51,
	0xc6, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0x9b, 0xd4, 0xa5, 0x0c, 0x58, 0x00, 0x00, 0x00,
}

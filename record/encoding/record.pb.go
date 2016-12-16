// Code generated by protoc-gen-go.
// source: record.proto
// DO NOT EDIT!

package encoding

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type Record struct {
	Metadata *Metadata `protobuf:"bytes,1,opt,name=metadata" json:"metadata,omitempty"`
	Data     []byte    `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	Seal     *Seal     `protobuf:"bytes,3,opt,name=seal" json:"seal,omitempty"`
}

func (m *Record) Reset()                    { *m = Record{} }
func (m *Record) String() string            { return proto.CompactTextString(m) }
func (*Record) ProtoMessage()               {}
func (*Record) Descriptor() ([]byte, []int) { return fileDescriptor1, []int{0} }

func (m *Record) GetMetadata() *Metadata {
	if m != nil {
		return m.Metadata
	}
	return nil
}

func (m *Record) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *Record) GetSeal() *Seal {
	if m != nil {
		return m.Seal
	}
	return nil
}

func init() {
	proto.RegisterType((*Record)(nil), "encoding.Record")
}

func init() { proto.RegisterFile("record.proto", fileDescriptor1) }

var fileDescriptor1 = []byte{
	// 138 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xe2, 0xe2, 0x29, 0x4a, 0x4d, 0xce,
	0x2f, 0x4a, 0xd1, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x48, 0xcd, 0x4b, 0xce, 0x4f, 0xc9,
	0xcc, 0x4b, 0x97, 0xe2, 0xcb, 0x4d, 0x2d, 0x49, 0x4c, 0x49, 0x2c, 0x49, 0x84, 0xc8, 0x48, 0x71,
	0x15, 0xa7, 0x26, 0xe6, 0x40, 0xd8, 0x4a, 0x05, 0x5c, 0x6c, 0x41, 0x60, 0x5d, 0x42, 0x7a, 0x5c,
	0x1c, 0x30, 0x75, 0x12, 0x8c, 0x0a, 0x8c, 0x1a, 0xdc, 0x46, 0x42, 0x7a, 0x30, 0x23, 0xf4, 0x7c,
	0xa1, 0x32, 0x41, 0x70, 0x35, 0x42, 0x42, 0x5c, 0x2c, 0x60, 0xb5, 0x4c, 0x0a, 0x8c, 0x1a, 0x3c,
	0x41, 0x60, 0xb6, 0x90, 0x12, 0x17, 0x0b, 0xc8, 0x6c, 0x09, 0x66, 0xb0, 0x7e, 0x3e, 0x84, 0xfe,
	0xe0, 0xd4, 0xc4, 0x9c, 0x20, 0xb0, 0x5c, 0x12, 0x1b, 0xd8, 0x62, 0x63, 0x40, 0x00, 0x00, 0x00,
	0xff, 0xff, 0x1c, 0xe6, 0x43, 0x03, 0xae, 0x00, 0x00, 0x00,
}

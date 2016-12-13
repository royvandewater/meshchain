// Code generated by protoc-gen-go.
// source: metadata.proto
// DO NOT EDIT!

/*
Package encoding is a generated protocol buffer package.

It is generated from these files:
	metadata.proto
	record.proto

It has these top-level messages:
	Metadata
	Record
*/
package encoding

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Metadata struct {
	ID         string   `protobuf:"bytes,1,opt,name=ID" json:"ID,omitempty"`
	LocalID    string   `protobuf:"bytes,2,opt,name=LocalID" json:"LocalID,omitempty"`
	PublicKeys [][]byte `protobuf:"bytes,3,rep,name=PublicKeys,proto3" json:"PublicKeys,omitempty"`
}

func (m *Metadata) Reset()                    { *m = Metadata{} }
func (m *Metadata) String() string            { return proto.CompactTextString(m) }
func (*Metadata) ProtoMessage()               {}
func (*Metadata) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Metadata) GetID() string {
	if m != nil {
		return m.ID
	}
	return ""
}

func (m *Metadata) GetLocalID() string {
	if m != nil {
		return m.LocalID
	}
	return ""
}

func (m *Metadata) GetPublicKeys() [][]byte {
	if m != nil {
		return m.PublicKeys
	}
	return nil
}

func init() {
	proto.RegisterType((*Metadata)(nil), "encoding.Metadata")
}

func init() { proto.RegisterFile("metadata.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 118 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xe2, 0xe2, 0xcb, 0x4d, 0x2d, 0x49,
	0x4c, 0x49, 0x2c, 0x49, 0xd4, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x48, 0xcd, 0x4b, 0xce,
	0x4f, 0xc9, 0xcc, 0x4b, 0x57, 0x0a, 0xe1, 0xe2, 0xf0, 0x85, 0xca, 0x09, 0xf1, 0x71, 0x31, 0x79,
	0xba, 0x48, 0x30, 0x2a, 0x30, 0x6a, 0x70, 0x06, 0x31, 0x79, 0xba, 0x08, 0x49, 0x70, 0xb1, 0xfb,
	0xe4, 0x27, 0x27, 0xe6, 0x78, 0xba, 0x48, 0x30, 0x81, 0x05, 0x61, 0x5c, 0x21, 0x39, 0x2e, 0xae,
	0x80, 0xd2, 0xa4, 0x9c, 0xcc, 0x64, 0xef, 0xd4, 0xca, 0x62, 0x09, 0x66, 0x05, 0x66, 0x0d, 0x9e,
	0x20, 0x24, 0x91, 0x24, 0x36, 0xb0, 0x35, 0xc6, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0x5d, 0x2a,
	0x00, 0x2d, 0x78, 0x00, 0x00, 0x00,
}

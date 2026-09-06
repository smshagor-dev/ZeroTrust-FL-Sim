package protocompat

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestCheckAllowsAdditiveChanges(t *testing.T) {
	baseline := testDescriptorSet()
	current := proto.Clone(baseline).(*descriptorpb.FileDescriptorSet)
	file := current.File[0]

	file.MessageType[0].Field = append(file.MessageType[0].Field, &descriptorpb.FieldDescriptorProto{
		Name:   proto.String("display_name"),
		Number: proto.Int32(2),
		Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
		Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
	})
	file.MessageType = append(file.MessageType, &descriptorpb.DescriptorProto{Name: proto.String("AddedMessage")})
	file.EnumType[0].Value = append(file.EnumType[0].Value, &descriptorpb.EnumValueDescriptorProto{
		Name:   proto.String("MODE_ACTIVE"),
		Number: proto.Int32(1),
	})
	file.Service[0].Method = append(file.Service[0].Method, &descriptorpb.MethodDescriptorProto{
		Name:       proto.String("Describe"),
		InputType:  proto.String(".zerotrust.fl.v1.Sample"),
		OutputType: proto.String(".zerotrust.fl.v1.Sample"),
	})

	if err := Check(baseline, current); err != nil {
		t.Fatalf("additive protobuf changes must remain compatible: %v", err)
	}
}

func TestCheckRejectsBreakingChanges(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*descriptorpb.FileDescriptorSet)
		want   string
	}{
		{
			name: "package change",
			mutate: func(current *descriptorpb.FileDescriptorSet) {
				current.File[0].Package = proto.String("zerotrust.fl.v2")
			},
			want: "changed package",
		},
		{
			name: "message removal",
			mutate: func(current *descriptorpb.FileDescriptorSet) {
				current.File[0].MessageType = nil
			},
			want: "message .zerotrust.fl.v1.Sample was removed or renamed",
		},
		{
			name: "field removal",
			mutate: func(current *descriptorpb.FileDescriptorSet) {
				current.File[0].MessageType[0].Field = nil
			},
			want: "removed or renumbered field 1 (id)",
		},
		{
			name: "field rename",
			mutate: func(current *descriptorpb.FileDescriptorSet) {
				current.File[0].MessageType[0].Field[0].Name = proto.String("identifier")
			},
			want: "changed name from \"id\" to \"identifier\"",
		},
		{
			name: "field renumber",
			mutate: func(current *descriptorpb.FileDescriptorSet) {
				current.File[0].MessageType[0].Field[0].Number = proto.Int32(9)
			},
			want: "removed or renumbered field 1 (id)",
		},
		{
			name: "field type change",
			mutate: func(current *descriptorpb.FileDescriptorSet) {
				current.File[0].MessageType[0].Field[0].Type = descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum()
			},
			want: "changed type",
		},
		{
			name: "field cardinality change",
			mutate: func(current *descriptorpb.FileDescriptorSet) {
				current.File[0].MessageType[0].Field[0].Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
			},
			want: "changed cardinality",
		},
		{
			name: "enum value removal",
			mutate: func(current *descriptorpb.FileDescriptorSet) {
				current.File[0].EnumType[0].Value = nil
			},
			want: "removed or renamed value MODE_UNSPECIFIED=0",
		},
		{
			name: "enum value renumber",
			mutate: func(current *descriptorpb.FileDescriptorSet) {
				current.File[0].EnumType[0].Value[0].Number = proto.Int32(7)
			},
			want: "changed number from 0 to 7",
		},
		{
			name: "rpc removal",
			mutate: func(current *descriptorpb.FileDescriptorSet) {
				current.File[0].Service[0].Method = nil
			},
			want: "removed or renamed RPC Ping",
		},
		{
			name: "rpc signature change",
			mutate: func(current *descriptorpb.FileDescriptorSet) {
				current.File[0].Service[0].Method[0].OutputType = proto.String(".zerotrust.fl.v1.Other")
			},
			want: "changed request or response type",
		},
		{
			name: "rpc streaming change",
			mutate: func(current *descriptorpb.FileDescriptorSet) {
				current.File[0].Service[0].Method[0].ServerStreaming = proto.Bool(true)
			},
			want: "changed streaming mode",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseline := testDescriptorSet()
			current := proto.Clone(baseline).(*descriptorpb.FileDescriptorSet)
			test.mutate(current)

			err := Check(baseline, current)
			if err == nil {
				t.Fatal("expected compatibility failure")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %q", test.want, err)
			}
		})
	}
}

func testDescriptorSet() *descriptorpb.FileDescriptorSet {
	return &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name:    proto.String("fl_service.proto"),
		Package: proto.String("zerotrust.fl.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Sample"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name:   proto.String("id"),
				Number: proto.Int32(1),
				Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			}},
		}},
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name: proto.String("Mode"),
			Value: []*descriptorpb.EnumValueDescriptorProto{{
				Name:   proto.String("MODE_UNSPECIFIED"),
				Number: proto.Int32(0),
			}},
		}},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("TestService"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       proto.String("Ping"),
				InputType:  proto.String(".zerotrust.fl.v1.Sample"),
				OutputType: proto.String(".zerotrust.fl.v1.Sample"),
			}},
		}},
	}}}
}

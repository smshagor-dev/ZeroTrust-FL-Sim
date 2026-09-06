package protocompat

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

// LoadDescriptorSet decodes a protoc FileDescriptorSet from disk.
func LoadDescriptorSet(path string) (*descriptorpb.FileDescriptorSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read protobuf descriptor set %q: %w", path, err)
	}
	set := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(data, set); err != nil {
		return nil, fmt.Errorf("decode protobuf descriptor set %q: %w", path, err)
	}
	if len(set.GetFile()) == 0 {
		return nil, fmt.Errorf("protobuf descriptor set %q contains no files", path)
	}
	return set, nil
}

// CheckFiles loads and compares two descriptor sets. The baseline is the
// already-published contract; the current set is the proposed replacement.
func CheckFiles(baselinePath, currentPath string) error {
	baseline, err := LoadDescriptorSet(baselinePath)
	if err != nil {
		return err
	}
	current, err := LoadDescriptorSet(currentPath)
	if err != nil {
		return err
	}
	return Check(baseline, current)
}

// Check enforces the append-only zerotrust.fl.v1 compatibility policy.
func Check(baseline, current *descriptorpb.FileDescriptorSet) error {
	if baseline == nil || current == nil {
		return fmt.Errorf("baseline and current protobuf descriptor sets are required")
	}

	baselineFiles, err := indexFiles(baseline)
	if err != nil {
		return fmt.Errorf("index baseline protobuf descriptors: %w", err)
	}
	currentFiles, err := indexFiles(current)
	if err != nil {
		return fmt.Errorf("index current protobuf descriptors: %w", err)
	}

	var problems []string
	for _, fileName := range sortedKeys(baselineFiles) {
		baselineFile := baselineFiles[fileName]
		currentFile, ok := currentFiles[fileName]
		if !ok {
			problems = append(problems, fmt.Sprintf("file %s was removed or renamed", fileName))
			continue
		}
		if baselineFile.GetPackage() != currentFile.GetPackage() {
			problems = append(problems, fmt.Sprintf("file %s changed package from %q to %q", fileName, baselineFile.GetPackage(), currentFile.GetPackage()))
		}
		if baselineFile.GetSyntax() != currentFile.GetSyntax() {
			problems = append(problems, fmt.Sprintf("file %s changed syntax from %q to %q", fileName, baselineFile.GetSyntax(), currentFile.GetSyntax()))
		}
		problems = append(problems, compareFileSymbols(baselineFile, currentFile)...)
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("protobuf compatibility check failed:\n- %s", strings.Join(problems, "\n- "))
}

func indexFiles(set *descriptorpb.FileDescriptorSet) (map[string]*descriptorpb.FileDescriptorProto, error) {
	files := make(map[string]*descriptorpb.FileDescriptorProto, len(set.GetFile()))
	for _, file := range set.GetFile() {
		if file == nil || strings.TrimSpace(file.GetName()) == "" {
			return nil, fmt.Errorf("descriptor set contains a file without a name")
		}
		if _, exists := files[file.GetName()]; exists {
			return nil, fmt.Errorf("descriptor set contains duplicate file %q", file.GetName())
		}
		files[file.GetName()] = file
	}
	return files, nil
}

type symbolIndex struct {
	messages map[string]*descriptorpb.DescriptorProto
	enums    map[string]*descriptorpb.EnumDescriptorProto
	services map[string]*descriptorpb.ServiceDescriptorProto
}

func compareFileSymbols(baseline, current *descriptorpb.FileDescriptorProto) []string {
	baselineSymbols := buildSymbolIndex(baseline)
	currentSymbols := buildSymbolIndex(current)

	var problems []string
	for _, name := range sortedKeys(baselineSymbols.messages) {
		baselineMessage := baselineSymbols.messages[name]
		currentMessage, ok := currentSymbols.messages[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("message %s was removed or renamed", name))
			continue
		}
		problems = append(problems, compareMessage(name, baselineMessage, currentMessage)...)
	}
	for _, name := range sortedKeys(baselineSymbols.enums) {
		baselineEnum := baselineSymbols.enums[name]
		currentEnum, ok := currentSymbols.enums[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("enum %s was removed or renamed", name))
			continue
		}
		problems = append(problems, compareEnum(name, baselineEnum, currentEnum)...)
	}
	for _, name := range sortedKeys(baselineSymbols.services) {
		baselineService := baselineSymbols.services[name]
		currentService, ok := currentSymbols.services[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("service %s was removed or renamed", name))
			continue
		}
		problems = append(problems, compareService(name, baselineService, currentService)...)
	}
	return problems
}

func buildSymbolIndex(file *descriptorpb.FileDescriptorProto) symbolIndex {
	index := symbolIndex{
		messages: make(map[string]*descriptorpb.DescriptorProto),
		enums:    make(map[string]*descriptorpb.EnumDescriptorProto),
		services: make(map[string]*descriptorpb.ServiceDescriptorProto),
	}
	prefix := packagePrefix(file.GetPackage())
	for _, message := range file.GetMessageType() {
		indexMessage(index, prefix, message)
	}
	for _, enum := range file.GetEnumType() {
		index.enums[qualified(prefix, enum.GetName())] = enum
	}
	for _, service := range file.GetService() {
		index.services[qualified(prefix, service.GetName())] = service
	}
	return index
}

func indexMessage(index symbolIndex, prefix string, message *descriptorpb.DescriptorProto) {
	name := qualified(prefix, message.GetName())
	index.messages[name] = message
	for _, nested := range message.GetNestedType() {
		indexMessage(index, name, nested)
	}
	for _, enum := range message.GetEnumType() {
		index.enums[qualified(name, enum.GetName())] = enum
	}
}

func compareMessage(name string, baseline, current *descriptorpb.DescriptorProto) []string {
	var problems []string
	if baseline.GetOptions().GetMapEntry() != current.GetOptions().GetMapEntry() {
		problems = append(problems, fmt.Sprintf("message %s changed map-entry semantics", name))
	}

	currentOneofs := make(map[string]struct{}, len(current.GetOneofDecl()))
	for _, oneof := range current.GetOneofDecl() {
		currentOneofs[oneof.GetName()] = struct{}{}
	}
	for _, oneof := range baseline.GetOneofDecl() {
		if _, ok := currentOneofs[oneof.GetName()]; !ok {
			problems = append(problems, fmt.Sprintf("message %s removed or renamed oneof %q", name, oneof.GetName()))
		}
	}

	currentFields := make(map[int32]*descriptorpb.FieldDescriptorProto, len(current.GetField()))
	for _, field := range current.GetField() {
		currentFields[field.GetNumber()] = field
	}
	for _, field := range baseline.GetField() {
		currentField, ok := currentFields[field.GetNumber()]
		if !ok {
			problems = append(problems, fmt.Sprintf("message %s removed or renumbered field %d (%s)", name, field.GetNumber(), field.GetName()))
			continue
		}
		fieldName := fmt.Sprintf("message %s field %d", name, field.GetNumber())
		if field.GetName() != currentField.GetName() {
			problems = append(problems, fmt.Sprintf("%s changed name from %q to %q", fieldName, field.GetName(), currentField.GetName()))
		}
		if field.GetType() != currentField.GetType() || field.GetTypeName() != currentField.GetTypeName() {
			problems = append(problems, fmt.Sprintf("%s (%s) changed type", fieldName, field.GetName()))
		}
		if field.GetLabel() != currentField.GetLabel() {
			problems = append(problems, fmt.Sprintf("%s (%s) changed cardinality", fieldName, field.GetName()))
		}
		baselineOneof := fieldOneofName(baseline, field)
		currentOneof := fieldOneofName(current, currentField)
		if baselineOneof != currentOneof {
			problems = append(problems, fmt.Sprintf("%s (%s) changed oneof membership from %q to %q", fieldName, field.GetName(), baselineOneof, currentOneof))
		}
		if field.GetProto3Optional() != currentField.GetProto3Optional() {
			problems = append(problems, fmt.Sprintf("%s (%s) changed proto3 optional presence", fieldName, field.GetName()))
		}
	}
	return problems
}

func compareEnum(name string, baseline, current *descriptorpb.EnumDescriptorProto) []string {
	currentValues := make(map[string]*descriptorpb.EnumValueDescriptorProto, len(current.GetValue()))
	for _, value := range current.GetValue() {
		currentValues[value.GetName()] = value
	}

	var problems []string
	for _, value := range baseline.GetValue() {
		currentValue, ok := currentValues[value.GetName()]
		if !ok {
			problems = append(problems, fmt.Sprintf("enum %s removed or renamed value %s=%d", name, value.GetName(), value.GetNumber()))
			continue
		}
		if value.GetNumber() != currentValue.GetNumber() {
			problems = append(problems, fmt.Sprintf("enum %s value %s changed number from %d to %d", name, value.GetName(), value.GetNumber(), currentValue.GetNumber()))
		}
	}
	return problems
}

func compareService(name string, baseline, current *descriptorpb.ServiceDescriptorProto) []string {
	currentMethods := make(map[string]*descriptorpb.MethodDescriptorProto, len(current.GetMethod()))
	for _, method := range current.GetMethod() {
		currentMethods[method.GetName()] = method
	}

	var problems []string
	for _, method := range baseline.GetMethod() {
		currentMethod, ok := currentMethods[method.GetName()]
		if !ok {
			problems = append(problems, fmt.Sprintf("service %s removed or renamed RPC %s", name, method.GetName()))
			continue
		}
		methodName := fmt.Sprintf("service %s RPC %s", name, method.GetName())
		if method.GetInputType() != currentMethod.GetInputType() || method.GetOutputType() != currentMethod.GetOutputType() {
			problems = append(problems, fmt.Sprintf("%s changed request or response type", methodName))
		}
		if method.GetClientStreaming() != currentMethod.GetClientStreaming() || method.GetServerStreaming() != currentMethod.GetServerStreaming() {
			problems = append(problems, fmt.Sprintf("%s changed streaming mode", methodName))
		}
	}
	return problems
}

func fieldOneofName(message *descriptorpb.DescriptorProto, field *descriptorpb.FieldDescriptorProto) string {
	if field.OneofIndex == nil {
		return ""
	}
	index := int(field.GetOneofIndex())
	if index < 0 || index >= len(message.GetOneofDecl()) {
		return "<invalid>"
	}
	return message.GetOneofDecl()[index].GetName()
}

func packagePrefix(pkg string) string {
	if pkg == "" {
		return ""
	}
	return "." + pkg
}

func qualified(prefix, name string) string {
	if prefix == "" {
		return "." + name
	}
	return prefix + "." + name
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

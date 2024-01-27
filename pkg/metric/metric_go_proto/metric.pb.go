// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.21.7
// source: pkg/metric/metric.proto

package metric_go_proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type MetricMetadata_Type int32

const (
	MetricMetadata_TYPE_UINT64       MetricMetadata_Type = 0
	MetricMetadata_TYPE_DISTRIBUTION MetricMetadata_Type = 1
)

// Enum value maps for MetricMetadata_Type.
var (
	MetricMetadata_Type_name = map[int32]string{
		0: "TYPE_UINT64",
		1: "TYPE_DISTRIBUTION",
	}
	MetricMetadata_Type_value = map[string]int32{
		"TYPE_UINT64":       0,
		"TYPE_DISTRIBUTION": 1,
	}
)

func (x MetricMetadata_Type) Enum() *MetricMetadata_Type {
	p := new(MetricMetadata_Type)
	*p = x
	return p
}

func (x MetricMetadata_Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MetricMetadata_Type) Descriptor() protoreflect.EnumDescriptor {
	return file_pkg_metric_metric_proto_enumTypes[0].Descriptor()
}

func (MetricMetadata_Type) Type() protoreflect.EnumType {
	return &file_pkg_metric_metric_proto_enumTypes[0]
}

func (x MetricMetadata_Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MetricMetadata_Type.Descriptor instead.
func (MetricMetadata_Type) EnumDescriptor() ([]byte, []int) {
	return file_pkg_metric_metric_proto_rawDescGZIP(), []int{0, 0}
}

type MetricMetadata_Units int32

const (
	MetricMetadata_UNITS_NONE        MetricMetadata_Units = 0
	MetricMetadata_UNITS_NANOSECONDS MetricMetadata_Units = 1
)

// Enum value maps for MetricMetadata_Units.
var (
	MetricMetadata_Units_name = map[int32]string{
		0: "UNITS_NONE",
		1: "UNITS_NANOSECONDS",
	}
	MetricMetadata_Units_value = map[string]int32{
		"UNITS_NONE":        0,
		"UNITS_NANOSECONDS": 1,
	}
)

func (x MetricMetadata_Units) Enum() *MetricMetadata_Units {
	p := new(MetricMetadata_Units)
	*p = x
	return p
}

func (x MetricMetadata_Units) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MetricMetadata_Units) Descriptor() protoreflect.EnumDescriptor {
	return file_pkg_metric_metric_proto_enumTypes[1].Descriptor()
}

func (MetricMetadata_Units) Type() protoreflect.EnumType {
	return &file_pkg_metric_metric_proto_enumTypes[1]
}

func (x MetricMetadata_Units) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MetricMetadata_Units.Descriptor instead.
func (MetricMetadata_Units) EnumDescriptor() ([]byte, []int) {
	return file_pkg_metric_metric_proto_rawDescGZIP(), []int{0, 1}
}

type MetricMetadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name                          string                  `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	PrometheusName                string                  `protobuf:"bytes,9,opt,name=prometheus_name,json=prometheusName,proto3" json:"prometheus_name,omitempty"`
	Description                   string                  `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	Cumulative                    bool                    `protobuf:"varint,3,opt,name=cumulative,proto3" json:"cumulative,omitempty"`
	Sync                          bool                    `protobuf:"varint,4,opt,name=sync,proto3" json:"sync,omitempty"`
	Type                          MetricMetadata_Type     `protobuf:"varint,5,opt,name=type,proto3,enum=gvisor.MetricMetadata_Type" json:"type,omitempty"`
	Units                         MetricMetadata_Units    `protobuf:"varint,6,opt,name=units,proto3,enum=gvisor.MetricMetadata_Units" json:"units,omitempty"`
	Fields                        []*MetricMetadata_Field `protobuf:"bytes,7,rep,name=fields,proto3" json:"fields,omitempty"`
	DistributionBucketLowerBounds []int64                 `protobuf:"varint,8,rep,packed,name=distribution_bucket_lower_bounds,json=distributionBucketLowerBounds,proto3" json:"distribution_bucket_lower_bounds,omitempty"`
}

func (x *MetricMetadata) Reset() {
	*x = MetricMetadata{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_metric_metric_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MetricMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MetricMetadata) ProtoMessage() {}

func (x *MetricMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_metric_metric_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MetricMetadata.ProtoReflect.Descriptor instead.
func (*MetricMetadata) Descriptor() ([]byte, []int) {
	return file_pkg_metric_metric_proto_rawDescGZIP(), []int{0}
}

func (x *MetricMetadata) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *MetricMetadata) GetPrometheusName() string {
	if x != nil {
		return x.PrometheusName
	}
	return ""
}

func (x *MetricMetadata) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *MetricMetadata) GetCumulative() bool {
	if x != nil {
		return x.Cumulative
	}
	return false
}

func (x *MetricMetadata) GetSync() bool {
	if x != nil {
		return x.Sync
	}
	return false
}

func (x *MetricMetadata) GetType() MetricMetadata_Type {
	if x != nil {
		return x.Type
	}
	return MetricMetadata_TYPE_UINT64
}

func (x *MetricMetadata) GetUnits() MetricMetadata_Units {
	if x != nil {
		return x.Units
	}
	return MetricMetadata_UNITS_NONE
}

func (x *MetricMetadata) GetFields() []*MetricMetadata_Field {
	if x != nil {
		return x.Fields
	}
	return nil
}

func (x *MetricMetadata) GetDistributionBucketLowerBounds() []int64 {
	if x != nil {
		return x.DistributionBucketLowerBounds
	}
	return nil
}

type MetricRegistration struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Metrics []*MetricMetadata `protobuf:"bytes,1,rep,name=metrics,proto3" json:"metrics,omitempty"`
	Stages  []string          `protobuf:"bytes,2,rep,name=stages,proto3" json:"stages,omitempty"`
}

func (x *MetricRegistration) Reset() {
	*x = MetricRegistration{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_metric_metric_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MetricRegistration) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MetricRegistration) ProtoMessage() {}

func (x *MetricRegistration) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_metric_metric_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MetricRegistration.ProtoReflect.Descriptor instead.
func (*MetricRegistration) Descriptor() ([]byte, []int) {
	return file_pkg_metric_metric_proto_rawDescGZIP(), []int{1}
}

func (x *MetricRegistration) GetMetrics() []*MetricMetadata {
	if x != nil {
		return x.Metrics
	}
	return nil
}

func (x *MetricRegistration) GetStages() []string {
	if x != nil {
		return x.Stages
	}
	return nil
}

type Samples struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	NewSamples []uint64 `protobuf:"varint,1,rep,packed,name=new_samples,json=newSamples,proto3" json:"new_samples,omitempty"`
}

func (x *Samples) Reset() {
	*x = Samples{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_metric_metric_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Samples) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Samples) ProtoMessage() {}

func (x *Samples) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_metric_metric_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Samples.ProtoReflect.Descriptor instead.
func (*Samples) Descriptor() ([]byte, []int) {
	return file_pkg_metric_metric_proto_rawDescGZIP(), []int{2}
}

func (x *Samples) GetNewSamples() []uint64 {
	if x != nil {
		return x.NewSamples
	}
	return nil
}

type MetricValue struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Types that are assignable to Value:
	//
	//	*MetricValue_Uint64Value
	//	*MetricValue_DistributionValue
	Value       isMetricValue_Value `protobuf_oneof:"value"`
	FieldValues []string            `protobuf:"bytes,4,rep,name=field_values,json=fieldValues,proto3" json:"field_values,omitempty"`
}

func (x *MetricValue) Reset() {
	*x = MetricValue{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_metric_metric_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MetricValue) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MetricValue) ProtoMessage() {}

func (x *MetricValue) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_metric_metric_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MetricValue.ProtoReflect.Descriptor instead.
func (*MetricValue) Descriptor() ([]byte, []int) {
	return file_pkg_metric_metric_proto_rawDescGZIP(), []int{3}
}

func (x *MetricValue) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (m *MetricValue) GetValue() isMetricValue_Value {
	if m != nil {
		return m.Value
	}
	return nil
}

func (x *MetricValue) GetUint64Value() uint64 {
	if x, ok := x.GetValue().(*MetricValue_Uint64Value); ok {
		return x.Uint64Value
	}
	return 0
}

func (x *MetricValue) GetDistributionValue() *Samples {
	if x, ok := x.GetValue().(*MetricValue_DistributionValue); ok {
		return x.DistributionValue
	}
	return nil
}

func (x *MetricValue) GetFieldValues() []string {
	if x != nil {
		return x.FieldValues
	}
	return nil
}

type isMetricValue_Value interface {
	isMetricValue_Value()
}

type MetricValue_Uint64Value struct {
	Uint64Value uint64 `protobuf:"varint,2,opt,name=uint64_value,json=uint64Value,proto3,oneof"`
}

type MetricValue_DistributionValue struct {
	DistributionValue *Samples `protobuf:"bytes,3,opt,name=distribution_value,json=distributionValue,proto3,oneof"`
}

func (*MetricValue_Uint64Value) isMetricValue_Value() {}

func (*MetricValue_DistributionValue) isMetricValue_Value() {}

type StageTiming struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Stage   string                 `protobuf:"bytes,1,opt,name=stage,proto3" json:"stage,omitempty"`
	Started *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=started,proto3" json:"started,omitempty"`
	Ended   *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=ended,proto3" json:"ended,omitempty"`
}

func (x *StageTiming) Reset() {
	*x = StageTiming{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_metric_metric_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StageTiming) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StageTiming) ProtoMessage() {}

func (x *StageTiming) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_metric_metric_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StageTiming.ProtoReflect.Descriptor instead.
func (*StageTiming) Descriptor() ([]byte, []int) {
	return file_pkg_metric_metric_proto_rawDescGZIP(), []int{4}
}

func (x *StageTiming) GetStage() string {
	if x != nil {
		return x.Stage
	}
	return ""
}

func (x *StageTiming) GetStarted() *timestamppb.Timestamp {
	if x != nil {
		return x.Started
	}
	return nil
}

func (x *StageTiming) GetEnded() *timestamppb.Timestamp {
	if x != nil {
		return x.Ended
	}
	return nil
}

type MetricUpdate struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Metrics     []*MetricValue `protobuf:"bytes,1,rep,name=metrics,proto3" json:"metrics,omitempty"`
	StageTiming []*StageTiming `protobuf:"bytes,2,rep,name=stage_timing,json=stageTiming,proto3" json:"stage_timing,omitempty"`
}

func (x *MetricUpdate) Reset() {
	*x = MetricUpdate{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_metric_metric_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MetricUpdate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MetricUpdate) ProtoMessage() {}

func (x *MetricUpdate) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_metric_metric_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MetricUpdate.ProtoReflect.Descriptor instead.
func (*MetricUpdate) Descriptor() ([]byte, []int) {
	return file_pkg_metric_metric_proto_rawDescGZIP(), []int{5}
}

func (x *MetricUpdate) GetMetrics() []*MetricValue {
	if x != nil {
		return x.Metrics
	}
	return nil
}

func (x *MetricUpdate) GetStageTiming() []*StageTiming {
	if x != nil {
		return x.StageTiming
	}
	return nil
}

type MetricMetadata_Field struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	FieldName     string   `protobuf:"bytes,1,opt,name=field_name,json=fieldName,proto3" json:"field_name,omitempty"`
	AllowedValues []string `protobuf:"bytes,2,rep,name=allowed_values,json=allowedValues,proto3" json:"allowed_values,omitempty"`
}

func (x *MetricMetadata_Field) Reset() {
	*x = MetricMetadata_Field{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_metric_metric_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MetricMetadata_Field) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MetricMetadata_Field) ProtoMessage() {}

func (x *MetricMetadata_Field) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_metric_metric_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MetricMetadata_Field.ProtoReflect.Descriptor instead.
func (*MetricMetadata_Field) Descriptor() ([]byte, []int) {
	return file_pkg_metric_metric_proto_rawDescGZIP(), []int{0, 0}
}

func (x *MetricMetadata_Field) GetFieldName() string {
	if x != nil {
		return x.FieldName
	}
	return ""
}

func (x *MetricMetadata_Field) GetAllowedValues() []string {
	if x != nil {
		return x.AllowedValues
	}
	return nil
}

var File_pkg_metric_metric_proto protoreflect.FileDescriptor

var file_pkg_metric_metric_proto_rawDesc = []byte{
	0x0a, 0x17, 0x70, 0x6b, 0x67, 0x2f, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x2f, 0x6d, 0x65, 0x74,
	0x72, 0x69, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x67, 0x76, 0x69, 0x73, 0x6f,
	0x72, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xb6, 0x04, 0x0a, 0x0e, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x4d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x27, 0x0a, 0x0f, 0x70, 0x72, 0x6f,
	0x6d, 0x65, 0x74, 0x68, 0x65, 0x75, 0x73, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x09, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0e, 0x70, 0x72, 0x6f, 0x6d, 0x65, 0x74, 0x68, 0x65, 0x75, 0x73, 0x4e, 0x61,
	0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x75, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x69,
	0x76, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x63, 0x75, 0x6d, 0x75, 0x6c, 0x61,
	0x74, 0x69, 0x76, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x79, 0x6e, 0x63, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x04, 0x73, 0x79, 0x6e, 0x63, 0x12, 0x2f, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1b, 0x2e, 0x67, 0x76, 0x69, 0x73, 0x6f, 0x72, 0x2e,
	0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x54,
	0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x32, 0x0a, 0x05, 0x75, 0x6e, 0x69,
	0x74, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1c, 0x2e, 0x67, 0x76, 0x69, 0x73, 0x6f,
	0x72, 0x2e, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x2e, 0x55, 0x6e, 0x69, 0x74, 0x73, 0x52, 0x05, 0x75, 0x6e, 0x69, 0x74, 0x73, 0x12, 0x34, 0x0a,
	0x06, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e,
	0x67, 0x76, 0x69, 0x73, 0x6f, 0x72, 0x2e, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x4d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x52, 0x06, 0x66, 0x69, 0x65,
	0x6c, 0x64, 0x73, 0x12, 0x47, 0x0a, 0x20, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74,
	0x69, 0x6f, 0x6e, 0x5f, 0x62, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x5f, 0x6c, 0x6f, 0x77, 0x65, 0x72,
	0x5f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x73, 0x18, 0x08, 0x20, 0x03, 0x28, 0x03, 0x52, 0x1d, 0x64,
	0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x75, 0x63, 0x6b, 0x65,
	0x74, 0x4c, 0x6f, 0x77, 0x65, 0x72, 0x42, 0x6f, 0x75, 0x6e, 0x64, 0x73, 0x1a, 0x4d, 0x0a, 0x05,
	0x46, 0x69, 0x65, 0x6c, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x66, 0x69, 0x65, 0x6c, 0x64,
	0x4e, 0x61, 0x6d, 0x65, 0x12, 0x25, 0x0a, 0x0e, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x5f,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0d, 0x61, 0x6c,
	0x6c, 0x6f, 0x77, 0x65, 0x64, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x22, 0x2e, 0x0a, 0x04, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x0f, 0x0a, 0x0b, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x49, 0x4e, 0x54,
	0x36, 0x34, 0x10, 0x00, 0x12, 0x15, 0x0a, 0x11, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x44, 0x49, 0x53,
	0x54, 0x52, 0x49, 0x42, 0x55, 0x54, 0x49, 0x4f, 0x4e, 0x10, 0x01, 0x22, 0x2e, 0x0a, 0x05, 0x55,
	0x6e, 0x69, 0x74, 0x73, 0x12, 0x0e, 0x0a, 0x0a, 0x55, 0x4e, 0x49, 0x54, 0x53, 0x5f, 0x4e, 0x4f,
	0x4e, 0x45, 0x10, 0x00, 0x12, 0x15, 0x0a, 0x11, 0x55, 0x4e, 0x49, 0x54, 0x53, 0x5f, 0x4e, 0x41,
	0x4e, 0x4f, 0x53, 0x45, 0x43, 0x4f, 0x4e, 0x44, 0x53, 0x10, 0x01, 0x22, 0x5e, 0x0a, 0x12, 0x4d,
	0x65, 0x74, 0x72, 0x69, 0x63, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x30, 0x0a, 0x07, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x16, 0x2e, 0x67, 0x76, 0x69, 0x73, 0x6f, 0x72, 0x2e, 0x4d, 0x65, 0x74, 0x72,
	0x69, 0x63, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x07, 0x6d, 0x65, 0x74, 0x72,
	0x69, 0x63, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x67, 0x65, 0x73, 0x18, 0x02, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x06, 0x73, 0x74, 0x61, 0x67, 0x65, 0x73, 0x22, 0x2a, 0x0a, 0x07, 0x53,
	0x61, 0x6d, 0x70, 0x6c, 0x65, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x6e, 0x65, 0x77, 0x5f, 0x73, 0x61,
	0x6d, 0x70, 0x6c, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x04, 0x52, 0x0a, 0x6e, 0x65, 0x77,
	0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x73, 0x22, 0xb4, 0x01, 0x0a, 0x0b, 0x4d, 0x65, 0x74, 0x72,
	0x69, 0x63, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x23, 0x0a, 0x0c, 0x75,
	0x69, 0x6e, 0x74, 0x36, 0x34, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x04, 0x48, 0x00, 0x52, 0x0b, 0x75, 0x69, 0x6e, 0x74, 0x36, 0x34, 0x56, 0x61, 0x6c, 0x75, 0x65,
	0x12, 0x40, 0x0a, 0x12, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e,
	0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x67,
	0x76, 0x69, 0x73, 0x6f, 0x72, 0x2e, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x73, 0x48, 0x00, 0x52,
	0x11, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x56,
	0x61, 0x6c, 0x75, 0x65, 0x73, 0x42, 0x07, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x8b,
	0x01, 0x0a, 0x0b, 0x53, 0x74, 0x61, 0x67, 0x65, 0x54, 0x69, 0x6d, 0x69, 0x6e, 0x67, 0x12, 0x14,
	0x0a, 0x05, 0x73, 0x74, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x73,
	0x74, 0x61, 0x67, 0x65, 0x12, 0x34, 0x0a, 0x07, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x07, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x12, 0x30, 0x0a, 0x05, 0x65, 0x6e,
	0x64, 0x65, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x05, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x22, 0x75, 0x0a, 0x0c,
	0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x12, 0x2d, 0x0a, 0x07,
	0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e,
	0x67, 0x76, 0x69, 0x73, 0x6f, 0x72, 0x2e, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x52, 0x07, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x12, 0x36, 0x0a, 0x0c, 0x73,
	0x74, 0x61, 0x67, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x69, 0x6e, 0x67, 0x18, 0x02, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x13, 0x2e, 0x67, 0x76, 0x69, 0x73, 0x6f, 0x72, 0x2e, 0x53, 0x74, 0x61, 0x67, 0x65,
	0x54, 0x69, 0x6d, 0x69, 0x6e, 0x67, 0x52, 0x0b, 0x73, 0x74, 0x61, 0x67, 0x65, 0x54, 0x69, 0x6d,
	0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pkg_metric_metric_proto_rawDescOnce sync.Once
	file_pkg_metric_metric_proto_rawDescData = file_pkg_metric_metric_proto_rawDesc
)

func file_pkg_metric_metric_proto_rawDescGZIP() []byte {
	file_pkg_metric_metric_proto_rawDescOnce.Do(func() {
		file_pkg_metric_metric_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_metric_metric_proto_rawDescData)
	})
	return file_pkg_metric_metric_proto_rawDescData
}

var file_pkg_metric_metric_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_pkg_metric_metric_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_pkg_metric_metric_proto_goTypes = []interface{}{
	(MetricMetadata_Type)(0),      // 0: gvisor.MetricMetadata.Type
	(MetricMetadata_Units)(0),     // 1: gvisor.MetricMetadata.Units
	(*MetricMetadata)(nil),        // 2: gvisor.MetricMetadata
	(*MetricRegistration)(nil),    // 3: gvisor.MetricRegistration
	(*Samples)(nil),               // 4: gvisor.Samples
	(*MetricValue)(nil),           // 5: gvisor.MetricValue
	(*StageTiming)(nil),           // 6: gvisor.StageTiming
	(*MetricUpdate)(nil),          // 7: gvisor.MetricUpdate
	(*MetricMetadata_Field)(nil),  // 8: gvisor.MetricMetadata.Field
	(*timestamppb.Timestamp)(nil), // 9: google.protobuf.Timestamp
}
var file_pkg_metric_metric_proto_depIdxs = []int32{
	0, // 0: gvisor.MetricMetadata.type:type_name -> gvisor.MetricMetadata.Type
	1, // 1: gvisor.MetricMetadata.units:type_name -> gvisor.MetricMetadata.Units
	8, // 2: gvisor.MetricMetadata.fields:type_name -> gvisor.MetricMetadata.Field
	2, // 3: gvisor.MetricRegistration.metrics:type_name -> gvisor.MetricMetadata
	4, // 4: gvisor.MetricValue.distribution_value:type_name -> gvisor.Samples
	9, // 5: gvisor.StageTiming.started:type_name -> google.protobuf.Timestamp
	9, // 6: gvisor.StageTiming.ended:type_name -> google.protobuf.Timestamp
	5, // 7: gvisor.MetricUpdate.metrics:type_name -> gvisor.MetricValue
	6, // 8: gvisor.MetricUpdate.stage_timing:type_name -> gvisor.StageTiming
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	9, // [9:9] is the sub-list for extension type_name
	9, // [9:9] is the sub-list for extension extendee
	0, // [0:9] is the sub-list for field type_name
}

func init() { file_pkg_metric_metric_proto_init() }
func file_pkg_metric_metric_proto_init() {
	if File_pkg_metric_metric_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_metric_metric_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MetricMetadata); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_metric_metric_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MetricRegistration); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_metric_metric_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Samples); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_metric_metric_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MetricValue); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_metric_metric_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StageTiming); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_metric_metric_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MetricUpdate); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_metric_metric_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MetricMetadata_Field); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_pkg_metric_metric_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*MetricValue_Uint64Value)(nil),
		(*MetricValue_DistributionValue)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pkg_metric_metric_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pkg_metric_metric_proto_goTypes,
		DependencyIndexes: file_pkg_metric_metric_proto_depIdxs,
		EnumInfos:         file_pkg_metric_metric_proto_enumTypes,
		MessageInfos:      file_pkg_metric_metric_proto_msgTypes,
	}.Build()
	File_pkg_metric_metric_proto = out.File
	file_pkg_metric_metric_proto_rawDesc = nil
	file_pkg_metric_metric_proto_goTypes = nil
	file_pkg_metric_metric_proto_depIdxs = nil
}

/*
©AngelaMos | 2026
codec.go

JSON codec for the sensor gRPC service

Registered under the name "json" so calls use the content-subtype
application/grpc+json. Avoids a protoc build step; see
proto/sensor.proto for the equivalent protobuf contract.
*/

package sensorrpc

import (
	"encoding/json"

	"google.golang.org/grpc/encoding"
)

const CodecName = "json"

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (jsonCodec) Name() string { return CodecName }

func init() {
	encoding.RegisterCodec(jsonCodec{})
}
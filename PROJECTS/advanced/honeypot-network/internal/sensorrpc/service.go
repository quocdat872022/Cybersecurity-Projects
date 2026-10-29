/*
©AngelaMos | 2026
service.go

Hand-written gRPC service descriptor and client stubs

Equivalent to protoc-generated code for proto/sensor.proto, using
the JSON codec so no code generation is needed.
*/

package sensorrpc

import (
	"context"

	"google.golang.org/grpc"
)

const ServiceName = "hive.sensor.v1.SensorHub"

type EventStream interface {
	Recv() (*Envelope, error)
	Send(*Ack) error
	grpc.ServerStream
}

type HubServer interface {
	Register(context.Context, *RegisterRequest) (*RegisterResponse, error)
	Heartbeat(context.Context, *HeartbeatRequest) (*HeartbeatResponse, error)
	StreamEvents(EventStream) error
}

type serverStream struct{ grpc.ServerStream }

func (s *serverStream) Recv() (*Envelope, error) {
	env := new(Envelope)
	if err := s.ServerStream.RecvMsg(env); err != nil {
		return nil, err
	}
	return env, nil
}

func (s *serverStream) Send(a *Ack) error {
	return s.ServerStream.SendMsg(a)
}

func registerHandler(
	srv any, ctx context.Context,
	dec func(any) error, interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	in := new(RegisterRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HubServer).Register(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/" + ServiceName + "/Register",
	}
	return interceptor(ctx, in, info,
		func(ctx context.Context, req any) (any, error) {
			return srv.(HubServer).Register(
				ctx, req.(*RegisterRequest),
			)
		})
}

func heartbeatHandler(
	srv any, ctx context.Context,
	dec func(any) error, interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	in := new(HeartbeatRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HubServer).Heartbeat(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/" + ServiceName + "/Heartbeat",
	}
	return interceptor(ctx, in, info,
		func(ctx context.Context, req any) (any, error) {
			return srv.(HubServer).Heartbeat(
				ctx, req.(*HeartbeatRequest),
			)
		})
}

func streamHandler(srv any, stream grpc.ServerStream) error {
	return srv.(HubServer).StreamEvents(&serverStream{stream})
}

var hubServiceDesc = grpc.ServiceDesc{
	ServiceName: ServiceName,
	HandlerType: (*HubServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Register", Handler: registerHandler},
		{MethodName: "Heartbeat", Handler: heartbeatHandler},
	},
	Streams: []grpc.StreamDesc{{
		StreamName:    "StreamEvents",
		Handler:       streamHandler,
		ServerStreams: true,
		ClientStreams: true,
	}},
	Metadata: "proto/sensor.proto",
}

func RegisterHubServer(s grpc.ServiceRegistrar, srv HubServer) {
	s.RegisterService(&hubServiceDesc, srv)
}

// ---- client ----

type Client struct{ cc grpc.ClientConnInterface }

func NewClient(cc grpc.ClientConnInterface) *Client {
	return &Client{cc: cc}
}

func (c *Client) Register(
	ctx context.Context, in *RegisterRequest,
) (*RegisterResponse, error) {
	out := new(RegisterResponse)
	err := c.cc.Invoke(
		ctx, "/"+ServiceName+"/Register", in, out,
		grpc.CallContentSubtype(CodecName),
	)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) Heartbeat(
	ctx context.Context, in *HeartbeatRequest,
) (*HeartbeatResponse, error) {
	out := new(HeartbeatResponse)
	err := c.cc.Invoke(
		ctx, "/"+ServiceName+"/Heartbeat", in, out,
		grpc.CallContentSubtype(CodecName),
	)
	if err != nil {
		return nil, err
	}
	return out, nil
}

type ClientStream struct{ grpc.ClientStream }

func (s *ClientStream) Send(e *Envelope) error {
	return s.ClientStream.SendMsg(e)
}

func (s *ClientStream) Recv() (*Ack, error) {
	a := new(Ack)
	if err := s.ClientStream.RecvMsg(a); err != nil {
		return nil, err
	}
	return a, nil
}

func (c *Client) StreamEvents(
	ctx context.Context,
) (*ClientStream, error) {
	desc := &grpc.StreamDesc{
		StreamName:    "StreamEvents",
		ServerStreams: true,
		ClientStreams: true,
	}
	s, err := c.cc.NewStream(
		ctx, desc, "/"+ServiceName+"/StreamEvents",
		grpc.CallContentSubtype(CodecName),
	)
	if err != nil {
		return nil, err
	}
	return &ClientStream{s}, nil
}
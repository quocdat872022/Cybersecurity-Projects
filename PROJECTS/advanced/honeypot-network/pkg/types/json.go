/*
©AngelaMos | 2026
json.go

JSON decoding for enum types that marshal as strings

Event and Session values cross process boundaries (sensor to
central hub, Redis stream), so every string-marshaled enum needs a
matching UnmarshalJSON.
*/

package types

import (
	"encoding/json"
	"fmt"
)

func (s *ServiceType) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	v, ok := ParseServiceType(name)
	if !ok {
		return fmt.Errorf("unknown service type %q", name)
	}
	*s = v
	return nil
}

func (e *EventType) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	v, ok := ParseEventType(name)
	if !ok {
		return fmt.Errorf("unknown event type %q", name)
	}
	*e = v
	return nil
}

func (p *Protocol) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	for proto, n := range protocolNames {
		if n == name {
			*p = proto
			return nil
		}
	}
	return fmt.Errorf("unknown protocol %q", name)
}
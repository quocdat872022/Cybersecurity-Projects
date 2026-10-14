// ©AngelaMos | 2026
// config_test.go

package config

import (
	"reflect"
	"testing"
)

func TestEnvCallbackScalarAndAliases(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		value   string
		wantKey string
		wantVal any
	}{
		{
			"mysql fake enabled alias",
			"MYSQL_FAKE_ENABLED",
			"true",
			"mysql.enabled",
			"true",
		},
		{
			"mysql canonical enabled",
			"MYSQL_ENABLED",
			"true",
			"mysql.enabled",
			"true",
		},
		{
			"mysql fake addr alias",
			"MYSQL_FAKE_ADDR",
			"0.0.0.0:33306",
			"mysql.addr",
			"0.0.0.0:33306",
		},
		{
			"turnstile secret alias",
			"TURNSTILE_SECRET",
			"sk",
			"turnstile.secret_key",
			"sk",
		},
		{"unmapped key dropped", "SOME_RANDOM_VAR", "x", "", nil},
		{
			"blank slice dropped keeps default",
			"TRUSTED_PROXY_CIDRS",
			"",
			"",
			nil,
		},
		{
			"whitespace-only slice dropped",
			"TRUSTED_PROXY_CIDRS",
			" , ,",
			"",
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotKey, gotVal := envCallback(c.key, c.value)
			if gotKey != c.wantKey {
				t.Fatalf("key: got %q, want %q", gotKey, c.wantKey)
			}
			if !reflect.DeepEqual(gotVal, c.wantVal) {
				t.Fatalf("value: got %#v, want %#v", gotVal, c.wantVal)
			}
		})
	}
}

func TestEnvCallbackSliceSplitting(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  []string
	}{
		{"single", "10.0.0.0/8", []string{"10.0.0.0/8"}},
		{
			"multiple",
			"10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
			[]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		},
		{
			"spaces trimmed",
			" 10.0.0.0/8 , 172.16.0.0/12 ",
			[]string{"10.0.0.0/8", "172.16.0.0/12"},
		},
		{
			"empty entries dropped",
			"10.0.0.0/8,,192.168.0.0/16,",
			[]string{"10.0.0.0/8", "192.168.0.0/16"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotKey, gotVal := envCallback("TRUSTED_PROXY_CIDRS", c.value)
			if gotKey != "server.trusted_proxy_cidrs" {
				t.Fatalf(
					"key: got %q, want %q",
					gotKey,
					"server.trusted_proxy_cidrs",
				)
			}
			got, ok := gotVal.([]string)
			if !ok {
				t.Fatalf("value type: got %T, want []string", gotVal)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("value: got %#v, want %#v", got, c.want)
			}
		})
	}
}

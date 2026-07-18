/*
©AngelaMos | 2026
lookup.go

GeoIP resolution using MaxMind GeoLite2 databases

Resolves IP addresses to geographic location (GeoLite2-City) and
ASN/organization (GeoLite2-ASN). Both databases are optional and
independent — if either file is missing, that portion of GeoInfo
is left zero-valued rather than failing the whole lookup, allowing
the system to operate without a MaxMind account during local dev.
*/

package geo

import (
	"fmt"
	"net"
	"os"

	"github.com/oschwald/maxminddb-golang"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

type cityRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

type asnRecord struct {
	AutonomousSystemNumber       int    `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

type Lookup struct {
	city *maxminddb.Reader
	asn  *maxminddb.Reader
}

// NewLookup opens the City and ASN databases independently. A missing
// or unreadable file for either is not an error — Resolve simply
// won't populate those fields, matching the previous zero-value
// fallback behavior for local dev without a MaxMind account.
func NewLookup(cityPath, asnPath string) (*Lookup, error) {
	l := &Lookup{}

	if city, err := maxminddb.Open(cityPath); err != nil {
		fmt.Fprintf(os.Stderr, "geoip: city db unavailable at %s: %v\n", cityPath, err)
	} else {
		l.city = city
	}

	if asn, err := maxminddb.Open(asnPath); err != nil {
		fmt.Fprintf(os.Stderr, "geoip: asn db unavailable at %s: %v\n", asnPath, err)
	} else {
		l.asn = asn
	}

	return l, nil
}

func (l *Lookup) Resolve(
	ip string,
) (*types.GeoInfo, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid ip: %s", ip)
	}

	if parsed.IsLoopback() || parsed.IsPrivate() {
		return &types.GeoInfo{}, nil
	}

	info := &types.GeoInfo{}

	if l.city != nil {
		var rec cityRecord
		if err := l.city.Lookup(parsed, &rec); err != nil {
			return nil, fmt.Errorf("city lookup: %w", err)
		}
		info.CountryCode = rec.Country.ISOCode
		info.Country = rec.Country.Names["en"]
		info.City = rec.City.Names["en"]
		info.Latitude = rec.Location.Latitude
		info.Longitude = rec.Location.Longitude
	}

	if l.asn != nil {
		var rec asnRecord
		if err := l.asn.Lookup(parsed, &rec); err != nil {
			return nil, fmt.Errorf("asn lookup: %w", err)
		}
		info.ASN = rec.AutonomousSystemNumber
		info.Org = rec.AutonomousSystemOrganization
	}

	return info, nil
}

func (l *Lookup) Close() error {
	var firstErr error
	if l.city != nil {
		if err := l.city.Close(); err != nil {
			firstErr = err
		}
	}
	if l.asn != nil {
		if err := l.asn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

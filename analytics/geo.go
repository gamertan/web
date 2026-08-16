// SPDX-License-Identifier: MPL-2.0

package analytics

import "context"

// GeoEnricher is deliberately optional. Implementations may use a private local
// database; the base analytics package performs no network lookup.
type GeoEnricher interface {
	Lookup(context.Context, string) (GeoEvidence, error)
}
type GeoEvidence struct {
	CountryCode, Region, City, ASNOrganization string
	ASN                                        uint
	Source, Confidence                         string
}

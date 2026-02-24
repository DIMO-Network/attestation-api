package fetchapi

import (
	"github.com/DIMO-Network/cloudevent"
	pb "github.com/DIMO-Network/fetch-api/pkg/grpc"
)

// TagVehicleStatus is the tag used to filter vehicle status events for VC issuance (e.g. POM).
// Events may also be tagged "vehicle" and "status" per fetch-api indexing; we use contains_any to match any of these.
const TagVehicleStatus = "vehicle.status"

// StatusEventTagsForQuery are tags used when querying status events for POM/general status.
// Matches events tagged with vehicle.status or the common "vehicle"/"status" pair from indexing.
var StatusEventTagsForQuery = []string{TagVehicleStatus, "vehicle", "status"}

// BuildAdvancedOptionsForStatus builds AdvancedSearchOptions for status events with the given subject, producer, and tags.
// Used by POM and any consumer that needs status events with the correct tag filter.
func BuildAdvancedOptionsForStatus(subject, producer string, tags []string) *pb.AdvancedSearchOptions {
	if tags == nil {
		tags = StatusEventTagsForQuery
	}
	return &pb.AdvancedSearchOptions{
		Type:     &pb.StringFilterOption{In: []string{cloudevent.TypeStatus}},
		Subject:  &pb.StringFilterOption{In: []string{subject}},
		Producer: &pb.StringFilterOption{In: []string{producer}},
		Tags:     &pb.ArrayFilterOption{ContainsAny: tags},
	}
}

// TagVehicleFingerprint is the tag for status events that contain VIN (matches model-garage vss.TagVehicleFingerprint).
const TagVehicleFingerprint = "vehicle.fingerprint"

// BuildAdvancedOptionsForStatusWithFingerprintTag builds AdvancedSearchOptions for status events that contain VIN
// (tagged with vehicle.fingerprint). Used when querying for fingerprint/VIN from status events.
func BuildAdvancedOptionsForStatusWithFingerprintTag(subject, producer string) *pb.AdvancedSearchOptions {
	return &pb.AdvancedSearchOptions{
		Type:     &pb.StringFilterOption{In: []string{cloudevent.TypeStatus}},
		Subject:  &pb.StringFilterOption{In: []string{subject}},
		Producer: &pb.StringFilterOption{In: []string{producer}},
		Tags:     &pb.ArrayFilterOption{ContainsAny: []string{TagVehicleFingerprint}},
	}
}

package fetchapi

import (
	"testing"

	"github.com/DIMO-Network/cloudevent"
	"github.com/stretchr/testify/require"
)

func TestBuildAdvancedOptionsForStatus(t *testing.T) {
	subject := "did:erc721:1:0xabc:1"
	producer := "did:erc721:1:0xdef:2"

	opts := BuildAdvancedOptionsForStatus(subject, producer, nil)
	require.NotNil(t, opts)
	require.NotNil(t, opts.Type)
	require.Equal(t, []string{cloudevent.TypeStatus}, opts.Type.In)
	require.NotNil(t, opts.Subject)
	require.Equal(t, []string{subject}, opts.Subject.In)
	require.NotNil(t, opts.Producer)
	require.Equal(t, []string{producer}, opts.Producer.In)
	require.NotNil(t, opts.Tags)
	require.Equal(t, StatusEventTagsForQuery, opts.Tags.ContainsAny)
}

func TestBuildAdvancedOptionsForStatus_customTags(t *testing.T) {
	opts := BuildAdvancedOptionsForStatus("sub", "prod", []string{"vehicle.status"})
	require.NotNil(t, opts.Tags)
	require.Equal(t, []string{"vehicle.status"}, opts.Tags.ContainsAny)
}

func TestBuildAdvancedOptionsForStatusWithFingerprintTag(t *testing.T) {
	subject := "did:erc721:1:0xabc:1"
	producer := "did:erc721:1:0xdef:2"

	opts := BuildAdvancedOptionsForStatusWithFingerprintTag(subject, producer)
	require.NotNil(t, opts)
	require.NotNil(t, opts.Type)
	require.Equal(t, []string{cloudevent.TypeStatus}, opts.Type.In)
	require.NotNil(t, opts.Subject)
	require.Equal(t, []string{subject}, opts.Subject.In)
	require.NotNil(t, opts.Producer)
	require.Equal(t, []string{producer}, opts.Producer.In)
	require.NotNil(t, opts.Tags)
	require.Equal(t, []string{TagVehicleFingerprint}, opts.Tags.ContainsAny)
	require.Equal(t, "vehicle.fingerprint", TagVehicleFingerprint)
}

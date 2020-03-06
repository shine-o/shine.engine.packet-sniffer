package lib

import "testing"

// given a segment assert it returns correct packet Length and package Type
func TestPacketBoundary(t *testing.T) {

}

// Streams flowing from the Server. Assert that each resulting packet department & command correspond to known Department Code and Commands
func TestServerStreams(t *testing.T) {

}

// Streams flowing from the Client. Assert that each resulting packet department & command correspond to known Department Code and Commands
func TestClientStreams(t *testing.T) {
	cs := make(map[string]string)

	cs["Login"] = "hexstreamgoeshere"

	// for each resulting packet, check against a list of known Department Codes and Commands

}

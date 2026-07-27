package tamizdat

import "testing"

func TestServerH2FrameSizeLimitsClientPerStreamScratch(t *testing.T) {
	const streams = 4096
	h2Server := newServerH2(streams)

	if got := h2Server.MaxConcurrentStreams; got != streams {
		t.Fatalf("MaxConcurrentStreams = %d, want %d", got, streams)
	}
	if got := h2Server.MaxReadFrameSize; got != 64<<10 {
		t.Fatalf("MaxReadFrameSize = %d, want %d", got, 64<<10)
	}
	if got := h2Server.MaxUploadBufferPerStream; got != 4<<20 {
		t.Fatalf("MaxUploadBufferPerStream = %d, want %d", got, 4<<20)
	}
	if got := h2Server.MaxUploadBufferPerConnection; got != 16<<20 {
		t.Fatalf("MaxUploadBufferPerConnection = %d, want %d", got, 16<<20)
	}
}

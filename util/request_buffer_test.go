package util

import "testing"

func TestRequestBuffer(t *testing.T) {
	buffer := MakeRequestBuffer()
	received := make(chan byte, 6)
	for id := uint32(1); id <= 3; id++ {
		expected := byte(id)
		buffer.Request(id, func(response []byte) {
			if response[0] != expected {
				received <- 0
			} else {
				received <- response[0]
			}
		})
	}
	for value := byte(1); value <= 6; value++ {
		buffer.Respond([]byte{value})
	}
	for id := uint32(4); id <= 6; id++ {
		if !buffer.Request(id, func(response []byte) { received <- response[0] }) {
			t.Fatal("queued response was not delivered")
		}
	}
	for expected := byte(1); expected <= 6; expected++ {
		if got := <-received; got != expected {
			t.Fatalf("response %d received in position %d", got, expected)
		}
	}
}

func TestRequestBufferCancellationAndReentry(t *testing.T) {
	buffer := MakeRequestBuffer()
	buffer.Request(1, func([]byte) { t.Error("cancelled request received a response") })
	if !buffer.CancelRequest(1) || buffer.CancelRequest(1) {
		t.Fatal("incorrect cancellation result")
	}
	buffer.Respond([]byte{2})
	buffer.Request(2, func(response []byte) {
		if response[0] != 2 {
			t.Error("queued response lost")
		}
		buffer.Request(3, func(response []byte) {
			if response[0] != 3 {
				t.Error("reentrant response lost")
			}
		})
	})
	buffer.Respond([]byte{3})
}

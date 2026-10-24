package util

import "sync"

type RequestBuffer struct {
	lock           *sync.Mutex
	waitingForData map[uint32]func([]byte)
	responses      [][]byte
}

func MakeRequestBuffer() *RequestBuffer {
	buffer := RequestBuffer{
		lock:           &sync.Mutex{},
		waitingForData: make(map[uint32]func([]byte)),
		responses:      make([][]byte, 0),
	}
	return &buffer
}

func (buffer *RequestBuffer) Request(id uint32, request func(response []byte)) bool {
	buffer.lock.Lock()
	defer buffer.lock.Unlock()
	if len(buffer.responses) > 0 {
		response := buffer.responses[0]
		buffer.responses = buffer.responses[1:]
		request(response)
		return true
	} else {
		buffer.waitingForData[id] = request
		return false
	}
}

func (buffer *RequestBuffer) CancelRequest(id uint32) bool {
	buffer.lock.Lock()
	defer buffer.lock.Unlock()
	if _, ok := buffer.waitingForData[id]; ok {
		delete(buffer.waitingForData, id)
		return true
	} else {
		return false
	}
}

func (buffer *RequestBuffer) Respond(data []byte) {
	buffer.lock.Lock()

	isKeepalive := len(data) > 4 && data[4] == 0xBB

	// When a real response arrives, purge all pending keepalives so the real response is delivered immediately
	if !isKeepalive && len(buffer.responses) > 0 {
		filtered := make([][]byte, 0, len(buffer.responses))
		for _, resp := range buffer.responses {
			if len(resp) > 4 && resp[4] == 0xBB {
				continue
			}
			filtered = append(filtered, resp)
		}
		buffer.responses = filtered
	}

	if len(buffer.waitingForData) > 0 {
		// Get first waiting request
		var id uint32
		var request func([]byte)
		for id, request = range buffer.waitingForData {
			break
		}
		delete(buffer.waitingForData, id)
		buffer.lock.Unlock()
		request(data)
	} else {
		// If it's a keepalive and host hasn't asked for it yet, only keep at most one keepalive in queue
		if isKeepalive {
			hasKeepalive := false
			for _, resp := range buffer.responses {
				if len(resp) > 4 && resp[4] == 0xBB {
					hasKeepalive = true
					break
				}
			}
			if hasKeepalive {
				buffer.lock.Unlock()
				return
			}
		}
		buffer.responses = append(buffer.responses, data)
		buffer.lock.Unlock()
	}
}

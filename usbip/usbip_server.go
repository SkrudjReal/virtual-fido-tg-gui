package usbip

import (
	"net"
	"strings"
	"sync"
	"syscall"

	"github.com/bulwarkid/virtual-fido/util"
)

var usbipLogger = util.NewLogger("[USBIP] ", util.LogLevelTrace)
var errLogger = util.NewLogger("[ERR] ", util.LogLevelEnabled)

type USBIPServer struct {
	devices  []USBIPDevice
	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

func NewUSBIPServer(devices []USBIPDevice) *USBIPServer {
	server := new(USBIPServer)
	server.devices = devices
	return server
}

func (server *USBIPServer) Start() {
	usbipLogger.Println("Starting USBIP server...")
	listener, err := net.Listen("tcp", ":3240")
	if err != nil {
		usbipLogger.Printf("Could not create listener: %v", err)
		return
	}
	server.mu.Lock()
	server.listener = listener
	server.closed = false
	server.mu.Unlock()

	for {
		connection, err := listener.Accept()
		if err != nil {
			server.mu.Lock()
			closed := server.closed
			server.mu.Unlock()
			if closed {
				usbipLogger.Println("USBIP server stopped.")
				return
			}
			usbipLogger.Printf("Connection accept error: %v", err)
			continue
		}
		if !strings.HasPrefix(connection.RemoteAddr().String(), "127.0.0.1") {
			usbipLogger.Printf("Connection attempted from non-local address: %s", connection.RemoteAddr().String())
			connection.Close()
			continue
		}
		usbipConn := newUSBIPConnection(server, connection)
		util.Try(func() {
			usbipConn.handle()
		}, func(err interface{}) {
			errLogger.Printf("%v", err)
		})
	}
}

func (server *USBIPServer) Stop() {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.closed = true
	if server.listener != nil {
		server.listener.Close()
		server.listener = nil
	}
}

func (server *USBIPServer) getDevice(busID string) USBIPDevice {
	var device USBIPDevice = nil
	for _, other := range server.devices {
		if other.BusID() == busID {
			device = other
			break
		}
	}
	return device
}

type usbipConnection struct {
	responseMutex *sync.Mutex
	conn          net.Conn
	server        *USBIPServer
}

func newUSBIPConnection(server *USBIPServer, conn net.Conn) *usbipConnection {
	usbipConn := new(usbipConnection)
	usbipConn.responseMutex = &sync.Mutex{}
	usbipConn.conn = conn
	usbipConn.server = server
	return usbipConn
}

func (conn *usbipConnection) handle() {
	for {
		header := util.ReadBE[usbipControlHeader](conn.conn)
		usbipLogger.Printf("[CONTROL MESSAGE] %#v\n\n", header)
		if header.Command == usbipCommandOpReqDevlist {
			reply := newOpRepDevlist(conn.server.devices)
			usbipLogger.Printf("[OP_REP_DEVLIST] %#v\n\n", reply)
			conn.writeResponse(util.ToBE(reply))
		} else if header.Command == usbipCommandOpReqImport {
			busIDData := util.Read(conn.conn, 32)
			busID := util.CStringToString(busIDData)
			device := conn.server.getDevice(busID)
			if device == nil {
				// Device not found
				reply := opRepImportError(1)
				conn.writeResponse(util.ToBE(reply))
				continue
			}
			reply := newOpRepImport(device)
			usbipLogger.Printf("[OP_REP_IMPORT] %s\n\n", reply)
			conn.writeResponse(util.ToBE(reply))
			conn.handleCommands(device)
		} else {
			usbipLogger.Printf("Unknown Command Code: %d", header.Command)
		}
	}
}

func (conn *usbipConnection) handleCommands(device USBIPDevice) {
	for {
		var readErr bool
		util.Try(func() {
			header := util.ReadBE[usbipMessageHeader](conn.conn)
			usbipLogger.Printf("[MESSAGE HEADER] %s\n\n", header)
			if header.Command == usbipCmdSubmit {
				conn.handleCommandSubmit(device, header)
			} else if header.Command == usbipCmdUnlink {
				conn.handleCommandUnlink(device, header)
			} else {
				usbipLogger.Printf("Unsupported Command: %#v\n\n", header)
			}
		}, func(err interface{}) {
			readErr = true
			usbipLogger.Printf("USBIP connection closed: %v", err)
		})
		if readErr {
			break
		}
	}
}

func (conn *usbipConnection) handleCommandSubmit(device USBIPDevice, header usbipMessageHeader) {
	command := util.ReadBE[usbipCommandSubmitBody](conn.conn)
	usbipLogger.Printf("[COMMAND SUBMIT] %s\n\n", command)
	transferBuffer := make([]byte, command.TransferBufferLength)
	if header.Direction == usbipDirOut && command.TransferBufferLength > 0 {
		_, err := conn.conn.Read(transferBuffer)
		util.CheckErr(err, "Could not read transfer buffer")
	}
	// Getting the reponse may not be immediate, so we need a callback
	onReturnSubmit := func(response []byte) {
		var actualData []byte
		if response != nil {
			actualData = response
			if len(actualData) > int(command.TransferBufferLength) {
				actualData = actualData[:command.TransferBufferLength]
			}
		}
		replyHeader := header.replyHeader()
		replyBody := usbipReturnSubmitBody{
			Status:          0,
			ActualLength:    uint32(len(actualData)),
			StartFrame:      0,
			NumberOfPackets: 0,
			ErrorCount:      0,
			Padding:         0,
		}
		usbipLogger.Printf("[RETURN SUBMIT] %v %#v\n\n", replyHeader, replyBody)
		reply := util.Concat(util.ToBE(replyHeader), util.ToBE(replyBody))
		if header.Direction == usbipDirIn && len(actualData) > 0 {
			usbipLogger.Printf("[RETURN SUBMIT] DATA: %#v\n\n", actualData)
			reply = append(reply, actualData...)
		}
		conn.writeResponse(reply)
	}
	device.HandleMessage(header.SequenceNumber, onReturnSubmit, header.Endpoint, command.SetupBytes[:], transferBuffer)
}

func (conn *usbipConnection) handleCommandUnlink(device USBIPDevice, header usbipMessageHeader) {
	unlink := util.ReadBE[usbipCommandUnlinkBody](conn.conn)
	usbipLogger.Printf("[COMMAND UNLINK] %#v\n\n", unlink)
	var status int32
	if device.RemoveWaitingRequest(unlink.UnlinkSequenceNumber) {
		status = -int32(syscall.ECONNRESET)
	} else {
		status = -int32(syscall.ENOENT)
	}
	replyHeader := header.replyHeader()
	replyBody := usbipReturnUnlinkBody{
		Status:  status,
		Padding: [24]byte{},
	}
	reply := util.Concat(
		util.ToBE(replyHeader),
		util.ToBE(replyBody),
	)
	conn.writeResponse(reply)
}

func (conn *usbipConnection) writeResponse(data []byte) {
	conn.responseMutex.Lock()
	defer conn.responseMutex.Unlock()
	util.Try(func() {
		util.Write(conn.conn, data)
	}, func(err interface{}) {
		usbipLogger.Printf("writeResponse error: %v", err)
	})
}

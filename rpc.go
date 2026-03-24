package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// --- XDR reader ---

type xdrReader struct {
	data []byte
	pos  int
}

func (r *xdrReader) Uint32() uint32 {
	v := binary.BigEndian.Uint32(r.data[r.pos:])
	r.pos += 4
	return v
}

func (r *xdrReader) Uint64() uint64 {
	v := binary.BigEndian.Uint64(r.data[r.pos:])
	r.pos += 8
	return v
}

func (r *xdrReader) Opaque() []byte {
	n := int(r.Uint32())
	if r.pos+n > len(r.data) {
		r.pos = len(r.data)
		return nil
	}
	data := make([]byte, n)
	copy(data, r.data[r.pos:r.pos+n])
	r.pos += (n + 3) &^ 3 // pad to 4-byte boundary
	return data
}

func (r *xdrReader) String() string {
	return string(r.Opaque())
}

// --- XDR writer ---

type xdrWriter struct {
	data []byte
}

func (w *xdrWriter) PutUint32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.data = append(w.data, b[:]...)
}

func (w *xdrWriter) PutUint64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.data = append(w.data, b[:]...)
}

func (w *xdrWriter) PutOpaque(data []byte) {
	w.PutUint32(uint32(len(data)))
	w.data = append(w.data, data...)
	if pad := (4 - len(data)%4) % 4; pad > 0 {
		w.data = append(w.data, make([]byte, pad)...)
	}
}

func (w *xdrWriter) PutString(s string) {
	w.PutOpaque([]byte(s))
}

func (w *xdrWriter) Bytes() []byte {
	return w.data
}

// --- Sun RPC over TCP ---

type rpcCall struct {
	xid       uint32
	program   uint32
	version   uint32
	procedure uint32
	body      *xdrReader
}

// rpcReadRecord reads one RPC record (possibly multi-fragment) from a TCP connection.
func rpcReadRecord(conn net.Conn) ([]byte, error) {
	var result []byte
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return nil, err
		}
		word := binary.BigEndian.Uint32(hdr[:])
		last := word&0x80000000 != 0
		fragLen := word & 0x7FFFFFFF
		if fragLen > 1<<20 {
			return nil, fmt.Errorf("fragment too large: %d", fragLen)
		}
		frag := make([]byte, fragLen)
		if _, err := io.ReadFull(conn, frag); err != nil {
			return nil, err
		}
		result = append(result, frag...)
		if last {
			return result, nil
		}
	}
}

// rpcWriteRecord writes one RPC record as a single fragment.
func rpcWriteRecord(conn net.Conn, data []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data))|0x80000000)
	if _, err := conn.Write(append(hdr[:], data...)); err != nil {
		return err
	}
	return nil
}

func parseRPCCall(data []byte) (*rpcCall, error) {
	if len(data) < 40 {
		return nil, fmt.Errorf("rpc message too short: %d bytes", len(data))
	}
	r := &xdrReader{data: data}
	xid := r.Uint32()
	msgType := r.Uint32()
	if msgType != 0 {
		return nil, fmt.Errorf("expected RPC CALL (0), got %d", msgType)
	}
	rpcVers := r.Uint32()
	if rpcVers != 2 {
		return nil, fmt.Errorf("unsupported RPC version %d", rpcVers)
	}
	prog := r.Uint32()
	vers := r.Uint32()
	proc := r.Uint32()

	// Skip auth credentials
	_ = r.Uint32() // flavor
	_ = r.Opaque() // body
	// Skip verifier
	_ = r.Uint32() // flavor
	_ = r.Opaque() // body

	return &rpcCall{
		xid:       xid,
		program:   prog,
		version:   vers,
		procedure: proc,
		body:      &xdrReader{data: data, pos: r.pos},
	}, nil
}

func buildRPCReply(xid uint32, body []byte) []byte {
	w := &xdrWriter{}
	w.PutUint32(xid)
	w.PutUint32(1) // REPLY
	w.PutUint32(0) // MSG_ACCEPTED
	w.PutUint32(0) // AUTH_NONE verifier
	w.PutUint32(0) // empty verifier body
	w.PutUint32(0) // ACCEPT_STAT = SUCCESS
	w.data = append(w.data, body...)
	return w.data
}

func buildRPCError(xid uint32, acceptStat uint32) []byte {
	w := &xdrWriter{}
	w.PutUint32(xid)
	w.PutUint32(1) // REPLY
	w.PutUint32(0) // MSG_ACCEPTED
	w.PutUint32(0) // AUTH_NONE
	w.PutUint32(0) // empty verifier
	w.PutUint32(acceptStat)
	return w.data
}

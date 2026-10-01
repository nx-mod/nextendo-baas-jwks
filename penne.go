package main

// Penne frontline push messages (npns 22.5.0).
//
// A notification is a PutRecord carrying exactly one record (handler 0x4f754dfbb0). The record is
// {0: variant u8, 1: object}; variant 1 = a message. The message object (parser 0x4f754d69f0) is:
//
//	field 0  id        string, < 48 chars; for a topic message "<topic>-<unique>"
//	field 1  type      u16; 2 = topic message
//	field 2  dest      table {1: application ids (comma-separated), 2: account (32 hex or ""), 4: topic}
//	field 4  payload   string, < 4096 bytes: what the receiving module parses
//	field 5  time      u64: delivery time (seconds); a due time delivers at once
//
// bcat's news code (0x61119029b0) reads the payload as JSON: {"type":"news","topic_id":...} to re-fetch a channel.
//
// NOTHING here is confirmed against a console. A malformed message aborts npns (a system crash), so a push is
// only sent on an explicit internal trigger, never automatically.

import (
	"encoding/binary"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// The live frontline stream's send function, if a console has one open and is synced. A push goes out only on
// an explicit internal trigger (POST /internal/penne-push?topic=...), never automatically.
var (
	penneStreamMu   sync.Mutex
	penneStreamSend func([]byte)
)

func penneRegisterStream(send func([]byte)) {
	penneStreamMu.Lock()
	penneStreamSend = send
	penneStreamMu.Unlock()
}

func penneUnregisterStream() {
	penneStreamMu.Lock()
	penneStreamSend = nil
	penneStreamMu.Unlock()
}

// handlePennePush sends one news PutRecord to the live console stream.
func handlePennePush(w http.ResponseWriter, r *http.Request) {
	topic := r.URL.Query().Get("topic")
	if topic == "" {
		topic = defaultNewsTopic
	}
	penneStreamMu.Lock()
	send := penneStreamSend
	penneStreamMu.Unlock()
	if send == nil {
		http.Error(w, "no live penne stream", http.StatusServiceUnavailable)
		return
	}
	msg := penneNewsPushDefault(topic)
	send(msg)
	log.Printf("[baas-jwks]     frontline -> PutRecord news push for %s (%d bytes)", topic, len(msg))
	w.Write([]byte("sent " + topic + "\n"))
}

const defaultNewsTopic = "nx_news"

// pennePutRecord is the command type that carries a delivered record (a notification). Other command types are
// in main.go.
const pennePutRecord = 4

// --- a FlatBuffers builder, following the official back-to-front algorithm ---

type fb struct {
	buf      []byte
	head     int // bytes written; the message is buf[len(buf)-head:]
	minalign int
	vt       []int // field value offsets for the table being built (0 = unset)
	objEnd   int   // head at startObject (the table's inline data size is measured from here)
}

func newFB() *fb { return &fb{buf: make([]byte, 256), minalign: 1} }

func (b *fb) offset() int { return b.head }

func (b *fb) prep(size, additional int) {
	if size > b.minalign {
		b.minalign = size
	}
	alignSize := (^(b.head + additional) + 1) & (size - 1)
	for len(b.buf) < b.head+alignSize+size+additional {
		nb := make([]byte, len(b.buf)*2)
		copy(nb[len(nb)-len(b.buf):], b.buf)
		b.buf = nb
	}
	for i := 0; i < alignSize; i++ {
		b.head++
		b.buf[len(b.buf)-b.head] = 0
	}
}

func (b *fb) place8(v byte) { b.head++; b.buf[len(b.buf)-b.head] = v }
func (b *fb) place16(v uint16) {
	b.head += 2
	binary.LittleEndian.PutUint16(b.buf[len(b.buf)-b.head:], v)
}
func (b *fb) place32(v uint32) {
	b.head += 4
	binary.LittleEndian.PutUint32(b.buf[len(b.buf)-b.head:], v)
}
func (b *fb) place64(v uint64) {
	b.head += 8
	binary.LittleEndian.PutUint64(b.buf[len(b.buf)-b.head:], v)
}

func (b *fb) putU8(v byte)    { b.prep(1, 0); b.place8(v) }
func (b *fb) putU16(v uint16) { b.prep(2, 0); b.place16(v) }
func (b *fb) putU32(v uint32) { b.prep(4, 0); b.place32(v) }
func (b *fb) putU64(v uint64) { b.prep(8, 0); b.place64(v) }

// offsetBack writes a 4-byte offset pointing back (toward the end) to target.
func (b *fb) offsetBack(target int) {
	b.prep(4, 0)
	b.place32(uint32(b.head + 4 - target))
}

// createString writes a string, returns its offset.
func (b *fb) createString(s string) int {
	b.prep(4, len(s)+1) // length prefix aligned to 4; +1 NUL, +len bytes reserved
	b.head++            // NUL terminator
	b.buf[len(b.buf)-b.head] = 0
	b.head += len(s)
	copy(b.buf[len(b.buf)-b.head:], s)
	b.place32(uint32(len(s)))
	return b.head
}

func (b *fb) startObject(numFields int) {
	b.vt = make([]int, numFields)
	b.objEnd = b.head
}

func (b *fb) slot(i int) { b.vt[i] = b.head }

func (b *fb) addU8(i int, v byte)     { b.putU8(v); b.slot(i) }
func (b *fb) addU16(i int, v uint16)  { b.putU16(v); b.slot(i) }
func (b *fb) addU64(i int, v uint64)  { b.putU64(v); b.slot(i) }
func (b *fb) addOffset(i, target int) { b.offsetBack(target); b.slot(i) }

// endObject writes the vtable and table header, returns the table's offset.
func (b *fb) endObject() int {
	b.prep(4, 0)
	b.head += 4 // soffset to the vtable, filled below
	objOff := b.head

	fields := 0
	for i := range b.vt {
		if b.vt[i] != 0 {
			fields = i + 1
		}
	}
	// vtable: field voffsets (reverse), then table size, then vtable size
	for i := fields - 1; i >= 0; i-- {
		off := uint16(0)
		if b.vt[i] != 0 {
			off = uint16(objOff - b.vt[i])
		}
		b.putU16(off)
	}
	b.putU16(uint16(objOff - b.objEnd)) // table inline size
	b.putU16(uint16((fields + 2) * 2))  // vtable size
	vtOff := b.head
	// the soffset stored at the table start = vtable offset - table offset (positive; reader does table - soffset)
	binary.LittleEndian.PutUint32(b.buf[len(b.buf)-objOff:], uint32(int32(vtOff-objOff)))
	return objOff
}

// finish prepends the root offset (4-aligned to minalign) and frames the message.
func (b *fb) finish(root int) []byte {
	b.prep(b.minalign, 4)
	b.offsetBack(root)
	msg := append([]byte(nil), b.buf[len(b.buf)-b.head:]...)
	out := make([]byte, 4+len(msg))
	binary.LittleEndian.PutUint32(out, uint32(len(msg)))
	copy(out[4:], msg)
	return out
}

// --- the news push message ---

// penneNewsPush builds a framed PutRecord that tells the console topic `topic` changed, so bcat re-fetches it.
// apps is the application ids the message is addressed to (comma-separated); payload is the JSON bcat reads.
func penneNewsPush(topic, apps, payload string) []byte {
	b := newFB()

	id := b.createString(topic + "-" + strconv.FormatInt(time.Now().UnixNano(), 16))
	appsOff := b.createString(apps)
	payloadOff := b.createString(payload)

	// destination table {1: application ids, 2: account (empty), 4: topic}
	topicOff := b.createString(topic)
	b.startObject(5)
	b.addOffset(1, appsOff)
	b.addOffset(4, topicOff)
	dest := b.endObject()

	// message object {0: id, 1: type=2, 2: dest, 4: payload, 5: time}
	b.startObject(6)
	b.addOffset(0, id)
	b.addU16(1, 2)
	b.addOffset(2, dest)
	b.addOffset(4, payloadOff)
	b.addU64(5, uint64(time.Now().Unix()))
	msgObj := b.endObject()

	// record {0: variant=1 (message), 1: object}
	b.startObject(2)
	b.addU8(0, 1)
	b.addOffset(1, msgObj)
	record := b.endObject()

	// records vector (exactly one)
	b.prep(4, 4)
	b.offsetBack(record)
	b.place32(1) // vector length
	recordsVec := b.head

	// PutRecord command table {0: records vector}
	b.startObject(1)
	b.addOffset(0, recordsVec)
	cmd := b.endObject()

	// root {0: command type, 1: command}
	b.startObject(2)
	b.addU8(0, pennePutRecord)
	b.addOffset(1, cmd)
	root := b.endObject()

	return b.finish(root)
}

func pennePayloadNews(topic string) string {
	return `{"type":"news","topic_id":"` + topic + `","wait_range":0,"ha_wait_range_min":0,"ha_wait_range_max":0}`
}

// the qlaunch (HOME menu) application id, whose bcat receives News topics.
const penneNewsApps = "0x0100000000001000"

func penneNewsPushDefault(topic string) []byte {
	return penneNewsPush(topic, penneNewsApps, pennePayloadNews(topic))
}

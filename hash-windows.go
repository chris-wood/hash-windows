package main

import "fmt"
import "time"
import "log"
import random "math/rand"
import "math"

//import "os"
//import "log"
//import "runtime"
//import "github.com/pkg/profile"

import "crypto/rand"
import "crypto/hmac"
import "crypto/sha256"
import "encoding/binary"
import "encoding/hex"

func computeTag(in uint32, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	inContainer := make([]byte, 4)
	binary.LittleEndian.PutUint32(inContainer, in)
	mac.Write(inContainer)
	output := mac.Sum(nil)
	return hex.EncodeToString(output[0:4])
}

type LossyChannel struct {
	channel         chan interface{}
	lossProbability float64
	timeout         int
	id              int
}

type channelError struct {
	prob string
}

func (e channelError) Error() string {
	return fmt.Sprintf("%s", e.prob)
}

func NewLossyChannel(lossProbability float64, timeoutInMs int, id int) *LossyChannel {
	return &LossyChannel{make(chan interface{}), lossProbability, timeoutInMs * 1000000, id}
}

func (c LossyChannel) Read() (interface{}, error) {
	select {
	case item := <-c.channel:
		coinFlip := random.Float64()

		if coinFlip >= c.lossProbability {
			return item, nil
		} else {
			return c.Read() // Try to read again...
		}

	// The read timed out
	case <-time.After(time.Nanosecond * time.Duration(c.timeout)):
		return nil, channelError{"timeout"}
	}
}

func (c LossyChannel) Write(v interface{}) {
	c.channel <- v
}

type HashState struct {
	tagTable   map[string]uint32
	currentNum uint32
	lastNum    uint32
	lastTag    string
	key        string
}

func GenerateRandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b) // ignore errors...
	return b
}

func NewHashState(n int) *HashState {
	state := HashState{
		tagTable:   make(map[string]uint32),
		currentNum: 0,
		lastNum:    0,
		lastTag:    "",
		key:        string(GenerateRandomBytes(32)),
	}

	state.lastTag = computeTag(state.lastNum, state.key)

	for i := 0; i <= n; i++ {
		state.IncreaseWindow()
	}

	return &state
}

func (s HashState) IsInWindow(tag string) bool {
	_, ok := s.tagTable[tag]
	return ok
}

func (s *HashState) IncreaseWindow() {
	topValue := computeTag(s.currentNum, s.key)
	s.tagTable[topValue] = s.currentNum
	s.currentNum++
}

func (s *HashState) AdvanceWindow() {
	bottomValue := computeTag(s.lastNum, s.key)
	_, ok := s.tagTable[bottomValue]
	if ok {
		delete(s.tagTable, bottomValue)
		s.lastNum++
		s.lastTag = computeTag(s.lastNum, s.key)
		topValue := computeTag(s.currentNum, s.key)
		s.tagTable[topValue] = s.currentNum
		s.currentNum++
	}
}

func slidingWindow(state *HashState, stream, out *LossyChannel) {
	for {
		tagOut, err := stream.Read()
		if err == nil {
			start := time.Now()
			flag := false
			tag, _ := tagOut.(string)

			if state.IsInWindow(tag) {
				if tag == state.lastTag {
					state.AdvanceWindow()
				}
				flag = true
			}
			elapsed := time.Since(start)

			out.Write(PacketResult{flag, elapsed})
		} else {
			// pass
		}
	}
}

type PacketResult struct {
	inWindow bool
	elapsed  time.Duration
}

type TagPair struct {
	tag string
	seq uint32
}

type Receiver struct {
	tagWindow map[string]uint32
	window    []TagPair
	cumTag    TagPair
	upperTag  TagPair
	key       string
}

func contains(window []TagPair, tag TagPair) bool {
	for i := 0; i < len(window); i++ {
		if window[i] == tag {
			return true
		}
	}
	return false
}

func NewReceiver(windowSize int) *Receiver {
	key := string(GenerateRandomBytes(32))

	firstTag := computeTag(0, key)

	receiver := Receiver{
		tagWindow: make(map[string]uint32),
		window:    make([]TagPair, 1),
		cumTag:    TagPair{firstTag, 0},
		upperTag:  TagPair{firstTag, 0},
		key:       key,
	}

	// Inject the first tag into the window
	receiver.tagWindow[firstTag] = 0
	for i := 0; i <= windowSize; i++ {
		receiver.IncreaseWindow()
	}

	return &receiver
}

func (t TagPair) Next(key string) TagPair {
	nextTag := computeTag(uint32(t.seq+1), key)
	return TagPair{nextTag, t.seq + 1}
}

func (r *Receiver) AdvanceWindow() {
	r.cumTag = r.cumTag.Next(r.key)
}

func (r *Receiver) IncreaseWindow() {
	nextPair := r.upperTag.Next(r.key)
	r.tagWindow[nextPair.tag] = nextPair.seq
	r.upperTag = nextPair
}

func (r *Receiver) Receive(tag string) (string, string) {
	seq, ok := r.tagWindow[tag]
	if !ok { // out of window, drop
		log.Println("Out of window", tag)
		return r.cumTag.tag, r.cumTag.tag
	} else if seq == r.cumTag.seq {
		log.Println("In window and matches CACK", tag)
		// Advance the tag by one count
		r.AdvanceWindow()

		// But skip ahead to the next tag that has not yet been received
		for {
			if !contains(r.window, r.cumTag) {
				break
			}
			r.AdvanceWindow()
		}

		return r.cumTag.tag, r.cumTag.tag
	} else { // in window, but not the next expected one
		log.Println("In window but != CACK", tag)
		// Add the tag to the window
		pair := TagPair{tag, seq}
		r.window = append(r.window, pair)

		// And return the last accumulated tag
		return r.cumTag.tag, tag
	}
}

type ACK struct {
	cack string
	sack string
}

func (r *Receiver) Run(inputChannel, outputChannel *LossyChannel) {
	for {
		msg, err := inputChannel.Read()
		if err == nil {
			cack, sack := r.Receive(msg.(string))
			outputChannel.Write(ACK{cack, sack})
		}
	}
}

type Sender struct {
	tagWindow   map[string]uint32
	buffer      []uint8 // bit mask -- 1 if sent and ACKd, 0 otherwise
	flight      []int64
	windowUpper uint32
	windowLower uint32
	key         string

	// RTO state variables
	// see: https://tools.ietf.org/html/rfc6298
	srtt   float64
	rttVar float64
	rto    float64
	timer  *time.Timer
}

func NewSender(dataSize, windowSize int) *Sender {
	key := string(GenerateRandomBytes(32))
	sender := Sender{
		tagWindow:   make(map[string]uint32),
		buffer:      make([]uint8, dataSize),
		flight:      make([]int64, dataSize),
		windowUpper: uint32(windowSize - 1),
		windowLower: uint32(0),
		key:         key,
		srtt:        float64(0.0),
		rttVar:      float64(0.0),
		rto:         float64(1000000),
	}

	return &sender
}

func (s *Sender) UpdateState(rtt float64) {
	if s.srtt == 0.0 {
		s.srtt = rtt
		s.rttVar = rtt / 2
	} else {
		beta := float64(0.25)   // 1/4
		alpha := float64(0.125) // 1/8
		delta := math.Abs(s.srtt - rtt)
		s.rttVar = (1-beta)*s.rttVar + beta*delta
		s.srtt = (1-alpha)*s.srtt + alpha*rtt
	}
	s.rto = s.srtt + (4 * s.rttVar)
}

func (s *Sender) ResetTimer() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.NewTimer(time.Nanosecond * time.Duration(s.rto))
	go s.HandleTimeout()
}

func (s *Sender) Acknowledge(seq uint32) {
	rtt := s.CalculateRTT(seq)
	s.UpdateState(float64(rtt))
	s.ResetTimer()
}

func (s *Sender) TagForSeq(seq uint32) string {
	return computeTag(seq, s.key)
}

func (s *Sender) HandleTimeout() {
	<-s.timer.C
	// handle the timeout here...
}

func (s *Sender) Send(channel *LossyChannel) bool {
	index := -1
	for i := s.windowLower; i < s.windowUpper; i++ {
		if s.flight[i] == 0 && s.buffer[i] == 0 {
			index = int(i)
			break
		}
	}

	if index == -1 {
		return false
	}

	tag := s.TagForSeq(uint32(index))

	s.flight[index] = time.Now().UnixNano()
	channel.Write(tag)
	s.ResetTimer()

	return true
}

func (s *Sender) AdvanceWindow() {
	tag := computeTag(s.windowLower, s.key)
	delete(s.tagWindow, tag)
	s.windowLower++
	s.windowUpper++
	tag = computeTag(s.windowUpper, s.key)
	s.tagWindow[tag] = s.windowUpper
}

func (s *Sender) CalculateRTT(seq uint32) int64 {
	now := time.Now().UnixNano()
	return now - s.flight[seq]
}

func (s *Sender) Receive(channel *LossyChannel) {
	for {
		if s.windowLower == uint32(len(s.buffer)) {
			break
		}

		msg, err := channel.Read() // this channel passes ACK structs
		if err == nil {
			seq, ok := s.tagWindow[msg.(string)]
			if !ok {
				// error! someone injected fake data
			} else {
				s.buffer[seq] = 1 // ACK the packet
				s.flight[seq] = 2 // Mark it as permanently in flight
				if seq == s.windowLower {
					s.AdvanceWindow()
					s.Send(channel)
				}

				s.Acknowledge(seq)
			}
		}
	}
}

func (s *Sender) Run(channel *LossyChannel) {
	for {
		if s.windowLower == uint32(len(s.buffer)) {
			s.timer.Stop()
			break
		} else if !s.Send(channel) {
			break
		}
	}

	fmt.Println("Done transferring data")
}

/*

sender (of data):
	packet: (seq number)
	data:
		- map from seq number to tag
		- list of numbers to send (window that sends the first N of this list), ACKs advance window, SACKs remove entries from window

receiver (of data):
	packet: (ack number, SACK) (or not SACK, if just using cumulative ACK scheme)
		- ACK number is ACK of last packet received
		- SACK number is ACK of packet just received, not necessarily the LAST one received
	data: minimum cumulative sequence received, and current window size

*/

func main() {
	/*
		receiver := NewReceiver(10)

		for i := 1; i < 10; i++ {
			tag := computeTag(uint32(i), receiver.key)
			ack, sack := receiver.Receive(tag)
			fmt.Println(ack, sack)
		}

		tag := computeTag(uint32(0), receiver.key)
		ack, sack := receiver.Receive(tag)
		fmt.Println(ack, sack)

		for i := 4; i < 10; i++ {
			tag := computeTag(uint32(i), receiver.key)
			ack, sack := receiver.Receive(tag)
			fmt.Println(ack, sack)
		}
	*/

	outputStream := NewLossyChannel(0.00, 5, 1) // 1ms
	inputStream := NewLossyChannel(0.00, 5, 1)  // 1ms

	windowSize := 5
	dataSize := 10
	receiver := NewReceiver(windowSize)
	sender := NewSender(windowSize, dataSize)

	go receiver.Run(outputStream, inputStream)
	go sender.Receive(inputStream)
	sender.Run(outputStream)

	/*
		state := NewHashState(10)                   // initial window size
		outputStream := NewLossyChannel(0.05, 5, 1) // 1ms
		inputStream := NewLossyChannel(0.00, 5, 1)  // 1ms

		go slidingWindow(state, inputStream, outputStream)

		for i := 0; i < 100; i++ {
			tag := computeTag(uint32(i), state.key)
			inputStream.Write(tag)

			packetResult, err := outputStream.Read()
			if err == nil {
				result, _ := packetResult.(PacketResult)
				if result.inWindow {
					fmt.Printf("1 %d\n", result.elapsed)
				} else {
					fmt.Printf("0 %d\n", result.elapsed)
				}
			} else {
				fmt.Println("Timeout", i)
			}
		}

		for i := 0; i < 100; i++ {
			tag := computeTag(uint32(i), state.key)
			inputStream.Write(tag)

			packetResult, err := outputStream.Read()
			if err == nil {
				result, _ := packetResult.(PacketResult)
				if result.inWindow {
					fmt.Printf("1 %d\n", result.elapsed)
				} else {
					fmt.Printf("0 %d\n", result.elapsed)
				}
			} else {
				fmt.Println("Timeout", i)
			}
		}
	*/

	/*
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
		f.Close()
	*/
}

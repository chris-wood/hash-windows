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
	channelIndex    int
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

func NewLossyChannel(dataSize int, lossProbability float64, timeoutInMs int, id int) *LossyChannel {
	return &LossyChannel{make(chan interface{}, dataSize), 0, lossProbability, timeoutInMs * 1000000, id}
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
	coinFlip := random.Float64()

	if coinFlip >= c.lossProbability {
		c.channel <- v
	}
}

func GenerateRandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b) // ignore errors...
	return b
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

func NewReceiver(windowSize int, key string) *Receiver {
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
	for i := 0; i < windowSize; i++ {
		receiver.IncreaseWindow()
	}

	log.Println("RECEIVER: initial window: ", receiver.tagWindow)

	return &receiver
}

func (t TagPair) Next(key string) TagPair {
	nextTag := computeTag(uint32(t.seq+1), key)
	return TagPair{nextTag, t.seq + 1}
}

func (r *Receiver) AdvanceWindow() {
	r.cumTag = r.cumTag.Next(r.key)
	nextPair := r.upperTag.Next(r.key)
	r.tagWindow[nextPair.tag] = nextPair.seq
	r.upperTag = nextPair
}

func (r *Receiver) IncreaseWindow() {
	nextPair := r.upperTag.Next(r.key)
	r.tagWindow[nextPair.tag] = nextPair.seq
	r.upperTag = nextPair
}

func (r *Receiver) Receive(tag string) (string, string) {
	seq, ok := r.tagWindow[tag]

	log.Println("RECEIVER: Received mesage", tag, seq, r.tagWindow)

	if !ok { // out of window, drop
		log.Println("RECEIVER: Out of window", tag)
		return r.cumTag.tag, r.cumTag.tag
	} else if seq == r.cumTag.seq {
		log.Println("RECEIVER: In window and matches CACK", tag)
		// Advance the tag by one count
		r.AdvanceWindow()

		// But skip ahead to the next tag that has not yet been received
		for {
			if !contains(r.window, r.cumTag) {
				break
			}
			r.AdvanceWindow()
		}

		log.Println("RECEIVER: CACK is now", r.cumTag.seq)
		return r.cumTag.tag, tag
	} else { // in window, but not the next expected one
		log.Println("RECEIVER: In window but != CACK", tag)
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
			cackSeq, _ := r.tagWindow[cack]
			sackSeq, _ := r.tagWindow[sack]
			log.Println("RECEIVER: Sending CACK", cack, cackSeq, "SACK", sack, sackSeq)
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

	sendSignal chan bool

	// RTO state variables
	// see: https://tools.ietf.org/html/rfc6298
	srtt   float64
	rttVar float64
	rto    float64
	timer  *time.Timer
}

func NewSender(dataSize, windowSize int, key string) *Sender {
	sender := Sender{
		tagWindow:   make(map[string]uint32),
		buffer:      make([]uint8, dataSize),
		flight:      make([]int64, dataSize),
		windowUpper: uint32(windowSize - 1),
		windowLower: uint32(0),
		key:         key,
		sendSignal:  make(chan bool),
		srtt:        float64(0.0),
		rttVar:      float64(0.0),
		rto:         float64(1000000),
	}

	// Initialize the sender window
	for i := 0; i < windowSize; i++ {
		tag := computeTag(uint32(i), sender.key)
		sender.tagWindow[tag] = uint32(i)
	}

	log.Println("SENDER: initial window:", sender.tagWindow)

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
	log.Println("New RTO:", s.rto)
}

func (s *Sender) ResetTimer() {
	if s.timer != nil {
		s.timer.Stop()
	} else {
		s.timer = time.NewTimer(time.Duration(s.rto))
	}

	log.Println("SENDER: waiting for", s.rto, "ns")
	s.timer.Reset(time.Nanosecond * time.Duration(s.rto))
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
	log.Println("SENDER: Timeout occurred")

	// Reset the flight time of the last unacknowledged packet
	for i := s.windowLower; i <= s.windowUpper; i++ {
		if s.flight[i] != 0 && s.buffer[i] == 0 {
			s.flight[i] = 0
			break
		}
	}
	s.sendSignal <- true
}

func (s *Sender) Send(channel *LossyChannel) bool {
	index := -1

	log.Println("SENDER: Searching for next packet to send", len(s.flight), s.windowLower, s.windowUpper)
	for i := s.windowLower; i <= s.windowUpper; i++ {
		if s.flight[i] == 0 && s.buffer[i] == 0 {
			index = int(i)
			break
		}
	}

	if index == -1 {
		log.Println("SENDER: No packets available to send")
		return false
	}

	tag := s.TagForSeq(uint32(index))

	s.flight[index] = time.Now().UnixNano()
	channel.Write(tag)
	s.ResetTimer()

	log.Println("SENDER: Sent packet", index)

	return true
}

func (s *Sender) AdvanceWindow() {
	if s.windowLower < s.windowUpper {
		tag := computeTag(s.windowLower, s.key)
		delete(s.tagWindow, tag)
		s.windowLower++
	}

	if int(s.windowUpper) < len(s.flight)-1 {
		s.windowUpper++
		tag := computeTag(s.windowUpper, s.key)
		s.tagWindow[tag] = s.windowUpper
	}
}

func (s *Sender) CalculateRTT(seq uint32) int64 {
	now := time.Now().UnixNano()
	return now - s.flight[seq]
}

func (s *Sender) Receive(inputChannel, outputChannel *LossyChannel) {
	for {
		if s.windowLower == uint32(len(s.buffer))-1 {
			log.Println("SENDER: Done receiving.")
			break
		}

		msg, err := inputChannel.Read() // this channel passes ACK structs
		if err == nil {
			ack := msg.(ACK)
			sack := ack.sack
			cack := ack.cack

			log.Println("SENDER: Received response", cack, sack)

			seq, ok := s.tagWindow[sack]
			cackSeq, _ := s.tagWindow[cack]

			// Short-circuit
			if seq == uint32(len(s.buffer)) {
				s.timer.Stop()
				break
			}

			if !ok {
				log.Println("SENDER: injection detected")
				// error! someone injected fake data
			} else {
				log.Println("SENDER: In window", seq)
				s.buffer[seq] = 1 // ACK the packet

				// Advance the window forward to the CACK
				for {
					if s.windowLower == cackSeq {
						break
					}
					log.Println("SENDER: advancing window")
					s.AdvanceWindow()
					s.sendSignal <- true
				}

				s.Acknowledge(seq)
			}
		}
	}
}

func (s *Sender) Run(outputChannel *LossyChannel) {
	for {
		if s.windowLower == uint32(len(s.buffer))-1 {
			log.Println("SENDER: Reached the end of the data")
			s.timer.Stop()
			break
		}

		ok := s.Send(outputChannel)
		if !ok { // We can't send another packet, so just wait...
			select {
			case <-s.sendSignal:
				break
			case <-s.timer.C:
				break
			}
		}
	}

	fmt.Println("Done transferring data")
}

func main() {
	windowSize := 5
	dataSize := 10
	key := string(GenerateRandomBytes(32))

	outputStream := NewLossyChannel(dataSize, 0.05, 5, 1) // 1ms
	inputStream := NewLossyChannel(dataSize, 0.05, 5, 1)  // 1ms

	receiver := NewReceiver(windowSize, key)
	sender := NewSender(dataSize, windowSize, key)

	go receiver.Run(outputStream, inputStream)
	go sender.Receive(inputStream, outputStream)
	sender.Run(outputStream)
}

package main

import "fmt"
import "crypto/rand"
import "crypto/hmac"
import "crypto/sha256"
import "encoding/binary"
import "encoding/hex"

type HashState struct {
	tagTable   map[string]uint32
	currentNum uint32
	lastNum    uint32
	key        []byte
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
		key:        GenerateRandomBytes(32),
	}

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
	topValue := s.computeTag(s.currentNum)
	s.tagTable[topValue] = s.currentNum
	s.currentNum++
}

func (s *HashState) AdvanceWindow() {
	bottomValue := s.computeTag(s.lastNum)
	_, ok := s.tagTable[bottomValue]
	if ok {
		delete(s.tagTable, bottomValue)
		s.lastNum++
		topValue := s.computeTag(s.currentNum)
		s.tagTable[topValue] = s.currentNum
		s.currentNum++
	}
}

func (s HashState) computeTag(in uint32) string {
	mac := hmac.New(sha256.New, s.key)
	inContainer := make([]byte, 4)
	binary.LittleEndian.PutUint32(inContainer, in)
	mac.Write(inContainer)
	output := mac.Sum(nil)
	return hex.EncodeToString(output[0:4])
}

func slidingWindow(state *HashState, stream chan string, out chan bool) {
	for {
		tag := <-stream
		if state.IsInWindow(tag) {
			state.AdvanceWindow()
			out <- true
		} else {
			out <- false
		}
	}
}

func main() {
	state := NewHashState(10)
	outputStream := make(chan bool)
	inputStream := make(chan string)

	go slidingWindow(state, inputStream, outputStream)
	for i := 0; i < 50; i++ {
		tag := state.computeTag(uint32(i))
		inputStream <- tag

		output := <-outputStream
		if output {
			fmt.Println("In window")
		} else {
			fmt.Println("Not in window")
		}
	}

	for i := 0; i < 50; i++ {
		tag := state.computeTag(uint32(i))
		inputStream <- tag

		output := <-outputStream
		if output {
			fmt.Println("In window")
		} else {
			fmt.Println("Not in window")
		}
	}
}

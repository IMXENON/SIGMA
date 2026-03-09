package protocol

import (
	"fmt"
)

func (s *Session) GenMsg1() ([]byte, error) {
	// Check State
	if !s.StateEq(StateInitialized) {
		return nil, fmt.Errorf("session state is not initialized")
	}
	// Call Generate Msg1
	msg1, err := s.genMsg1()
	if err != nil {
		s.SetState(StateFailed)
		return nil, fmt.Errorf("gen msg1 failed: %w", err)
	}
	// Set State to Msg1Sent
	s.SetState(StateMsg1Sent)
	return msg1, nil
}

func (s *Session) HandleMsg1AndReply(data []byte) ([]byte, error) {
	// Check State
	if !s.StateEq(StateInitialized) {
		return nil, fmt.Errorf("session state is not initialized")
	}
	// Process message
	if err := s.processMsg1(data); err != nil {
		return nil, fmt.Errorf("process msg1 failed: %w", err)
	}
	msg2, err := s.genMsg2(data)
	if err != nil {
		s.SetState(StateFailed)
		return nil, fmt.Errorf("gen msg2 failed: %w", err)
	}
	// Set State to Msg2Processed
	s.SetState(StateMsg2Sent)

	return msg2, nil
}

func (s *Session) HandleMsg2AndReply(data []byte) ([]byte, error) {
	// Check State
	if !s.StateEq(StateMsg1Sent) {
		return nil, fmt.Errorf("session state is not msg1 processed")
	}
	// Process message
	if err := s.processMsg2(data); err != nil {
		return nil, fmt.Errorf("process msg2 failed: %w", err)
	}
	msg3, err := s.genMsg3(data)
	if err != nil {
		s.SetState(StateFailed)
		return nil, fmt.Errorf("gen msg3 failed: %w", err)
	}
	// Set State to SharedSecretEstablished
	s.SetState(SharedSecretEstablished)

	return msg3, nil
}

func (s *Session) HandleMsg3(data []byte) error {
	// Check State
	if !s.StateEq(StateMsg2Sent) {
		return fmt.Errorf("session state is not msg2 processed")
	}
	// Process message
	if err := s.processMsg3(data); err != nil {
		s.SetState(StateFailed)
		return fmt.Errorf("process msg3 failed: %w", err)
	}
	// Set State to SharedSecretEstablished
	s.SetState(SharedSecretEstablished)

	return nil
}

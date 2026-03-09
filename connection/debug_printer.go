package connection

import "fmt"

// print information about the connection
func (s *SecureConn) PrintDebugRemoteSubject() {
	fmt.Printf("DEBUG: conn remote subject: %v\n", s.remoteSubject)
}

func (s *SecureConn) PrintDebugEpochKeys() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fmt.Printf("DEBUG: number of conn epoch keys: %v \n", len(s.keys))
}

// DebugGetEpochKeys returns the AEAD keys for the given epoch.
func (c *SecureConn) DebugGetEpochKeys() []uint16 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ks := make([]uint16, 0, len(c.keys))
	for k := range c.keys {
		ks = append(ks, k)
	}
	return ks
}

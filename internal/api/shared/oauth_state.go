package shared

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const oauthStateExpiry = 10 * time.Minute

type oauthStateEntry struct {
 createdAt time.Time
}

type OAuthStateStore struct {
 mu      sync.Mutex
 entries map[string]oauthStateEntry
}

func NewOAuthStateStore() *OAuthStateStore {
 store := &OAuthStateStore{
  entries: make(map[string]oauthStateEntry),
 }
 go store.cleanup()
 return store
}

func (s *OAuthStateStore) Generate() string {
 b := make([]byte, 32)
 rand.Read(b)
 state := hex.EncodeToString(b)
 s.mu.Lock()
 s.entries[state] = oauthStateEntry{createdAt: time.Now()}
 s.mu.Unlock()
 return state
}

func (s *OAuthStateStore) Validate(state string) bool {
 s.mu.Lock()
 defer s.mu.Unlock()
 entry, exists := s.entries[state]
 if !exists {
  return false
 }
 delete(s.entries, state)
 return time.Since(entry.createdAt) < oauthStateExpiry
}

func (s *OAuthStateStore) cleanup() {
 ticker := time.NewTicker(5 * time.Minute)
 for range ticker.C {
  s.mu.Lock()
  now := time.Now()
  for state, entry := range s.entries {
   if now.Sub(entry.createdAt) > oauthStateExpiry {
    delete(s.entries, state)
   }
  }
  s.mu.Unlock()
 }
}

var sharedOAuthState = NewOAuthStateStore()

func generateOAuthState() string {
 return sharedOAuthState.Generate()
}

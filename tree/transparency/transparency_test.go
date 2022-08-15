package transparency

import (
	"bytes"
	"testing"

	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/JumpPrivacy/katie/crypto/vrf/p256"
	"github.com/JumpPrivacy/katie/db"
)

func random() []byte {
	out := make([]byte, 12)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	return out
}

type memoryStore struct {
	latest string
	Data   map[uint64][]byte
	Log    logStore
	Prefix prefixStore
}

func (m *memoryStore) GetRoot() (*db.TransparencyTreeRoot, error) {
	if m.latest == "" {
		return &db.TransparencyTreeRoot{}, nil
	}
	out := &db.TransparencyTreeRoot{}
	if err := json.Unmarshal([]byte(m.latest), out); err != nil {
		return nil, err
	}
	return out, nil
}

func (m *memoryStore) SetRoot(root *db.TransparencyTreeRoot) error {
	raw, err := json.Marshal(root)
	if err != nil {
		return err
	}
	m.latest = string(raw)
	return nil
}

func (m *memoryStore) Get(key uint64) ([]byte, error) {
	out, ok := m.Data[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return out, nil
}

func (m *memoryStore) Put(key uint64, data []byte) error {
	if m.Data == nil {
		m.Data = make(map[uint64][]byte)
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	m.Data[key] = buf

	return nil
}

func (m *memoryStore) LogStore() db.LogStore {
	if m.Log == nil {
		m.Log = make(logStore)
	}
	return m.Log
}

func (m *memoryStore) PrefixStore() db.PrefixStore {
	if m.Prefix == nil {
		m.Prefix = make(prefixStore)
	}
	return m.Prefix
}

func (m *memoryStore) Commit() error { return nil }

type logStore map[int][]byte

func (ls logStore) BatchGet(keys []int) (map[int][]byte, error) {
	out := make(map[int][]byte)

	for _, key := range keys {
		if d, ok := ls[key]; ok {
			out[key] = d
		}
	}

	return out, nil
}

func (ls logStore) BatchPut(data map[int][]byte) error {
	for key, d := range data {
		buf := make([]byte, len(d))
		copy(buf, d)
		ls[key] = buf
	}
	return nil
}

type prefixStore map[uint64][]byte

func (ps prefixStore) Get(key uint64) ([]byte, error) {
	out, ok := ps[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return out, nil
}

func (ps prefixStore) Put(key uint64, data []byte) error {
	buf := make([]byte, len(data))
	copy(buf, data)
	ps[key] = buf

	return nil
}

func TestTree(t *testing.T) {
	sigPubKey, sigPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vrfEcKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vrfKey, err := p256.NewVRFSigner(vrfEcKey)
	if err != nil {
		t.Fatal(err)
	}
	vrfPub, err := p256.NewVRFVerifier(&vrfEcKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &LogConfig{sigPubKey, vrfPub}

	tree, err := NewTree(sigPrivKey, vrfKey, new(memoryStore))
	if err != nil {
		t.Fatal(err)
	}
	data := make(map[string][]byte)

	// Add initial data to tree.
	for i := 0; i < 700; i++ {
		key := fmt.Sprintf("%x", random())
		value := random()

		data[key] = value

		_, err := tree.Insert(key, value)
		if err != nil {
			t.Fatal(err)
		}
		sr, err := tree.Search(key)
		if err != nil {
			t.Fatal(err)
		} else if err := Verify(cfg, key, sr); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(sr.Value.Value, value) {
			t.Fatal("values don't match")
		}
	}

	// Overwrite some entries.
	for i := 0; i < 10; i++ {
		j := 0
		for key := range data {
			if j > 10 {
				break
			}
			j++

			value := random()
			data[key] = value

			_, err := tree.Insert(key, value)
			if err != nil {
				t.Fatal(err)
			}
			sr, err := tree.Search(key)
			if err != nil {
				t.Fatal(err)
			} else if err := Verify(cfg, key, sr); err != nil {
				t.Fatal(err)
			} else if !bytes.Equal(sr.Value.Value, value) {
				t.Fatal("values don't match")
			}
		}
	}

	// Search for every entry.
	for key, value := range data {
		sr, err := tree.Search(key)
		if err != nil {
			t.Fatal(err)
		} else if err := Verify(cfg, key, sr); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(sr.Value.Value, value) {
			t.Fatal("values don't match")
		}
	}

	// Search for some keys that don't exist.
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("%x", random())

		sr, err := tree.Search(key)
		if err != nil {
			t.Fatal(err)
		} else if err := Verify(cfg, key, sr); err != nil {
			t.Fatal(err)
		} else if sr.Value != nil {
			t.Fatal("expected nil value")
		}
	}
}

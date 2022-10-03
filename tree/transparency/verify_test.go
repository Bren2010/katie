package transparency

import (
	"testing"
)

func TestProofGuide(t *testing.T) {
	guide := newProofGuide(700)
	ids := make([]uint64, 0)
	for {
		done, err := guide.done()
		if err != nil {
			t.Fatal(err)
		} else if done {
			break
		}
		id := guide.next()

		ids = append(ids, id)

		if id < 399 {
			guide.insert(id, 0)
		} else {
			guide.insert(id, 1)
		}
	}
	if ids[guide.final()] != 399 {
		t.Fatal("wrong result returned")
	}

	guide = newProofGuide(700)
	for {
		done, err := guide.done()
		if err != nil {
			t.Fatal(err)
		} else if done {
			break
		}
		id := guide.next()

		guide.insert(id, -1)
	}
	if guide.final() != -1 {
		t.Fatal("wrong result returned")
	}
}

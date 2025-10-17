package transparency

import (
	"errors"
	"time"

	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

type Verifier struct {
	config *structs.PublicConfig

	auditor    *structs.AuditorTreeHead
	log        *log.Verifier
	logEntries map[uint64]structs.LogEntry
}

func NewVerifier(config *structs.PublicConfig) *Verifier {
	return &Verifier{
		config: config,

		log: log.NewVerifier(config.Suite),
	}
}

func (v *Verifier) Last() *uint64 { return v.log.Last() }

func (v *Verifier) verifyTreeHead(fth *structs.FullTreeHead) (uint64, *uint64, *uint64, error) {
	last := v.Last()

	if fth.TreeHead == nil {
		if last == nil {
			return 0, nil, nil, errors.New("no tree head provided")
		}
		entry, ok := v.logEntries[*last-1]
		if !ok {
			return 0, nil, nil, errors.New("expected log entry not found")
		}
		now := uint64(time.Now().UnixMilli())
		if now < entry.Timestamp && entry.Timestamp-now > v.config.MaxAhead {
			return 0, nil, nil, errors.New("rightmost timestamp is too far ahead of local clock")
		} else if now > entry.Timestamp && now-entry.Timestamp > v.config.MaxBehind {
			return 0, nil, nil, errors.New("rightmost timestamp is too far behind local clock")
		}
		return *last, nil, nil, nil
	}

	if last != nil && fth.TreeHead.TreeSize <= *last {
		return 0, nil, nil, errors.New("received tree head has size less than or equal to what was advertised")
	}
	var nP *uint64
	if fth.AuditorTreeHead != nil {
		if last != nil && v.auditor.TreeSize < v.config.AuditorStartPos {
			return 0, nil, nil, errors.New("auditor start position does not overlap with previous auditor")
		} else if fth.AuditorTreeHead.TreeSize > fth.TreeHead.TreeSize {
			return 0, nil, nil, errors.New("auditor tree size greater than service operator tree size")
		}
		nP = &fth.AuditorTreeHead.TreeSize
	}

	return fth.TreeHead.TreeSize, nP, last, nil
}

func (v *Verifier) VerifySearch(req *structs.SearchRequest, res *structs.SearchResponse) error {
	if req.Last != v.Last() {
		return errors.New("request does not match verifier state")
	}
	n, nP, m, err := v.verifyTreeHead(&res.FullTreeHead)
	if err != nil {
		return err
	}

	handle := newReceivedProofHandler(v.config.Suite, res.Search)
	provider := newDataProvider(v.config.Suite, handle)

	if err := updateView(v.config, n, m, provider); err != nil {
		return err
	}
	if req.Version == nil {
		_, _, err = greatestVersionSearch(v.config, *res.Version, n, provider)
	} else {
		_, _, err = fixedVersionSearch(v.config, *req.Version, n, provider) // TODO: contact monitoring
	}
	if err != nil {
		return err
	}

	result, err := provider.Finish(n, nP, m)
	if err != nil {
		return err
	}
	return v.finish(result, &res.FullTreeHead)
}

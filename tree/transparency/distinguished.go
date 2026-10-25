package transparency

import (
	"context"
	"errors"

	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// WalkDistinguished returns a proof of which log entries are the recent
// distinguished log entries, according to the application's definition of
// "recent" in the Transparency Log's config.
func (t *Tree) WalkDistinguished(
	ctx context.Context,
	req *structs.DistinguishedRequest,
) (*structs.DistinguishedResponse, error) {
	if t.config.Recent == nil {
		return nil, errors.New("walking distinguished log entries is not supported")
	}
	fth, err := t.fullTreeHead(req.Last)
	if err != nil {
		return nil, err
	} else if req.Stop != nil && *req.Stop >= t.n() {
		return nil, errors.New("advertised stopping position is greater than tree size")
	}

	// Execute the algorithm to update the user's view of the tree, and then
	// walk the recent distinguished log entries.
	handle := algorithms.NewProducedProofHandle(t.config.Suite, t.tx, nil)
	provider := algorithms.NewDataProvider(t.config.Suite, handle)
	if err := t.updateView(req.Last, provider); err != nil {
		return nil, err
	}
	_, err = algorithms.WalkDistinguished(t.config.Public(), req.Stop, t.config.Recent, t.n(), provider)
	if err != nil {
		return nil, err
	}

	combinedProof, err := provider.Output(t.n(), nP(fth), req.Last)
	if err != nil {
		return nil, err
	}
	return &structs.DistinguishedResponse{
		FullTreeHead:  *fth,
		Distinguished: *combinedProof,
	}, nil
}

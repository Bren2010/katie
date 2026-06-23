package managed

import (
	"context"

	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/transparency/auditor/wire"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// ManagedLog wraps a Transparency Log implementation and signs new values that
// are submitted through Update before they are sequenced.
//
// To be clear, this code is run by a Service Operator whose Transparency Log is
// hosted by a Third-Party Manager.
type ManagedLog struct {
	log wire.Interface
	tx  db.ManagedLogStore
}

func NewManagedLog(log wire.Interface, tx db.ManagedLogStore) *ManagedLog {
	return &ManagedLog{log: log, tx: tx}
}

func (ml *ManagedLog) Search(
	ctx context.Context,
	req *structs.SearchRequest,
) (*structs.SearchResponse, error) {
	return ml.log.Search(ctx, req)
}

func (ml *ManagedLog) ContactMonitor(
	ctx context.Context,
	req *structs.ContactMonitorRequest,
) (*structs.ContactMonitorResponse, error) {
	return ml.log.ContactMonitor(ctx, req)
}

func (ml *ManagedLog) OwnerInit(
	ctx context.Context,
	req *structs.OwnerInitRequest,
) (*structs.OwnerInitResponse, error) {
	return ml.log.OwnerInit(ctx, req)
}

func (ml *ManagedLog) OwnerMonitor(
	ctx context.Context,
	req *structs.OwnerMonitorRequest,
) (*structs.OwnerMonitorResponse, error) {
	return ml.log.OwnerMonitor(ctx, req)
}

func (ml *ManagedLog) Update(
	ctx context.Context,
	req *structs.UpdateRequest,
) (<-chan wire.UpdateResponse, error) {
	panic("not implemented")
}

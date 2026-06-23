// Package wire defines interfaces that are necessary for wire-level
// compatibility between this or other Transparency Logs.
package wire

import (
	"context"

	"github.com/Bren2010/katie/tree/transparency/structs"
)

// Interface is the remotely accessible interface of a Transparency Log. This
// interface can be implemented by any suitable transport protocol for use in KT
// proof verification.
type Interface interface {
	Search(ctx context.Context, req *structs.SearchRequest) (*structs.SearchResponse, error)
	ContactMonitor(ctx context.Context, req *structs.ContactMonitorRequest) (*structs.ContactMonitorResponse, error)
	OwnerInit(ctx context.Context, req *structs.OwnerInitRequest) (*structs.OwnerInitResponse, error)
	OwnerMonitor(ctx context.Context, req *structs.OwnerMonitorRequest) (*structs.OwnerMonitorResponse, error)
	Update(ctx context.Context, req *structs.UpdateRequest) (<-chan UpdateResponse, error)
}

// ManagerInterface is the interface implemented by a Third-Party Manager.
type ManagerInterface interface {
	Interface

	// ManagerUpdate is the same as the normal Update operation, except it also
	// takes in signatures from the Service Operator over each value.
	ManagerUpdate(ctx context.Context, req *structs.ManagerUpdateRequest) (<-chan UpdateResponse, error)
}

// UpdateResponse wraps the output of an Update operation, which is either a
// struct.UpdateResponse or an error.
type UpdateResponse struct {
	Out *structs.UpdateResponse
	Err error
}

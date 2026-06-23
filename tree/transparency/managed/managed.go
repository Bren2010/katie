// Package managed implements the logic for the Service Operator portion of a
// Transparency Log with a Third-Party Manager.
package managed

import (
	"bytes"
	"context"
	"errors"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/tree/transparency/structs"
	"github.com/Bren2010/katie/tree/transparency/wire"
)

// ManagedLog wraps a Transparency Log implementation and signs new values that
// are submitted through Update before they are sequenced.
//
// This code is run by a Service Operator whose Transparency Log is hosted by a
// Third-Party Manager. All operations except Update are direct proxies.
type ManagedLog struct {
	config *structs.PublicConfig
	log    wire.ManagerInterface
	tx     db.ManagedLogStore
	priv   suites.SigningPrivateKey
}

var _ wire.Interface = &ManagedLog{}

func NewManagedLog(
	config *structs.PublicConfig,
	log wire.ManagerInterface,
	tx db.ManagedLogStore,
	priv suites.SigningPrivateKey,
) (*ManagedLog, error) {
	if config.Mode != structs.ThirdPartyManagement {
		return nil, errors.New("transparency log is not configured with third party manager")
	} else if config.LeafPublicKey == nil {
		return nil, errors.New("no leaf public key provided in configuration")
	} else if !bytes.Equal(config.LeafPublicKey.Bytes(), priv.Public().Bytes()) {
		return nil, errors.New("private key does not match leaf public key")
	}
	return &ManagedLog{config, log, tx, priv}, nil
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
	prev, err := ml.tx.IncrementGreatestVersion(req.Label, len(req.Values))
	if err != nil {
		return nil, err
	}

	// Sign new versions of the label.
	values := make([]structs.UpdateValue, len(req.Values))
	for i, val := range req.Values {
		tbs, err := structs.Marshal(&structs.UpdateTBS{
			Config:  ml.config,
			Label:   req.Label,
			Version: uint32(prev + 1 + i),
			Value:   val.Value,
		})
		if err != nil {
			return nil, err
		}
		sig, err := ml.priv.Sign(tbs)
		if err != nil {
			return nil, err
		}
		values[i] = structs.UpdateValue{
			Value:        val.Value,
			UpdateSuffix: structs.UpdateSuffix{Signature: sig},
		}
	}

	// Submit signed, new versions to manager to sequencing.
	return ml.log.ManagerUpdate(ctx, &structs.ManagerUpdateRequest{
		Last: req.Last,

		Label:           req.Label,
		GreatestVersion: req.GreatestVersion,
		SignedVersion:   uint32(prev + 1),
		Values:          values,
	})
}

package structs

import (
	"bytes"
	"io"
)

type SearchRequest struct {
	Last *uint64

	Label   []byte
	Version *uint32
}

func NewSearchRequest(buf *bytes.Buffer) (*SearchRequest, error) {
	last, err := readOptionalNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	label, err := readBytes[uint8](buf)
	if err != nil {
		return nil, err
	}
	version, err := readOptionalNumeric[uint32](buf)
	if err != nil {
		return nil, err
	}
	return &SearchRequest{last, label, version}, nil
}

func (sr *SearchRequest) Marshal(buf *bytes.Buffer) error {
	writeOptionalNumeric(buf, sr.Last)
	if err := writeBytes[uint8](buf, sr.Label, "label"); err != nil {
		return err
	}
	writeOptionalNumeric(buf, sr.Version)
	return nil
}

type SearchResponse struct {
	FullTreeHead FullTreeHead

	Version *uint32
	Opening []byte
	Value   UpdateValue

	BinaryLadder []BinaryLadderStep
	Search       CombinedTreeProof
}

func NewSearchResponse(
	config *PublicConfig,
	req *SearchRequest,
	buf *bytes.Buffer,
) (*SearchResponse, error) {
	fth, err := NewFullTreeHead(config, buf)
	if err != nil {
		return nil, err
	}

	var version *uint32
	if req.Version == nil {
		versionActual, err := readNumeric[uint32](buf)
		if err != nil {
			return nil, err
		}
		version = &versionActual
	}
	opening := make([]byte, config.Suite.CommitmentOpeningSize())
	if _, err := io.ReadFull(buf, opening); err != nil {
		return nil, err
	}
	value, err := NewUpdateValue(config, buf)
	if err != nil {
		return nil, err
	}

	steps, err := readFuncSlice[uint8](buf, func(buf *bytes.Buffer) (*BinaryLadderStep, error) {
		return NewBinaryLadderStep(config.Suite, buf)
	})
	if err != nil {
		return nil, err
	}
	search, err := NewCombinedTreeProof(config.Suite, buf)
	if err != nil {
		return nil, err
	}

	return &SearchResponse{*fth, version, opening, *value, steps, *search}, nil
}

func (sr *SearchResponse) Marshal(buf *bytes.Buffer) error {
	if err := sr.FullTreeHead.Marshal(buf); err != nil {
		return err
	}

	if sr.Version != nil {
		writeNumeric(buf, *sr.Version)
	}
	buf.Write(sr.Opening)
	if err := sr.Value.Marshal(buf); err != nil {
		return err
	}

	if err := writeMarshalSlice[uint8](buf, sr.BinaryLadder, "binary ladder"); err != nil {
		return err
	}
	return sr.Search.Marshal(buf)
}

type MonitorMapEntry struct {
	Position uint64
	Version  uint32
}

func NewMonitorMapEntry(buf *bytes.Buffer) (*MonitorMapEntry, error) {
	position, err := readNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	version, err := readNumeric[uint32](buf)
	if err != nil {
		return nil, err
	}
	return &MonitorMapEntry{position, version}, nil
}

func (mme *MonitorMapEntry) Marshal(buf *bytes.Buffer) error {
	writeNumeric(buf, mme.Position)
	writeNumeric(buf, mme.Version)
	return nil
}

type ContactMonitorRequest struct {
	Last *uint64

	Label   []byte
	Entries []MonitorMapEntry
}

func NewContactMonitorRequest(buf *bytes.Buffer) (*ContactMonitorRequest, error) {
	last, err := readOptionalNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	label, err := readBytes[uint8](buf)
	if err != nil {
		return nil, err
	}
	entries, err := readFuncSlice[uint8](buf, NewMonitorMapEntry)
	if err != nil {
		return nil, err
	}
	return &ContactMonitorRequest{last, label, entries}, nil
}

func (cmr *ContactMonitorRequest) Marshal(buf *bytes.Buffer) error {
	writeOptionalNumeric(buf, cmr.Last)
	if err := writeBytes[uint8](buf, cmr.Label, "label"); err != nil {
		return err
	}
	return writeMarshalSlice[uint8](buf, cmr.Entries, "monitoring map")
}

type ContactMonitorResponse struct {
	FullTreeHead FullTreeHead
	Monitor      CombinedTreeProof
}

func NewContactMonitorResponse(
	config *PublicConfig,
	buf *bytes.Buffer,
) (*ContactMonitorResponse, error) {
	fth, err := NewFullTreeHead(config, buf)
	if err != nil {
		return nil, err
	}
	monitor, err := NewCombinedTreeProof(config.Suite, buf)
	if err != nil {
		return nil, err
	}
	return &ContactMonitorResponse{*fth, *monitor}, nil
}

func (cmr *ContactMonitorResponse) Marshal(buf *bytes.Buffer) error {
	if err := cmr.FullTreeHead.Marshal(buf); err != nil {
		return err
	}
	return cmr.Monitor.Marshal(buf)
}

type OwnerInitRequest struct {
	Last *uint64

	Label []byte
	Start uint64
}

func NewOwnerInitRequest(buf *bytes.Buffer) (*OwnerInitRequest, error) {
	last, err := readOptionalNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	label, err := readBytes[uint8](buf)
	if err != nil {
		return nil, err
	}
	start, err := readNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	return &OwnerInitRequest{last, label, start}, nil
}

func (oir *OwnerInitRequest) Marshal(buf *bytes.Buffer) error {
	writeOptionalNumeric(buf, oir.Last)
	if err := writeBytes[uint8](buf, oir.Label, "label"); err != nil {
		return err
	}
	writeNumeric(buf, oir.Start)
	return nil
}

type OwnerInitResponse struct {
	FullTreeHead FullTreeHead

	GreatestVersions []uint32
	BinaryLadder     []BinaryLadderStep
	Init             CombinedTreeProof
}

func NewOwnerInitResponse(
	config *PublicConfig,
	buf *bytes.Buffer,
) (*OwnerInitResponse, error) {
	fth, err := NewFullTreeHead(config, buf)
	if err != nil {
		return nil, err
	}
	versions, err := readNumericSlice[uint8, uint32](buf)
	if err != nil {
		return nil, err
	}
	steps, err := readFuncSlice[uint16](buf, func(buf *bytes.Buffer) (*BinaryLadderStep, error) {
		return NewBinaryLadderStep(config.Suite, buf)
	})
	if err != nil {
		return nil, err
	}
	init, err := NewCombinedTreeProof(config.Suite, buf)
	if err != nil {
		return nil, err
	}
	return &OwnerInitResponse{*fth, versions, steps, *init}, nil
}

func (oir *OwnerInitResponse) Marshal(buf *bytes.Buffer) error {
	if err := oir.FullTreeHead.Marshal(buf); err != nil {
		return err
	} else if err := writeNumericSlice[uint8](buf, oir.GreatestVersions, "versions"); err != nil {
		return err
	} else if err := writeMarshalSlice[uint16](buf, oir.BinaryLadder, "binary ladder"); err != nil {
		return err
	}
	return oir.Init.Marshal(buf)
}

type OwnerMonitorRequest struct {
	Last *uint64

	Label           []byte
	Entries         []MonitorMapEntry
	Start           uint64
	GreatestVersion uint32
}

func NewOwnerMonitorRequest(buf *bytes.Buffer) (*OwnerMonitorRequest, error) {
	last, err := readOptionalNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	label, err := readBytes[uint8](buf)
	if err != nil {
		return nil, err
	}
	entries, err := readFuncSlice[uint8](buf, NewMonitorMapEntry)
	if err != nil {
		return nil, err
	}
	start, err := readNumeric[uint64](buf)
	if err != nil {
		return nil, err
	}
	greatestVersion, err := readNumeric[uint32](buf)
	if err != nil {
		return nil, err
	}
	return &OwnerMonitorRequest{last, label, entries, start, greatestVersion}, nil
}

func (omr *OwnerMonitorRequest) Marshal(buf *bytes.Buffer) error {
	writeOptionalNumeric(buf, omr.Last)
	if err := writeBytes[uint8](buf, omr.Label, "label"); err != nil {
		return err
	} else if err := writeMarshalSlice[uint8](buf, omr.Entries, "monitoring map"); err != nil {
		return err
	}
	writeNumeric(buf, omr.Start)
	writeNumeric(buf, omr.GreatestVersion)
	return nil
}

type OwnerMonitorResponse struct {
	FullTreeHead FullTreeHead
	Monitor      CombinedTreeProof
}

func NewOwnerMonitorResponse(
	config *PublicConfig,
	buf *bytes.Buffer,
) (*OwnerMonitorResponse, error) {
	fth, err := NewFullTreeHead(config, buf)
	if err != nil {
		return nil, err
	}
	monitor, err := NewCombinedTreeProof(config.Suite, buf)
	if err != nil {
		return nil, err
	}
	return &OwnerMonitorResponse{*fth, *monitor}, nil
}

func (omr *OwnerMonitorResponse) Marshal(buf *bytes.Buffer) error {
	if err := omr.FullTreeHead.Marshal(buf); err != nil {
		return err
	}
	return omr.Monitor.Marshal(buf)
}

package transparency

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/Bren2010/katie/db"
)

func getLabelInfo(tx db.TransparencyStore, label []byte) ([]uint64, error) {
	raw, err := tx.GetLabelInfo(label)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(raw)

	info := make([]uint64, 0)
	for {
		pos, err := binary.ReadUvarint(buf)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		info = append(info, pos)
	}

	for i := 1; i < len(info); i++ {
		info[i] += info[i-1]
	}
	return info, nil
}

func setLabelInfo(tx db.TransparencyStore, label []byte, info []uint64) error {
	for i := len(info) - 1; i > 0; i-- {
		if info[i] < info[i-1] {
			return errors.New("list of label-version positions is not monotonic")
		}
		info[i] -= info[i-1]
	}

	buf := &bytes.Buffer{}
	for _, pos := range info {
		temp := make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(temp, pos)
		buf.Write(temp[:n])
	}

	return tx.SetLabelInfo(label, buf.Bytes())
}

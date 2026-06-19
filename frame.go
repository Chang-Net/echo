package echo

import (
	"encoding/binary"
	"fmt"
	"io"
)

func ReadFrame(r io.Reader) (version uint8, data []byte, err error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}

	dataLen := binary.BigEndian.Uint16(header[0:2])
	version = header[2]

	if dataLen == 0 {
		return version, nil, nil
	}

	payload := make([]byte, dataLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}

	return version, payload, nil
}

func Encode(version uint8, data []byte) ([]byte, error) {
	dataLen := len(data)
	if dataLen > 65535 {
		return nil, fmt.Errorf("payload too large for echo frame")
	}

	frame := make([]byte, 3+dataLen)
	binary.BigEndian.PutUint16(frame[0:2], uint16(dataLen))
	frame[2] = version
	copy(frame[3:], data)

	return frame, nil
}

func Decode(frame []byte) (version uint8, data []byte, err error) {
	if len(frame) < 3 {
		return 0, nil, fmt.Errorf("invalid echo header")
	}

	dataLen := binary.BigEndian.Uint16(frame[0:2])
	version = frame[2]

	if len(frame) < 3+int(dataLen) {
		return 0, nil, fmt.Errorf("incomplete echo frame")
	}

	return version, frame[3 : 3+dataLen], nil
}

package soroauth

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The attestation object and the COSE key inside it are CBOR (WebAuthn Level 2
// §6.5.4 and RFC 9052). This is the small, strict subset of RFC 8949 they
// need, written here rather than imported because the module takes no
// dependency beyond go-stellar-sdk.
//
// Strict on purpose, because this decodes bytes an enrolling client chose:
//
//   - definite lengths only (CTAP2 canonical CBOR forbids indefinite ones);
//   - no tags, no floats, no simple values other than true, false and null;
//   - integers must fit an int64;
//   - duplicate map keys are refused rather than resolved, so two parties
//     cannot read different values out of one object;
//   - nesting is capped, and every length is checked against the bytes that
//     remain before anything is allocated, so a header claiming a huge array
//     cannot make the decoder allocate it.

const cborMaxDepth = 8

// cborPair is one entry of a CBOR map, in encoded order.
type cborPair struct {
	key, value any
}

// cborMap is a decoded CBOR map. Keys are int64 or string.
type cborMap []cborPair

// get returns the value under key (an int64 or a string).
func (m cborMap) get(key any) (any, bool) {
	for _, p := range m {
		if p.key == key {
			return p.value, true
		}
	}
	return nil, false
}

var errCBOR = errors.New("malformed CBOR")

func cborErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errCBOR, fmt.Sprintf(format, args...))
}

// decodeCBOR decodes the first data item in data and returns it with the bytes
// that follow. Values are int64, []byte, string, []any, cborMap, bool or nil.
func decodeCBOR(data []byte) (value any, rest []byte, err error) {
	return decodeCBORItem(data, 0)
}

func decodeCBORItem(data []byte, depth int) (any, []byte, error) {
	if depth > cborMaxDepth {
		return nil, nil, cborErr("nesting deeper than %d", cborMaxDepth)
	}
	if len(data) == 0 {
		return nil, nil, cborErr("unexpected end of data")
	}
	major := data[0] >> 5
	info := data[0] & 0x1f
	data = data[1:]

	var arg uint64
	switch {
	case info < 24:
		arg = uint64(info)
	case info >= 24 && info <= 27:
		size := 1 << (info - 24)
		if len(data) < size {
			return nil, nil, cborErr("truncated %d-byte argument", size)
		}
		switch size {
		case 1:
			arg = uint64(data[0])
		case 2:
			arg = uint64(binary.BigEndian.Uint16(data))
		case 4:
			arg = uint64(binary.BigEndian.Uint32(data))
		default:
			arg = binary.BigEndian.Uint64(data)
		}
		data = data[size:]
	default:
		return nil, nil, cborErr("additional information %d (indefinite length or reserved) is not allowed", info)
	}

	switch major {
	case 0:
		if arg > 1<<63-1 {
			return nil, nil, cborErr("unsigned integer %d does not fit an int64", arg)
		}
		return int64(arg), data, nil
	case 1:
		if arg > 1<<63-1 {
			return nil, nil, cborErr("negative integer does not fit an int64")
		}
		return -1 - int64(arg), data, nil
	case 2, 3:
		if arg > uint64(len(data)) {
			return nil, nil, cborErr("string of %d bytes with %d remaining", arg, len(data))
		}
		body := data[:arg]
		if major == 2 {
			return append([]byte(nil), body...), data[arg:], nil
		}
		return string(body), data[arg:], nil
	case 4:
		if arg > uint64(len(data)) {
			return nil, nil, cborErr("array of %d items with %d bytes remaining", arg, len(data))
		}
		items := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			var item any
			var err error
			item, data, err = decodeCBORItem(data, depth+1)
			if err != nil {
				return nil, nil, err
			}
			items = append(items, item)
		}
		return items, data, nil
	case 5:
		if arg > uint64(len(data)) {
			return nil, nil, cborErr("map of %d entries with %d bytes remaining", arg, len(data))
		}
		m := make(cborMap, 0, arg)
		for i := uint64(0); i < arg; i++ {
			var k, v any
			var err error
			k, data, err = decodeCBORItem(data, depth+1)
			if err != nil {
				return nil, nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, nil, cborErr("map key of type %T; only integer and text keys are allowed", k)
			}
			if _, dup := m.get(k); dup {
				return nil, nil, cborErr("duplicate map key %v", k)
			}
			v, data, err = decodeCBORItem(data, depth+1)
			if err != nil {
				return nil, nil, err
			}
			m = append(m, cborPair{key: k, value: v})
		}
		return m, data, nil
	case 7:
		switch info {
		case 20:
			return false, data, nil
		case 21:
			return true, data, nil
		case 22:
			return nil, data, nil
		}
		return nil, nil, cborErr("simple or float value %d is not allowed", info)
	}
	return nil, nil, cborErr("major type %d (tag) is not allowed", major)
}

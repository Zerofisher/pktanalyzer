// Package stream provides HPACK header compression for HTTP/2 (RFC 7541)
package stream

import (
	"errors"
	"fmt"
)

// HPACK errors
var (
	ErrHPACKInvalidIndex      = errors.New("hpack: invalid index")
	ErrHPACKInvalidEncoding   = errors.New("hpack: invalid encoding")
	ErrHPACKStringTooLong     = errors.New("hpack: string too long")
	ErrHPACKTableSizeOverflow = errors.New("hpack: dynamic table size overflow")
)

// HPACKHeader represents a decoded HTTP/2 header
type HPACKHeader struct {
	Name  string
	Value string
}

// HPACKDecoder decodes HPACK encoded headers
type HPACKDecoder struct {
	dynamicTable     []HPACKHeader
	maxTableSize     uint32
	currentTableSize uint32
}

// NewHPACKDecoder creates a new HPACK decoder
func NewHPACKDecoder(maxTableSize uint32) *HPACKDecoder {
	return &HPACKDecoder{
		dynamicTable: make([]HPACKHeader, 0),
		maxTableSize: maxTableSize,
	}
}

// DefaultHPACKDecoder creates a decoder with default settings (4096 bytes)
func DefaultHPACKDecoder() *HPACKDecoder {
	return NewHPACKDecoder(4096)
}

// Decode decodes HPACK encoded data into headers
func (d *HPACKDecoder) Decode(data []byte) ([]HPACKHeader, error) {
	var headers []HPACKHeader
	offset := 0

	for offset < len(data) {
		firstByte := data[offset]

		if firstByte&0x80 != 0 {
			// Indexed Header Field (7.1)
			// Format: 1xxxxxxx
			header, consumed, err := d.decodeIndexed(data[offset:])
			if err != nil {
				return headers, err
			}
			headers = append(headers, header)
			offset += consumed
		} else if firstByte&0x40 != 0 {
			// Literal Header Field with Incremental Indexing (7.2.1)
			// Format: 01xxxxxx
			header, consumed, err := d.decodeLiteralIncremental(data[offset:])
			if err != nil {
				return headers, err
			}
			headers = append(headers, header)
			offset += consumed
		} else if firstByte&0x20 != 0 {
			// Dynamic Table Size Update (7.3)
			// Format: 001xxxxx
			consumed, err := d.decodeDynamicTableSizeUpdate(data[offset:])
			if err != nil {
				return headers, err
			}
			offset += consumed
		} else {
			// Literal Header Field without Indexing (7.2.2) - 0000xxxx
			// or Literal Header Field Never Indexed (7.2.3) - 0001xxxx
			header, consumed, err := d.decodeLiteralWithoutIndexing(data[offset:])
			if err != nil {
				return headers, err
			}
			headers = append(headers, header)
			offset += consumed
		}
	}

	return headers, nil
}

// decodeIndexed decodes an indexed header field
func (d *HPACKDecoder) decodeIndexed(data []byte) (HPACKHeader, int, error) {
	index, consumed, err := decodeInteger(data, 7)
	if err != nil {
		return HPACKHeader{}, 0, err
	}

	if index == 0 {
		return HPACKHeader{}, 0, ErrHPACKInvalidIndex
	}

	header, err := d.getHeader(int(index))
	if err != nil {
		return HPACKHeader{}, 0, err
	}

	return header, consumed, nil
}

// decodeLiteralIncremental decodes a literal header field with incremental indexing
func (d *HPACKDecoder) decodeLiteralIncremental(data []byte) (HPACKHeader, int, error) {
	offset := 0

	// Get index (6-bit prefix)
	index, consumed, err := decodeInteger(data, 6)
	if err != nil {
		return HPACKHeader{}, 0, err
	}
	offset += consumed

	var name, value string

	if index == 0 {
		// New name
		name, consumed, err = decodeString(data[offset:])
		if err != nil {
			return HPACKHeader{}, 0, err
		}
		offset += consumed
	} else {
		// Indexed name
		header, err := d.getHeader(int(index))
		if err != nil {
			return HPACKHeader{}, 0, err
		}
		name = header.Name
	}

	// Decode value
	value, consumed, err = decodeString(data[offset:])
	if err != nil {
		return HPACKHeader{}, 0, err
	}
	offset += consumed

	header := HPACKHeader{Name: name, Value: value}

	// Add to dynamic table
	d.addHeader(header)

	return header, offset, nil
}

// decodeLiteralWithoutIndexing decodes a literal header without indexing
func (d *HPACKDecoder) decodeLiteralWithoutIndexing(data []byte) (HPACKHeader, int, error) {
	offset := 0

	// Get index (4-bit prefix)
	index, consumed, err := decodeInteger(data, 4)
	if err != nil {
		return HPACKHeader{}, 0, err
	}
	offset += consumed

	var name, value string

	if index == 0 {
		// New name
		name, consumed, err = decodeString(data[offset:])
		if err != nil {
			return HPACKHeader{}, 0, err
		}
		offset += consumed
	} else {
		// Indexed name
		header, err := d.getHeader(int(index))
		if err != nil {
			return HPACKHeader{}, 0, err
		}
		name = header.Name
	}

	// Decode value
	value, consumed, err = decodeString(data[offset:])
	if err != nil {
		return HPACKHeader{}, 0, err
	}
	offset += consumed

	return HPACKHeader{Name: name, Value: value}, offset, nil
}

// decodeDynamicTableSizeUpdate handles dynamic table size update
func (d *HPACKDecoder) decodeDynamicTableSizeUpdate(data []byte) (int, error) {
	newSize, consumed, err := decodeInteger(data, 5)
	if err != nil {
		return 0, err
	}

	if newSize > uint64(d.maxTableSize) {
		return 0, ErrHPACKTableSizeOverflow
	}

	d.setMaxTableSize(uint32(newSize))
	return consumed, nil
}

// getHeader returns a header from the combined static/dynamic table
func (d *HPACKDecoder) getHeader(index int) (HPACKHeader, error) {
	if index <= 0 {
		return HPACKHeader{}, ErrHPACKInvalidIndex
	}

	if index <= len(hpackStaticTable) {
		return hpackStaticTable[index-1], nil
	}

	dynIndex := index - len(hpackStaticTable) - 1
	if dynIndex >= len(d.dynamicTable) {
		return HPACKHeader{}, ErrHPACKInvalidIndex
	}

	return d.dynamicTable[dynIndex], nil
}

// addHeader adds a header to the dynamic table
func (d *HPACKDecoder) addHeader(header HPACKHeader) {
	entrySize := uint32(len(header.Name) + len(header.Value) + 32) // 32 byte overhead per RFC

	// Evict entries to make room
	for d.currentTableSize+entrySize > d.maxTableSize && len(d.dynamicTable) > 0 {
		last := d.dynamicTable[len(d.dynamicTable)-1]
		d.currentTableSize -= uint32(len(last.Name) + len(last.Value) + 32)
		d.dynamicTable = d.dynamicTable[:len(d.dynamicTable)-1]
	}

	// Only add if it fits
	if entrySize <= d.maxTableSize {
		// Insert at the beginning (FIFO)
		d.dynamicTable = append([]HPACKHeader{header}, d.dynamicTable...)
		d.currentTableSize += entrySize
	}
}

// setMaxTableSize updates the maximum table size and evicts entries if necessary
func (d *HPACKDecoder) setMaxTableSize(size uint32) {
	d.maxTableSize = size
	for d.currentTableSize > d.maxTableSize && len(d.dynamicTable) > 0 {
		last := d.dynamicTable[len(d.dynamicTable)-1]
		d.currentTableSize -= uint32(len(last.Name) + len(last.Value) + 32)
		d.dynamicTable = d.dynamicTable[:len(d.dynamicTable)-1]
	}
}

// decodeInteger decodes an HPACK integer (RFC 7541 Section 5.1)
func decodeInteger(data []byte, prefixBits int) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, ErrHPACKInvalidEncoding
	}

	mask := byte((1 << prefixBits) - 1)
	value := uint64(data[0] & mask)

	if value < uint64(mask) {
		return value, 1, nil
	}

	// Multi-byte integer
	m := uint64(0)
	for i := 1; i < len(data); i++ {
		b := data[i]
		value += uint64(b&0x7f) << m
		m += 7

		if b&0x80 == 0 {
			return value, i + 1, nil
		}

		if m > 63 {
			return 0, 0, ErrHPACKInvalidEncoding
		}
	}

	return 0, 0, ErrHPACKInvalidEncoding
}

// decodeString decodes an HPACK string (RFC 7541 Section 5.2)
func decodeString(data []byte) (string, int, error) {
	if len(data) == 0 {
		return "", 0, ErrHPACKInvalidEncoding
	}

	huffman := data[0]&0x80 != 0
	length, consumed, err := decodeInteger(data, 7)
	if err != nil {
		return "", 0, err
	}

	if uint64(len(data))-uint64(consumed) < length {
		return "", 0, ErrHPACKInvalidEncoding
	}

	stringData := data[consumed : consumed+int(length)]

	var result string
	if huffman {
		result, err = huffmanDecode(stringData)
		if err != nil {
			return "", 0, err
		}
	} else {
		result = string(stringData)
	}

	return result, consumed + int(length), nil
}

// HPACK Static Table (RFC 7541 Appendix A)
var hpackStaticTable = []HPACKHeader{
	{":authority", ""},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
	{":status", "206"},
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charset", ""},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", ""},
	{"accept-ranges", ""},
	{"accept", ""},
	{"access-control-allow-origin", ""},
	{"age", ""},
	{"allow", ""},
	{"authorization", ""},
	{"cache-control", ""},
	{"content-disposition", ""},
	{"content-encoding", ""},
	{"content-language", ""},
	{"content-length", ""},
	{"content-location", ""},
	{"content-range", ""},
	{"content-type", ""},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"expect", ""},
	{"expires", ""},
	{"from", ""},
	{"host", ""},
	{"if-match", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"if-range", ""},
	{"if-unmodified-since", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"max-forwards", ""},
	{"proxy-authenticate", ""},
	{"proxy-authorization", ""},
	{"range", ""},
	{"referer", ""},
	{"refresh", ""},
	{"retry-after", ""},
	{"server", ""},
	{"set-cookie", ""},
	{"strict-transport-security", ""},
	{"transfer-encoding", ""},
	{"user-agent", ""},
	{"vary", ""},
	{"via", ""},
	{"www-authenticate", ""},
}

// Huffman decoding table (RFC 7541 Appendix B)
// This is a simplified decoder - for production use, a more efficient implementation would be needed

// huffmanCodes maps Huffman codes to their symbols (RFC 7541 Appendix B)
// Format: code, bits, symbol
var huffmanTable = []struct {
	code   uint32
	bits   uint8
	symbol uint16 // uint16 to accommodate EOS (256)
}{
	{0x1ff8, 13, 0},
	{0x7fffd8, 23, 1},
	{0xfffffe2, 28, 2},
	{0xfffffe3, 28, 3},
	{0xfffffe4, 28, 4},
	{0xfffffe5, 28, 5},
	{0xfffffe6, 28, 6},
	{0xfffffe7, 28, 7},
	{0xfffffe8, 28, 8},
	{0xffffea, 24, 9},
	{0x3ffffffc, 30, 10},
	{0xfffffe9, 28, 11},
	{0xfffffea, 28, 12},
	{0x3ffffffd, 30, 13},
	{0xfffffeb, 28, 14},
	{0xfffffec, 28, 15},
	{0xfffffed, 28, 16},
	{0xfffffee, 28, 17},
	{0xfffffef, 28, 18},
	{0xffffff0, 28, 19},
	{0xffffff1, 28, 20},
	{0xffffff2, 28, 21},
	{0x3ffffffe, 30, 22},
	{0xffffff3, 28, 23},
	{0xffffff4, 28, 24},
	{0xffffff5, 28, 25},
	{0xffffff6, 28, 26},
	{0xffffff7, 28, 27},
	{0xffffff8, 28, 28},
	{0xffffff9, 28, 29},
	{0xffffffa, 28, 30},
	{0xffffffb, 28, 31},
	{0x14, 6, 32},     // ' '
	{0x3f8, 10, 33},   // '!'
	{0x3f9, 10, 34},   // '"'
	{0xffa, 12, 35},   // '#'
	{0x1ff9, 13, 36},  // '$'
	{0x15, 6, 37},     // '%'
	{0xf8, 8, 38},     // '&'
	{0x7fa, 11, 39},   // '\''
	{0x3fa, 10, 40},   // '('
	{0x3fb, 10, 41},   // ')'
	{0xf9, 8, 42},     // '*'
	{0x7fb, 11, 43},   // '+'
	{0xfa, 8, 44},     // ','
	{0x16, 6, 45},     // '-'
	{0x17, 6, 46},     // '.'
	{0x18, 6, 47},     // '/'
	{0x0, 5, 48},      // '0'
	{0x1, 5, 49},      // '1'
	{0x2, 5, 50},      // '2'
	{0x19, 6, 51},     // '3'
	{0x1a, 6, 52},     // '4'
	{0x1b, 6, 53},     // '5'
	{0x1c, 6, 54},     // '6'
	{0x1d, 6, 55},     // '7'
	{0x1e, 6, 56},     // '8'
	{0x1f, 6, 57},     // '9'
	{0x5c, 7, 58},     // ':'
	{0xfb, 8, 59},     // ';'
	{0x7ffc, 15, 60},  // '<'
	{0x20, 6, 61},     // '='
	{0xffb, 12, 62},   // '>'
	{0x3fc, 10, 63},   // '?'
	{0x1ffa, 13, 64},  // '@'
	{0x21, 6, 65},     // 'A'
	{0x5d, 7, 66},     // 'B'
	{0x5e, 7, 67},     // 'C'
	{0x5f, 7, 68},     // 'D'
	{0x60, 7, 69},     // 'E'
	{0x61, 7, 70},     // 'F'
	{0x62, 7, 71},     // 'G'
	{0x63, 7, 72},     // 'H'
	{0x64, 7, 73},     // 'I'
	{0x65, 7, 74},     // 'J'
	{0x66, 7, 75},     // 'K'
	{0x67, 7, 76},     // 'L'
	{0x68, 7, 77},     // 'M'
	{0x69, 7, 78},     // 'N'
	{0x6a, 7, 79},     // 'O'
	{0x6b, 7, 80},     // 'P'
	{0x6c, 7, 81},     // 'Q'
	{0x6d, 7, 82},     // 'R'
	{0x6e, 7, 83},     // 'S'
	{0x6f, 7, 84},     // 'T'
	{0x70, 7, 85},     // 'U'
	{0x71, 7, 86},     // 'V'
	{0x72, 7, 87},     // 'W'
	{0xfc, 8, 88},     // 'X'
	{0x73, 7, 89},     // 'Y'
	{0xfd, 8, 90},     // 'Z'
	{0x1ffb, 13, 91},  // '['
	{0x7fff0, 19, 92}, // '\\'
	{0x1ffc, 13, 93},  // ']'
	{0x3ffc, 14, 94},  // '^'
	{0x22, 6, 95},     // '_'
	{0x7ffd, 15, 96},  // '`'
	{0x3, 5, 97},      // 'a'
	{0x23, 6, 98},     // 'b'
	{0x4, 5, 99},      // 'c'
	{0x24, 6, 100},    // 'd'
	{0x5, 5, 101},     // 'e'
	{0x25, 6, 102},    // 'f'
	{0x26, 6, 103},    // 'g'
	{0x27, 6, 104},    // 'h'
	{0x6, 5, 105},     // 'i'
	{0x74, 7, 106},    // 'j'
	{0x75, 7, 107},    // 'k'
	{0x28, 6, 108},    // 'l'
	{0x29, 6, 109},    // 'm'
	{0x2a, 6, 110},    // 'n'
	{0x7, 5, 111},     // 'o'
	{0x2b, 6, 112},    // 'p'
	{0x76, 7, 113},    // 'q'
	{0x2c, 6, 114},    // 'r'
	{0x8, 5, 115},     // 's'
	{0x9, 5, 116},     // 't'
	{0x2d, 6, 117},    // 'u'
	{0x77, 7, 118},    // 'v'
	{0x78, 7, 119},    // 'w'
	{0x79, 7, 120},    // 'x'
	{0x7a, 7, 121},    // 'y'
	{0x7b, 7, 122},    // 'z'
	{0x7ffe, 15, 123}, // '{'
	{0x7fc, 11, 124},  // '|'
	{0x3ffd, 14, 125}, // '}'
	{0x1ffd, 13, 126}, // '~'
	{0xffffffc, 28, 127},
	{0xfffe6, 20, 128},
	{0x3fffd2, 22, 129},
	{0xfffe7, 20, 130},
	{0xfffe8, 20, 131},
	{0x3fffd3, 22, 132},
	{0x3fffd4, 22, 133},
	{0x3fffd5, 22, 134},
	{0x7fffd9, 23, 135},
	{0x3fffd6, 22, 136},
	{0x7fffda, 23, 137},
	{0x7fffdb, 23, 138},
	{0x7fffdc, 23, 139},
	{0x7fffdd, 23, 140},
	{0x7fffde, 23, 141},
	{0xffffeb, 24, 142},
	{0x7fffdf, 23, 143},
	{0xffffec, 24, 144},
	{0xffffed, 24, 145},
	{0x3fffd7, 22, 146},
	{0x7fffe0, 23, 147},
	{0xffffee, 24, 148},
	{0x7fffe1, 23, 149},
	{0x7fffe2, 23, 150},
	{0x7fffe3, 23, 151},
	{0x7fffe4, 23, 152},
	{0x1fffdc, 21, 153},
	{0x3fffd8, 22, 154},
	{0x7fffe5, 23, 155},
	{0x3fffd9, 22, 156},
	{0x7fffe6, 23, 157},
	{0x7fffe7, 23, 158},
	{0xffffef, 24, 159},
	{0x3fffda, 22, 160},
	{0x1fffdd, 21, 161},
	{0xfffe9, 20, 162},
	{0x3fffdb, 22, 163},
	{0x3fffdc, 22, 164},
	{0x7fffe8, 23, 165},
	{0x7fffe9, 23, 166},
	{0x1fffde, 21, 167},
	{0x7fffea, 23, 168},
	{0x3fffdd, 22, 169},
	{0x3fffde, 22, 170},
	{0xfffff0, 24, 171},
	{0x1fffdf, 21, 172},
	{0x3fffdf, 22, 173},
	{0x7fffeb, 23, 174},
	{0x7fffec, 23, 175},
	{0x1fffe0, 21, 176},
	{0x1fffe1, 21, 177},
	{0x3fffe0, 22, 178},
	{0x1fffe2, 21, 179},
	{0x7fffed, 23, 180},
	{0x3fffe1, 22, 181},
	{0x7fffee, 23, 182},
	{0x7fffef, 23, 183},
	{0xfffea, 20, 184},
	{0x3fffe2, 22, 185},
	{0x3fffe3, 22, 186},
	{0x3fffe4, 22, 187},
	{0x7ffff0, 23, 188},
	{0x3fffe5, 22, 189},
	{0x3fffe6, 22, 190},
	{0x7ffff1, 23, 191},
	{0x3ffffe0, 26, 192},
	{0x3ffffe1, 26, 193},
	{0xfffeb, 20, 194},
	{0x7fff1, 19, 195},
	{0x3fffe7, 22, 196},
	{0x7ffff2, 23, 197},
	{0x3fffe8, 22, 198},
	{0x1ffffec, 25, 199},
	{0x3ffffe2, 26, 200},
	{0x3ffffe3, 26, 201},
	{0x3ffffe4, 26, 202},
	{0x7ffffde, 27, 203},
	{0x7ffffdf, 27, 204},
	{0x3ffffe5, 26, 205},
	{0xfffff1, 24, 206},
	{0x1ffffed, 25, 207},
	{0x7fff2, 19, 208},
	{0x1fffe3, 21, 209},
	{0x3ffffe6, 26, 210},
	{0x7ffffe0, 27, 211},
	{0x7ffffe1, 27, 212},
	{0x3ffffe7, 26, 213},
	{0x7ffffe2, 27, 214},
	{0xfffff2, 24, 215},
	{0x1fffe4, 21, 216},
	{0x1fffe5, 21, 217},
	{0x3ffffe8, 26, 218},
	{0x3ffffe9, 26, 219},
	{0xffffffd, 28, 220},
	{0x7ffffe3, 27, 221},
	{0x7ffffe4, 27, 222},
	{0x7ffffe5, 27, 223},
	{0xfffec, 20, 224},
	{0xfffff3, 24, 225},
	{0xfffed, 20, 226},
	{0x1fffe6, 21, 227},
	{0x3fffe9, 22, 228},
	{0x1fffe7, 21, 229},
	{0x1fffe8, 21, 230},
	{0x7ffff3, 23, 231},
	{0x3fffea, 22, 232},
	{0x3fffeb, 22, 233},
	{0x1ffffee, 25, 234},
	{0x1ffffef, 25, 235},
	{0xfffff4, 24, 236},
	{0xfffff5, 24, 237},
	{0x3ffffea, 26, 238},
	{0x7ffff4, 23, 239},
	{0x3ffffeb, 26, 240},
	{0x7ffffe6, 27, 241},
	{0x3ffffec, 26, 242},
	{0x3ffffed, 26, 243},
	{0x7ffffe7, 27, 244},
	{0x7ffffe8, 27, 245},
	{0x7ffffe9, 27, 246},
	{0x7ffffea, 27, 247},
	{0x7ffffeb, 27, 248},
	{0xffffffe, 28, 249},
	{0x7ffffec, 27, 250},
	{0x7ffffed, 27, 251},
	{0x7ffffee, 27, 252},
	{0x7ffffef, 27, 253},
	{0x7fffff0, 27, 254},
	{0x3ffffee, 26, 255},
	{0x3fffffff, 30, 256}, // EOS
}

// Build a reverse lookup table for Huffman decoding
var huffmanDecodeTable map[uint64]huffmanEntry

type huffmanEntry struct {
	symbol byte
	bits   uint8
}

func init() {
	huffmanDecodeTable = make(map[uint64]huffmanEntry)
	for _, h := range huffmanTable {
		if h.symbol <= 255 { // Skip EOS (256)
			huffmanDecodeTable[uint64(h.code)<<(32-h.bits)] = huffmanEntry{
				symbol: byte(h.symbol),
				bits:   h.bits,
			}
		}
	}
}

// huffmanDecode decodes a Huffman-encoded string
func huffmanDecode(data []byte) (string, error) {
	var result []byte
	var current uint64
	var bits uint8

	for _, b := range data {
		current = (current << 8) | uint64(b)
		bits += 8

		for bits >= 5 { // Minimum code length is 5 bits
			// Try to find a match starting from longest codes
			found := false
			for testBits := uint8(30); testBits >= 5; testBits-- {
				if bits < testBits {
					continue
				}

				// Extract the top testBits bits
				shift := bits - testBits
				testCode := (current >> shift) << (32 - testBits)

				if entry, ok := huffmanDecodeTable[testCode]; ok && entry.bits == testBits {
					result = append(result, entry.symbol)
					bits -= testBits
					current &= (1 << bits) - 1
					found = true
					break
				}
			}

			if !found {
				break
			}
		}
	}

	// Check for valid padding (all 1s)
	if bits > 0 {
		padding := current & ((1 << bits) - 1)
		maxPadding := uint64((1 << bits) - 1)
		if padding != maxPadding && bits > 7 {
			return "", fmt.Errorf("invalid huffman padding")
		}
	}

	return string(result), nil
}

// GetHTTP2Headers extracts HTTP/2 headers from a header block
func GetHTTP2Headers(decoder *HPACKDecoder, headerBlock []byte) (map[string]string, error) {
	headers, err := decoder.Decode(headerBlock)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for _, h := range headers {
		result[h.Name] = h.Value
	}
	return result, nil
}

// HTTP2PseudoHeaders extracts pseudo-headers from decoded headers
type HTTP2PseudoHeaders struct {
	Method    string // :method
	Scheme    string // :scheme
	Authority string // :authority
	Path      string // :path
	Status    string // :status (response only)
}

// ExtractPseudoHeaders extracts pseudo-headers from decoded headers
func ExtractPseudoHeaders(headers []HPACKHeader) HTTP2PseudoHeaders {
	var ph HTTP2PseudoHeaders
	for _, h := range headers {
		switch h.Name {
		case ":method":
			ph.Method = h.Value
		case ":scheme":
			ph.Scheme = h.Value
		case ":authority":
			ph.Authority = h.Value
		case ":path":
			ph.Path = h.Value
		case ":status":
			ph.Status = h.Value
		}
	}
	return ph
}

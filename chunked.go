// This is a modification of net.http.internal.chunked to also receive chunks line.
// The purpose is to have a raw header which understand chunks, but does not convert it.
// ALl changes are marked with "CHANGED" comment.
package kpx

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
)

const maxLineLength = 4096 // assumed <= bufio.defaultBufSize

var ErrLineTooLong = errors.New("header line too long")

// NewChunkedReader returns a new chunkedReader that translates the data read from r
// out of HTTP "chunked" format before returning it.
// The chunkedReader returns io.EOF when the final 0-length chunk is read.
//
// NewChunkedReader is not needed by normal applications. The http package
// automatically decodes chunking when reading response bodies.
func NewChunkedReader(r io.Reader) io.Reader {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	return &chunkedReader{r: br}
}

type chunkedReader struct {
	r        *bufio.Reader
	n        uint64 // unread bytes in chunk
	err      error
	buf      [2]byte
	checkEnd bool // whether need to check for \r\n chunk footer
	c        []byte
}

// CHANGED: return full line if chunk ok, nil otherwise
func (cr *chunkedReader) beginChunk() []byte {
	// chunk-size CRLF
	var full, line []byte
	full, line, cr.err = readChunkLine(cr.r)
	if cr.err != nil {
		return nil
	}
	cr.n, cr.err = parseHexUint(line)
	if cr.err != nil {
		return nil
	}
	if cr.n == 0 {
		cr.err = io.EOF
	}
	return full
}

func (cr *chunkedReader) chunkHeaderAvailable() bool {
	n := cr.r.Buffered()
	if n > 0 {
		peek, _ := cr.r.Peek(n)
		return bytes.IndexByte(peek, '\n') >= 0
	}
	return false
}

// CHANGED: receives line from beginChunk, return it it not nil (not error)
func (cr *chunkedReader) Read(b []uint8) (n int, err error) {
	for cr.err == nil || (cr.err == io.EOF && cr.c != nil) {
		//if cr.checkEnd {
		//	if n > 0 && cr.r.Buffered() < 2 {
		//		// We have some data. Return early (per the io.Reader
		//		// contract) instead of potentially blocking while
		//		// reading more.
		//		break
		//	}
		//	if _, cr.err = io.ReadFull(cr.r, cr.buf[:2]); cr.err == nil {
		//		if string(cr.buf[:]) != "\r\n" {
		//			cr.err = errors.New("malformed chunked encoding")
		//			break
		//		}
		//	}
		//	cr.checkEnd = false
		//}
		if cr.n == 0 {
			if n > 0 && !cr.chunkHeaderAvailable() {
				// We've read enough. Don't potentially block
				// reading a new chunk header.
				break
			}
			// CHANGED: save chunk to consume and increase bytes to consume by size of chunk + CR
			cr.c = cr.beginChunk()
			if cr.err == io.EOF {
				cr.c = append(cr.c, 13, 10)
			}
			cr.n += uint64(len(cr.c)) + 2
			continue
		}
		if len(b) == 0 {
			break
		}
		rbuf := b
		if uint64(len(rbuf)) > cr.n {
			rbuf = rbuf[:cr.n]
		}
		var n0 int
		// CHANGED: start consuming chunk before consuming source
		if cr.c != nil {
			if len(cr.c) > 0 {
				n0 = copy(rbuf, cr.c)
				rbuf = rbuf[n0:]
				if len(cr.c) == n0 {
					cr.c = nil
				} else {
					cr.c = cr.c[n0:]
				}
			}
		} else {
			n0, cr.err = cr.r.Read(rbuf)
		}
		n += n0
		b = b[n0:]
		cr.n -= uint64(n0)
		// If we're at the end of a chunk, read the next two
		// bytes to verify they are "\r\n".
		if cr.n == 0 && cr.err == nil {
			cr.checkEnd = true
		}
	}
	return n, cr.err // no wrap
}

// Read a line of bytes (up to \n) from b.
// Give up if the line exceeds maxLineLength.
// The returned bytes are owned by the bufio.Reader
// so they are only valid until the next bufio read.
// CHANGED: keep full line (variable l), and return it
func readChunkLine(b *bufio.Reader) ([]byte, []byte, error) {
	p, err := b.ReadSlice('\n')
	if err != nil {
		// We always know when EOF is coming.
		// If the caller asked for a line, there should be a line.
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		} else if err == bufio.ErrBufferFull {
			err = ErrLineTooLong
		}
		return nil, nil, err // no wrap
	}
	if len(p) >= maxLineLength {
		return nil, nil, ErrLineTooLong // no wrap
	}
	l := p
	p = trimTrailingWhitespace(p)
	p, err = removeChunkExtension(p)
	if err != nil {
		return nil, nil, err // no wrap
	}
	return l, p, nil
}

func trimTrailingWhitespace(b []byte) []byte {
	for len(b) > 0 && isASCIISpace(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	return b
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// removeChunkExtension removes any chunk-extension from p.
// For example,
//
//	"0" => "0"
//	"0;token" => "0"
//	"0;token=val" => "0"
//	`0;token="quoted string"` => "0"
func removeChunkExtension(p []byte) ([]byte, error) {
	semi := bytes.IndexByte(p, ';')
	if semi == -1 {
		return p, nil
	}
	// care about exact syntax of chunk extensions? We're
	// ignoring and stripping them anyway. For now just never
	// return an error.
	return p[:semi], nil
}

// NewChunkedWriter returns a new chunkedWriter that translates writes into HTTP
// "chunked" format before writing them to w. Closing the returned chunkedWriter
// sends the final 0-length chunk that marks the end of the stream but does
// not send the final CRLF that appears after trailers; trailers and the last
// CRLF must be written separately.
//
// NewChunkedWriter is not needed by normal applications. The http
// package adds chunking automatically if handlers don't set a
// Content-Length header. Using newChunkedWriter inside a handler
// would result in double chunking or chunking with a Content-Length
// length, both of which are wrong.
func NewChunkedWriter(w io.Writer) io.WriteCloser {
	return &chunkedWriter{w}
}

// Writing to chunkedWriter translates to writing in HTTP chunked Transfer
// Encoding wire format to the underlying Wire chunkedWriter.
type chunkedWriter struct {
	Wire io.Writer
}

// Write the contents of data as one chunk to Wire.
// NOTE: Note that the corresponding chunk-writing procedure in Conn.Write has
// a bug since it does not check for success of io.WriteString
func (cw *chunkedWriter) Write(data []byte) (n int, err error) {

	// Don't send 0-length data. It looks like EOF for chunked encoding.
	if len(data) == 0 {
		return 0, nil
	}

	if _, err = fmt.Fprintf(cw.Wire, "%x\r\n", len(data)); err != nil {
		return 0, err // no wrap
	}
	if n, err = cw.Wire.Write(data); err != nil {
		return
	}
	if n != len(data) {
		err = io.ErrShortWrite
		return
	}
	if _, err = io.WriteString(cw.Wire, "\r\n"); err != nil {
		return
	}
	if bw, ok := cw.Wire.(*FlushAfterChunkWriter); ok {
		err = bw.Flush()
	}
	return
}

func (cw *chunkedWriter) Close() error {
	_, err := io.WriteString(cw.Wire, "0\r\n")
	return err // no wrap
}

// FlushAfterChunkWriter signals from the caller of NewChunkedWriter
// that each chunk should be followed by a flush. It is used by the
// http.Transport code to keep the buffering behavior for headers and
// trailers, but flush out chunks aggressively in the middle for
// request bodies which may be generated slowly. See Issue 6574.
type FlushAfterChunkWriter struct {
	*bufio.Writer
}

func parseHexUint(v []byte) (n uint64, err error) {
	for i, b := range v {
		switch {
		case '0' <= b && b <= '9':
			b = b - '0'
		case 'a' <= b && b <= 'f':
			b = b - 'a' + 10
		case 'A' <= b && b <= 'F':
			b = b - 'A' + 10
		default:
			return 0, errors.New("invalid byte in chunk length")
		}
		if i == 16 {
			return 0, errors.New("http chunk length too large")
		}
		n <<= 4
		n |= uint64(b)
	}
	return
}

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// Policy fingerprints reject ambiguous JSON before canonicalization.
func decodeDLPJSONLimits(raw []byte, maxDepth, maxNodes int) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("Invalid JSON encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		nodes++
		if depth > maxDepth || nodes > maxNodes {
			return nil, errors.New("DLP JSON complexity exceeds its limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch token {
		case json.Delim('{'):
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("Invalid JSON key")
				}
				if _, exists := object[key]; exists {
					return nil, errors.New("Duplicate JSON key")
				}
				value, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
				return nil, errors.New("Invalid JSON object")
			}
			return object, nil
		case json.Delim('['):
			array := []any{}
			for decoder.More() {
				value, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
				return nil, errors.New("Invalid JSON array")
			}
			return array, nil
		}
		switch token.(type) {
		case nil, string, json.Number, bool:
			return token, nil
		}
		return nil, errors.New("Invalid JSON value")
	}
	value, err := read(0)
	if err != nil {
		return nil, err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, errors.New("Trailing JSON data")
	}
	return value, nil
}

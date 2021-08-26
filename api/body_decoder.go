package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
)

func jsonBodyDecoder(body io.Reader, header http.Header, schema *openapi3.SchemaRef, encFn openapi3filter.EncodingFn) (interface{}, error) {
	var value interface{}
	if err := json.NewDecoder(body).Decode(&value); err != nil {
		return nil, &openapi3filter.ParseError{Kind: openapi3filter.KindInvalidFormat, Cause: err}
	}
	return value, nil
}

func init() {
	openapi3filter.RegisterBodyDecoder("application/vnd.scanner.adapter.scan.request+json; version=1.0", jsonBodyDecoder)
	openapi3filter.RegisterBodyDecoder("application/vnd.scanner.adapter.scan.request+json", jsonBodyDecoder)
}

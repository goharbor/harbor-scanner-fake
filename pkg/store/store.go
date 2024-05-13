package store

import (
	"errors"
	"sync"

	"github.com/goharbor/harbor-scanner-fake/api"
)

var (
	ErrNotFound = errors.New("not found")
)

type ReportOrError struct {
	Error      error
	VulnReport *api.HarborVulnerabilityReport
	SbomReport *api.HarborSbomReport
}

type Store interface {
	SetRequest(api.ScanRequestId, *api.ScanRequest)
	GetRequest(api.ScanRequestId) (*api.ScanRequest, error)
	SetReportOrError(api.ScanRequestId, *ReportOrError)
	GetReportOrError(api.ScanRequestId) (*ReportOrError, error)
}

func New() Store {
	return &memoryStore{
		m: sync.Map{},
	}
}

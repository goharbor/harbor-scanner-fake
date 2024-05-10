package store

import (
	"sync"
	"time"

	"github.com/goharbor/harbor-scanner-fake/api"
)

type memoryItem struct {
	CreatedAt   time.Time
	ScanRequest *api.ScanRequest
	VulnReport  *api.HarborVulnerabilityReport
	SbomReport  *api.HarborSbomReport
	Error       error
}

type memoryStore struct {
	m sync.Map
}

func (s *memoryStore) getItem(scanRequestId api.ScanRequestId) (*memoryItem, error) {
	value, ok := s.m.Load(scanRequestId)
	if !ok {
		return nil, ErrNotFound
	}

	item, _ := value.(*memoryItem)
	return item, nil
}

func (s *memoryStore) SetRequest(scanRequestId api.ScanRequestId, scanRequest *api.ScanRequest) {
	s.m.Store(scanRequestId, &memoryItem{
		CreatedAt:   time.Now(),
		ScanRequest: scanRequest,
	})
}

func (s *memoryStore) GetRequest(scanRequestId api.ScanRequestId) (*api.ScanRequest, error) {
	item, err := s.getItem(scanRequestId)
	if err != nil {
		return nil, err
	}

	return item.ScanRequest, nil
}

func (s *memoryStore) SetReportOrError(scanRequestId api.ScanRequestId, reportOrError *ReportOrError) {
	item, err := s.getItem(scanRequestId)
	if err != nil {
		return
	}

	item.VulnReport = reportOrError.VulnReport
	item.SbomReport = reportOrError.SbomReport
	item.Error = reportOrError.Error

	s.m.Store(scanRequestId, item)
}

func (s *memoryStore) GetReportOrError(scanRequestId api.ScanRequestId) (*ReportOrError, error) {
	item, err := s.getItem(scanRequestId)
	if err != nil {
		return nil, err
	}

	return &ReportOrError{
		Error:      err,
		VulnReport: item.VulnReport,
		SbomReport: item.SbomReport,
	}, nil
}

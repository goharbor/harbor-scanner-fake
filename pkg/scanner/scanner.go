package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/url"
	"path/filepath"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/containerd/containerd/content/local"
	clog "github.com/containerd/containerd/log"
	"github.com/deislabs/oras/pkg/oras"
	"github.com/goharbor/harbor-scanner-fake/api"
	"github.com/goharbor/harbor-scanner-fake/pkg/config"
	"github.com/goharbor/harbor-scanner-fake/pkg/db"
	"github.com/goharbor/harbor-scanner-fake/pkg/log"
	"github.com/goharbor/harbor-scanner-fake/pkg/store"
	"github.com/goharbor/harbor-scanner-fake/pkg/util"
	"github.com/google/uuid"
	"github.com/mborders/artifex"
	wr "github.com/mroth/weightedrand"
	"github.com/sirupsen/logrus"
)

var (
	randSeed *rand.Rand
)

func init() {
	randSeed = rand.New(rand.NewSource(time.Now().UnixNano()))
}

const (
	VulnerabilityDatabaseUpdatedAt = "harbor.scanner-adapter/vulnerability-database-updated-at"

	MimeTypeOCIArtifact    = "application/vnd.oci.image.manifest.v1+json"
	MimeTypeDockerArtifact = "application/vnd.docker.distribution.manifest.v2+json"

	MimeTypeNativeReport               = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	MimeTypeGenericVulnerabilityReport = "application/vnd.security.vulnerability.report; version=1.1"
)

var (
	ErrReportNotFound = errors.New("report not found")
)

type Scanner struct {
	cfg        *config.Config
	db         *db.DB
	dispatcher *artifex.Dispatcher
	metadata   api.ScannerAdapterMetadata
	store      store.Store

	errorChooser      *wr.Chooser
	vulnerableChooser *wr.Chooser
}

func (s *Scanner) Metadata() *api.ScannerAdapterMetadata {
	return &s.metadata
}

func (s *Scanner) Scan(scanRequest *api.ScanRequest) (api.ScanRequestId, error) {
	scanRequestId := api.ScanRequestId(uuid.NewString())

	s.store.SetRequest(scanRequestId, scanRequest)

	err := s.dispatcher.Dispatch(func() {
		s.do(context.TODO(), scanRequestId)
	})

	if err != nil {
		return "", err
	}

	return scanRequestId, nil
}

func (s *Scanner) GetReport(scanRequestId api.ScanRequestId) (*api.HarborVulnerabilityReport, error) {
	reportOrError, err := s.store.GetReportOrError(scanRequestId)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrReportNotFound
		}

		return nil, err
	}

	return reportOrError.Report, reportOrError.Error
}

func (s *Scanner) do(ctx context.Context, scanRequestId api.ScanRequestId) {
	req, err := s.store.GetRequest(scanRequestId)
	if err != nil {
		return
	}

	if !s.cfg.Scanner.SkipPulling {
		if err := s.pull(ctx, req); err != nil {
			log.G(ctx).WithError(err).WithField("artifact", mustGetArtifact(req)).Error("pull artifact failed")

			s.store.SetReportOrError(scanRequestId, &store.ReportOrError{Error: err})
			return
		}
	}

	report, err := s.generateReport(req)
	if err != nil {
		log.G(ctx).WithField("artifact", mustGetArtifact(req)).Error("generate report failed")
	}

	s.store.SetReportOrError(scanRequestId, &store.ReportOrError{Report: report, Error: err})
}

func (s *Scanner) pull(ctx context.Context, req *api.ScanRequest) error {
	if req.Registry.Url == nil {
		return fmt.Errorf("bad scan request, registry url required")
	}

	u, err := url.Parse(*req.Registry.Url)
	if err != nil {
		return err
	}

	if req.Registry.Authorization != nil {
		if username, password, ok := parseBasicAuth(*req.Registry.Authorization); ok {
			u.User = url.UserPassword(username, password)
		}
	}

	ref := fmt.Sprintf("%s/%s@%s", u.Host, *req.Artifact.Repository, *req.Artifact.Digest)

	cacheDir, err := util.GetCacheDir()
	if err != nil {
		return err
	}

	rootPath := filepath.Join(cacheDir, "docker", "registry", "v2")
	if err := util.MkdirIfNotExists(rootPath); err != nil {
		return err
	}

	store, err := local.NewStore(rootPath)
	if err != nil {
		return err
	}

	log.G(ctx).WithField("artifact", ref).Debug("pull artifact")

	pullOpts := []oras.PullOpt{
		oras.WithPullEmptyNameAllowed(),
		oras.WithContentProvideIngester(store),
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	resolver := makeResolver(u)

	_, _, err = oras.Pull(clog.WithLogger(ctx, logrus.NewEntry(logger)), resolver, ref, store, pullOpts...)

	return err
}

func (s *Scanner) generateReport(req *api.ScanRequest) (*api.HarborVulnerabilityReport, error) {
	time.Sleep(s.cfg.Scanner.ReportGeneratingDuration)

	if s.errorChooser.Pick().(bool) {
		return nil, fmt.Errorf(gofakeit.Sentence(100))
	}

	var (
		vulnerabilities []api.VulnerabilityItem
		severity        *api.Severity
	)

	if s.vulnerableChooser.Pick().(bool) {
		vulsPerReport := s.cfg.Scanner.VulnerabilitiesPerReport
		if vulsPerReport == 0 {
			vulsPerReport = randSeed.Int63n(s.db.Total())
		}

		picked := make(map[*api.VulnerabilityItem]bool, vulsPerReport)
		for int64(len(vulnerabilities)) != vulsPerReport {
			vul := s.db.Pick()
			if picked[vul] {
				continue
			}

			picked[vul] = true

			vulnerabilities = append(vulnerabilities, *vul)
			if severity == nil || db.Less(*severity, *vul.Severity) {
				severity = vul.Severity
			}
		}
	}

	now := time.Now()

	return &api.HarborVulnerabilityReport{
		GeneratedAt:     &now,
		Artifact:        &req.Artifact,
		Scanner:         &s.metadata.Scanner,
		Vulnerabilities: &vulnerabilities,
		Severity:        severity,
	}, nil
}

func New(cfg *config.Config, db *db.DB) *Scanner {
	dispatcher := artifex.NewDispatcher(cfg.Scanner.Workers, cfg.Scanner.Workers*5)
	dispatcher.Start()

	errorChooser, _ := wr.NewChooser(
		wr.Choice{Item: true, Weight: uint(cfg.Scanner.ErrorRate * 100)},
		wr.Choice{Item: false, Weight: uint(100 - cfg.Scanner.ErrorRate*100)},
	)

	vulnerableChooser, _ := wr.NewChooser(
		wr.Choice{Item: true, Weight: uint(cfg.Scanner.VulnerableRate * 100)},
		wr.Choice{Item: false, Weight: uint(100 - cfg.Scanner.VulnerableRate*100)},
	)

	metadata := api.ScannerAdapterMetadata{
		Capabilities: []api.ScannerCapability{{
			ConsumesMimeTypes: []string{MimeTypeOCIArtifact, MimeTypeDockerArtifact},
			ProducesMimeTypes: []string{MimeTypeNativeReport, MimeTypeGenericVulnerabilityReport},
		}},
		Properties: &api.ScannerProperties{
			AdditionalProperties: map[string]string{
				VulnerabilityDatabaseUpdatedAt: time.Now().Format(time.RFC3339),
			},
		},
		Scanner: api.Scanner{
			Name:    util.String("Fake"),
			Vendor:  util.String("Fake Scanner"),
			Version: util.String("v1.0.0"),
		},
	}

	return &Scanner{
		cfg:               cfg,
		db:                db,
		dispatcher:        dispatcher,
		store:             store.New(),
		metadata:          metadata,
		errorChooser:      errorChooser,
		vulnerableChooser: vulnerableChooser,
	}
}

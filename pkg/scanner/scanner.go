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
	"github.com/google/uuid"
	"github.com/mborders/artifex"
	wr "github.com/mroth/weightedrand"
	"github.com/sirupsen/logrus"

	"github.com/goharbor/harbor-scanner-fake/api"
	"github.com/goharbor/harbor-scanner-fake/pkg/config"
	"github.com/goharbor/harbor-scanner-fake/pkg/db"
	"github.com/goharbor/harbor-scanner-fake/pkg/log"
	"github.com/goharbor/harbor-scanner-fake/pkg/store"
	"github.com/goharbor/harbor-scanner-fake/pkg/util"
)

var (
	randSeed *rand.Rand
)

func init() {
	randSeed = rand.New(rand.NewSource(time.Now().UnixNano()))
}

const (
	CapabilityTypeSBOM          = "sbom"
	CapabilityTypeVulnerability = "vulnerability"

	VulnerabilityDatabaseUpdatedAt = "harbor.scanner-adapter/vulnerability-database-updated-at"

	MimeTypeOCIArtifact    = "application/vnd.oci.image.manifest.v1+json"
	MimeTypeDockerArtifact = "application/vnd.docker.distribution.manifest.v2+json"

	MimeTypeNativeReport               = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	MimeTypeGenericVulnerabilityReport = "application/vnd.security.vulnerability.report; version=1.1"
	MimeTypeSbomReport                 = "application/vnd.security.sbom.report+json; version=1.0"
)

var (
	ErrReportNotFound = errors.New("report not found")
)

type SbomPkg struct {
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
}

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

func (s *Scanner) GetReport(scanRequestId api.ScanRequestId) (*api.HarborVulnerabilityReport, *api.HarborSbomReport, error) {
	reportOrError, err := s.store.GetReportOrError(scanRequestId)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, ErrReportNotFound
		}

		return nil, nil, err
	}

	return reportOrError.VulnReport, reportOrError.SbomReport, reportOrError.Error
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

	vulnReport, sbomReport, err := s.generateReport(req)
	if err != nil {
		log.G(ctx).WithField("artifact", mustGetArtifact(req)).Error("generate report failed")
	}

	s.store.SetReportOrError(scanRequestId, &store.ReportOrError{VulnReport: vulnReport, SbomReport: sbomReport, Error: err})
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

func (s *Scanner) generateReport(req *api.ScanRequest) (*api.HarborVulnerabilityReport, *api.HarborSbomReport, error) {
	// backward compatibility with pluggable-scanner-spec prior to v1.2
	if len(*req.EnabledCapabilities) == 0 {
		vulnReport, err := s.generateVulnerabilityReport(req)
		return vulnReport, nil, err
	}

	// for pluggable-scanner-spec v1.2 and onwards
	var vulnReport *api.HarborVulnerabilityReport
	var sbomReport *api.HarborSbomReport
	var err error
	for _, capbility := range *req.EnabledCapabilities {
		switch capbility.Type {
		case CapabilityTypeVulnerability:
			vulnReport, err = s.generateVulnerabilityReport(req)
			if err != nil {
				return nil, nil, err
			}
		case CapabilityTypeSBOM:
			sbomReport, err = s.generateSbomReport(req)
			if err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, fmt.Errorf("the capability type is not supported, type=%s", capbility.Type)
		}
	}
	return vulnReport, sbomReport, err
}

func (s *Scanner) generateSbomReport(req *api.ScanRequest) (*api.HarborSbomReport, error) {
	time.Sleep(s.cfg.Scanner.ReportGeneratingDuration)

	now := time.Now()
	var mediaType api.SbomParametersSbomMediaTypes
	//Harbor currently only asks SPDX format of SBOM
	mediaType = api.SbomParametersSbomMediaTypesApplicationspdxJson
	artifactName := (*req.Artifact.Repository) + ":" + (*req.Artifact.Digest)
	if req.Artifact.Tag != nil {
		artifactName = (*req.Artifact.Repository) + ":" + (*req.Artifact.Tag)
	}
	var pkgs []*SbomPkg
	sbomPkgNumPerReport := s.cfg.Scanner.SbomPackagesPerReport
	for int64(len(pkgs)) < sbomPkgNumPerReport {
		pkgs = append(pkgs, generateSbomPkgRecord())
	}
	sbomData := map[string]interface{}{
		"SPDXID": "SPDXRef-DOCUMENT",
		"createionInfo": struct {
			Created  string   `json:"created"`
			Creators []string `json:"creators"`
		}{
			Created:  time.Now().Format("2006-01-02T15:04:05.999999999Z"),
			Creators: []string{"Tool: " + *s.metadata.Scanner.Name, "Organization: " + *s.metadata.Scanner.Vendor},
		},
		"name":     artifactName,
		"packages": pkgs,
	}

	return &api.HarborSbomReport{
		Artifact:         &req.Artifact,
		GeneratedAt:      &now,
		MediaType:        (*api.HarborSbomReportMediaType)(&mediaType),
		Sbom:             &sbomData,
		Scanner:          &s.metadata.Scanner,
		VendorAttributes: nil,
	}, nil
}

func (s *Scanner) generateVulnerabilityReport(req *api.ScanRequest) (*api.HarborVulnerabilityReport, error) {
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

	vulnType := api.ScannerCapabilityType(CapabilityTypeVulnerability)
	sbomType := api.ScannerCapabilityType(CapabilityTypeSBOM)
	metadata := api.ScannerAdapterMetadata{
		Capabilities: []api.ScannerCapability{
			{
				ConsumesMimeTypes: []string{MimeTypeOCIArtifact, MimeTypeDockerArtifact},
				ProducesMimeTypes: []string{MimeTypeNativeReport, MimeTypeGenericVulnerabilityReport},
				Type:              &vulnType,
			},
			{
				ConsumesMimeTypes: []string{MimeTypeOCIArtifact, MimeTypeDockerArtifact},
				ProducesMimeTypes: []string{MimeTypeSbomReport},
				Type:              &sbomType,
			},
		},
		Properties: &api.ScannerProperties{
			VulnerabilityDatabaseUpdatedAt: time.Now().Format(time.RFC3339),
		},
		Scanner: api.Scanner{
			Name:    util.String("Fake-Scanner"),
			Vendor:  util.String("Fake-Scanner-Vendor"),
			Version: util.String("v1.1.0"),
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

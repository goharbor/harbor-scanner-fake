package config

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/goharbor/harbor-scanner-fake/pkg/log"
	"github.com/heetch/confita"
	"github.com/heetch/confita/backend"
	"github.com/heetch/confita/backend/env"
	"github.com/heetch/confita/backend/file"
)

// DefaultConfigPath ...
var DefaultConfigPath = "/etc/fake-scanner/config.yaml"

func init() {
	configPath := os.Getenv("FAKE_SCANNER_CONFIG")
	if configPath != "" {
		DefaultConfigPath = configPath
	}
}

// Config
// --
// db:
//
//	total: 10000
//
// scanner:
//
//	workers: 100
//	skipPulling: true
//	errorRate: 0
//	vulnerableRate: 1
//	vulnerabilitiesPerReport: 100
//	reportGeneratingDuration: 0s
//
// server:
//
//	address: 0.0.0.0:8080
//	accessLog: true
//	timeout: 0s
//	delay:
//	  metadata: 0s
//	  acceptScanRequest: 0s
//	  getScanReport: 0s
type Config struct {
	DB struct {
		// The total count of the vulnerabilities in db
		Total int64 `config:"db-total"`
	}

	Scanner struct {
		// The count of the scan workers
		Workers int `config:"scanner-workers"`

		// Skip pulling the artifact from registry when it's true
		SkipPulling bool `config:"scanner-skip-pulling" yaml:"skipPulling"`

		// The rate when scan failed for the artifact
		ErrorRate float64 `config:"scanner-error-rate" yaml:"errorRate"`

		// The rate when there are vulnerabilities for the artifact
		VulnerableRate float64 `config:"scanner-vulnerable-rate" yaml:"vulnerableRate"`

		// The vulnerabilities count in the artifact
		VulnerabilitiesPerReport int64 `config:"scanner-vulnerabilities-per-report" yaml:"vulnerabilitiesPerReport"`

		// The package count in the SBOM of an artifact
		SbomPackagesPerReport int64 `config:"sbom-packages-per-report" yaml:"sbomPackagesPerReport"`

		// The duration to generate the scan report after artifact pulled
		ReportGeneratingDuration time.Duration `config:"scanner-report-generating-duration" yaml:"reportGeneratingDuration"`
	}

	Server struct {
		// The address the scanner listend
		Address string `config:"server-address"`

		// The access request will be logged when it's true
		AsscessLog bool `config:"server-access-log" yaml:"accessLog"`

		Delay struct {
			// The dealy duration of the metadata API
			Metadata time.Duration `config:"server-delay-metadata" yaml:"metadata"`
			// The dealy duration of the accept scan request API
			AcceptScanRequest time.Duration `config:"server-delay-accept-scan-request" yaml:"acceptScanRequest"`
			// The dealy duration of the get scan report API
			GetScanReport time.Duration `config:"server-delay-get-scan-report" yaml:"getScanReport"`
		}

		// A timeout will be returned when the APIs don't response after this time duration
		Timeout time.Duration `config:"server-timeout"`
	}
}

func (cfg *Config) Validate() error {
	if cfg.Scanner.ErrorRate < 0 || cfg.Scanner.ErrorRate > 1 {
		return fmt.Errorf("scanner.errorRate must be in [0, 1], but got %f", cfg.Scanner.ErrorRate)
	}

	if cfg.Scanner.VulnerableRate < 0 || cfg.Scanner.VulnerableRate > 1 {
		return fmt.Errorf("scanner.vulnerableRate must be in [0, 1], but got %f", cfg.Scanner.ErrorRate)
	}

	if cfg.Scanner.VulnerabilitiesPerReport > cfg.DB.Total {
		return fmt.Errorf("scanner.vulnerabilitiesPerReport %d must less or equal with db.Total %d", cfg.Scanner.VulnerabilitiesPerReport, cfg.DB.Total)
	}

	if cfg.Scanner.SbomPackagesPerReport <= 0 {
		return fmt.Errorf("scanner.SbomPackagesPerReport %d must be larger than 0", cfg.Scanner.SbomPackagesPerReport)
	}

	return nil
}

func Load(paths ...string) (*Config, error) {
	cfg := &Config{}

	cfg.DB.Total = 10000

	cfg.Scanner.Workers = 100
	cfg.Scanner.SkipPulling = true
	cfg.Scanner.VulnerableRate = 1
	cfg.Scanner.VulnerabilitiesPerReport = 100
	cfg.Scanner.SbomPackagesPerReport = 10

	cfg.Server.Address = "0.0.0.0:8080"
	cfg.Server.AsscessLog = true

	backends := []backend.Backend{
		env.NewBackend(),
	}

	for _, path := range paths {
		if !pathExist(path) {
			log.L.WithField("file", path).Debug("file not exist")
		}

		if pathExist(path) {
			backends = append(backends, file.NewBackend(path))
		}
	}

	err := confita.NewLoader(backends...).Load(context.Background(), cfg)
	if err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func pathExist(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

package db

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/heww/harbor-scanner-fake/api"
	"github.com/heww/harbor-scanner-fake/pkg/util"
)

var (
	knowSeverities    = []api.Severity{"Low", "Medium", "High", "Critical"}
	knowSeverityCodes = map[api.Severity]int{}

	years          []int
	maxVulsPerYear map[int]int
	totalVuls      int64
)

func init() {
	rand.Seed(time.Now().UnixNano())

	for i, severity := range knowSeverities {
		knowSeverityCodes[severity] = i
	}

	for year := 1999; year <= 2021; year++ {
		years = append(years, year)
	}

	maxVulsPerYear = map[int]int{}
	for _, year := range years {
		switch {
		case year <= 2014:
			maxVulsPerYear[year] = 10000
		case year <= 2021:
			maxVulsPerYear[year] = 1000000
		}
	}

	for _, c := range maxVulsPerYear {
		totalVuls += int64(c)
	}
}

func Less(a, b api.Severity) bool {
	return knowSeverityCodes[a] < knowSeverityCodes[b]
}

func randomSeverity() api.Severity {
	return knowSeverities[rand.Intn(len(knowSeverities))]
}

func randomCveId() string {
	year := years[rand.Intn(len(years))]
	digest := fmt.Sprintf("%d", rand.Intn(maxVulsPerYear[year]))

	l := int(math.Log10(float64(maxVulsPerYear[year])))
	if c := l - len(digest); c > 0 {
		digest = strings.Repeat("0", c) + digest
	}

	return fmt.Sprintf("CVE-%d-%s", year, digest)
}

func generate(cveId string) *api.VulnerabilityItem {
	cveIds := []string{cveId}

	severity := randomSeverity()

	description := gofakeit.Sentence(10)

	links := []string{gofakeit.URL()}

	p := gofakeit.AppName()

	version := gofakeit.AppVersion()

	var fixVersion *string
	if gofakeit.Bool() {
		v := gofakeit.AppVersion()
		fixVersion = &v
	}

	return &api.VulnerabilityItem{
		CweIds:      &cveIds,
		Description: &description,
		FixVersion:  fixVersion,
		Id:          &cveId,
		Links:       &links,
		Package:     &p,
		PreferredCvss: &api.CVSSDetails{
			ScoreV3: util.Float32(rand.Float32() * 10),
		},
		Severity: &severity,
		Version:  &version,
	}
}

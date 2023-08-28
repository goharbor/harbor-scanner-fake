package db

import (
	"fmt"

	"github.com/goharbor/harbor-scanner-fake/api"
)

type DB struct {
	total int64
	items []*api.VulnerabilityItem
}

func (d *DB) Total() int64 {
	return d.total
}

func (d *DB) Pick() *api.VulnerabilityItem {
	return d.items[randSeed.Int63n(d.total)]
}

func (d *DB) UpdateAt() {
}

func New(total int64) *DB {
	if total > totalVuls {
		panic(fmt.Errorf("only %d vulnerabilities exists", totalVuls))
	}

	var items []*api.VulnerabilityItem

	cveIds := map[string]bool{}

	for int64(len(items)) != total {
		cveId := randomCveId()
		if cveIds[cveId] {
			continue
		}

		items = append(items, generate(cveId))
	}

	return &DB{
		total: total,
		items: items,
	}
}

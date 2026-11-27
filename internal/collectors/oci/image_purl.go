package oci

import (
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

// Runtime products have verified identities but no package-registry
// coordinates. Use the generic PURL type instead of relabeling them as a
// similarly named library on a language registry.
func setImageProductPURL(c *model.Component) {
	if c.PURL != "" || c.Name == "" {
		return
	}
	for _, e := range c.Evidence {
		if e.Collector == "go-buildinfo" {
			if c.Name == "stdlib" && c.Version != "" {
				c.PURL = packageurl.NewPackageURL("golang", "", "stdlib", strings.TrimPrefix(c.Version, "go"), nil, "").ToString()
			} else if mainModule := imageContextValue(c.Context, "main_module"); c.Kind == "application" && mainModule != "" {
				if c.Version == "" {
					c.PURL = common.GoMainModulePURL(mainModule)
				} else {
					c.PURL = common.GoModulePURL(mainModule, c.Version)
				}
			} else if c.Kind == "package" && c.Version != "" {
				c.PURL = common.GoModulePURL(c.Name, c.Version)
			}
			if c.PURL != "" {
				c.PURLBasis = "ecosystem_inferred"
			}
			return
		}
		if c.Version == "" {
			continue
		}
		switch e.Collector {
		case "python-runtime-elf", "ruby-runtime-elf", "node-runtime-elf", "bun-runtime-elf", "deno-runtime-elf", "postgres-runtime-elf", "redis-runtime-elf", "httpd-server-elf", "haproxy-server-elf", "memcached-server-elf", "micromamba-elf", "php-runtime-elf", "php-cli-elf", "php-fpm-elf":
			c.PURL = packageurl.NewPackageURL("generic", "", c.Name, c.Version, nil, "").ToString()
			c.PURLBasis = "ecosystem_inferred"
			return
		}
	}
}

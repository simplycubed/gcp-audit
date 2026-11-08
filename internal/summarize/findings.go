package summarize

import (
	"path/filepath"
	"strings"

	"github.com/simplycubed/gcp-audit/internal/report"
)

func dataAccessLogsOn(cfgs []struct {
	Service         string `json:"service"`
	AuditLogConfigs []struct {
		LogType string `json:"logType"`
	} `json:"auditLogConfigs"`
}) bool {
	covered := map[string]map[string]bool{}
	for _, c := range cfgs {
		if covered[c.Service] == nil {
			covered[c.Service] = map[string]bool{}
		}
		for _, a := range c.AuditLogConfigs {
			covered[c.Service][a.LogType] = true
		}
	}
	has := func(svc string) bool {
		return covered[svc]["DATA_READ"] && covered[svc]["DATA_WRITE"]
	}
	if has("allServices") {
		return true
	}
	return has("storage.googleapis.com") && has("cloudsql.googleapis.com")
}

func sinkDropsAuditLogs(filter string) bool {
	lower := strings.ToLower(filter)
	if !strings.Contains(lower, "cloudaudit.googleapis.com") {
		return false
	}
	return strings.Contains(lower, "not ") || strings.Contains(lower, "!(") || strings.Contains(filter, "-")
}

func computeInstances(dir string, r *report.Report) {
	var doc struct {
		Items map[string]struct {
			Instances []struct {
				Name              string `json:"name"`
				NetworkInterfaces []struct {
					AccessConfigs []struct {
						NatIP string `json:"natIP"`
					} `json:"accessConfigs"`
				} `json:"networkInterfaces"`
				ServiceAccounts []struct {
					Email  string   `json:"email"`
					Scopes []string `json:"scopes"`
				} `json:"serviceAccounts"`
				Metadata struct {
					Items []struct {
						Key   string `json:"key"`
						Value string `json:"value"`
					} `json:"items"`
				} `json:"metadata"`
			} `json:"instances"`
		} `json:"items"`
	}
	path := filepath.Join(dir, "global", "compute", "instances-aggregated.json")
	if readJSON(path, &doc) != nil {
		return
	}
	for zone, scoped := range doc.Items {
		for _, inst := range scoped.Instances {
			if inst.Name == "" {
				continue
			}
			id := zone + "/" + inst.Name
			for _, nic := range inst.NetworkInterfaces {
				if len(nic.AccessConfigs) > 0 {
					r.Add("MEDIUM", "VM has an external IP address",
						"Remove the access config unless the VM must be reachable from the internet.", id)
					break
				}
			}
			for _, sa := range inst.ServiceAccounts {
				if !strings.Contains(sa.Email, "-compute@developer.gserviceaccount.com") {
					continue
				}
				for _, scope := range sa.Scopes {
					if scope == "https://www.googleapis.com/auth/cloud-platform" {
						r.Add("HIGH", "VM uses the default compute service account with cloud-platform scope",
							"Use a dedicated service account with a narrow role.", id)
					}
				}
			}
			osLogin := false
			for _, item := range inst.Metadata.Items {
				switch item.Key {
				case "ssh-keys":
					if item.Value != "" {
						r.Add("HIGH", "VM has project or instance SSH keys in metadata",
							"Remove ssh-keys metadata and use OS Login.", id)
					}
				case "serial-port-enable":
					if item.Value == "true" || item.Value == "1" {
						r.Add("HIGH", "VM serial port is enabled",
							"Set serial-port-enable to false.", id)
					}
				case "enable-oslogin":
					if strings.EqualFold(item.Value, "true") {
						osLogin = true
					}
				}
			}
			if !osLogin {
				r.Add("MEDIUM", "VM does not enable OS Login",
					"Set enable-oslogin to true.", id)
			}
		}
	}
}

func subnets(dir string, r *report.Report) {
	matches, _ := filepath.Glob(filepath.Join(dir, "locations", "*", "compute", "subnetworks.json"))
	for _, f := range matches {
		var doc struct {
			Items []struct {
				Name           string `json:"name"`
				EnableFlowLogs bool   `json:"enableFlowLogs"`
			} `json:"items"`
		}
		_ = readJSON(f, &doc)
		for _, sn := range doc.Items {
			if sn.Name == "" || sn.EnableFlowLogs {
				continue
			}
			r.Add("MEDIUM", "Subnet flow logs are disabled",
				"Enable VPC flow logs on subnets that carry workload traffic.", sn.Name)
		}
	}
}

func dnsZones(dir string, r *report.Report) {
	var doc struct {
		ManagedZones []struct {
			Name         string `json:"name"`
			Visibility   string `json:"visibility"`
			DnssecConfig struct {
				State string `json:"state"`
			} `json:"dnssecConfig"`
		} `json:"managedZones"`
	}
	if readJSON(filepath.Join(dir, "global", "dns", "managed-zones.json"), &doc) != nil {
		return
	}
	for _, z := range doc.ManagedZones {
		if z.Name == "" || strings.EqualFold(z.Visibility, "private") {
			continue
		}
		if !strings.EqualFold(z.DnssecConfig.State, "on") {
			r.Add("MEDIUM", "Public DNS zone does not have DNSSEC enabled",
				"Turn DNSSEC on for public zones.", z.Name)
		}
	}
}

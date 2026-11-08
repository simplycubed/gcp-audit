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

func storageBuckets(dir string, r *report.Report) {
	matches, _ := filepath.Glob(filepath.Join(dir, "global", "storage", "buckets", "*.json"))
	for _, f := range matches {
		base := filepath.Base(f)
		if strings.HasSuffix(base, "-iam.json") || emptyJSON(f) {
			continue
		}
		var doc struct {
			Name             string `json:"name"`
			IamConfiguration struct {
				PublicAccessPrevention string `json:"publicAccessPrevention"`
			} `json:"iamConfiguration"`
		}
		if readJSON(f, &doc) != nil || doc.Name == "" {
			continue
		}
		if doc.IamConfiguration.PublicAccessPrevention != "enforced" {
			r.Add("MEDIUM", "Cloud Storage public access prevention is not enforced",
				"Set iamConfiguration.publicAccessPrevention to enforced.", doc.Name)
		}
	}
	for _, f := range matches {
		if !strings.HasSuffix(filepath.Base(f), "-iam.json") || emptyJSON(f) {
			continue
		}
		resource := strings.TrimSuffix(filepath.Base(f), "-iam.json")
		if resource == "" {
			continue
		}
		publicIAM(f, r, "Cloud Storage bucket is public")
		tokenCreatorIAM(f, r, "Cloud Storage bucket grants service account token creator", resource)
	}
}

func resourceIAM(dir string, r *report.Report) {
	kinds := []struct {
		kind string
		glob string
	}{
		{"Cloud Run service", filepath.Join(dir, "locations", "*", "run", "*-iam.json")},
		{"Cloud Function", filepath.Join(dir, "locations", "*", "functions", "*-iam.json")},
		{"Artifact Registry repository", filepath.Join(dir, "locations", "*", "artifactregistry", "*-iam.json")},
		{"Secret Manager secret", filepath.Join(dir, "locations", "*", "secretmanager", "*-iam.json")},
		{"Pub/Sub topic", filepath.Join(dir, "global", "pubsub", "*-iam.json")},
		{"Cloud KMS key ring", filepath.Join(dir, "locations", "*", "kms", "*-iam.json")},
		{"Cloud KMS key", filepath.Join(dir, "locations", "*", "kms", "key-rings", "*", "*-iam.json")},
		{"Service account", filepath.Join(dir, "global", "iam", "*-iam.json")},
	}
	for _, k := range kinds {
		matches, _ := filepath.Glob(k.glob)
		for _, f := range matches {
			if emptyJSON(f) {
				continue
			}
			resource := strings.TrimSuffix(filepath.Base(f), "-iam.json")
			if resource == "" {
				continue
			}
			publicIAM(f, r, k.kind+" is public")
			tokenCreatorIAM(f, r, k.kind+" grants service account token creator", resource)
		}
	}
}

type iamBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

func iamBindings(path string) []iamBinding {
	var doc struct {
		Bindings []iamBinding `json:"bindings"`
	}
	if readJSON(path, &doc) != nil {
		return nil
	}
	return doc.Bindings
}

func publicMember(mem string) bool {
	return strings.HasPrefix(mem, "allUsers") || strings.HasPrefix(mem, "allAuthenticatedUsers")
}

func publicIAM(path string, r *report.Report, title string) {
	resource := strings.TrimSuffix(filepath.Base(path), "-iam.json")
	for _, b := range iamBindings(path) {
		for _, mem := range b.Members {
			if publicMember(mem) {
				r.Add("HIGH", title, mem+" has "+b.Role, resource)
			}
		}
	}
}

func tokenCreatorIAM(path string, r *report.Report, title, resource string) {
	for _, b := range iamBindings(path) {
		if b.Role == "roles/iam.serviceAccountTokenCreator" {
			r.Add("HIGH", title, strings.Join(b.Members, ", "), resource)
		}
	}
}

func kmsKeys(dir string, r *report.Report) {
	matches, _ := filepath.Glob(filepath.Join(dir, "locations", "*", "kms", "key-rings", "*", "keys.json"))
	for _, f := range matches {
		if emptyJSON(f) {
			continue
		}
		var doc struct {
			CryptoKeys []struct {
				Name           string `json:"name"`
				RotationPeriod string `json:"rotationPeriod"`
				Primary        struct {
					State string `json:"state"`
				} `json:"primary"`
			} `json:"cryptoKeys"`
		}
		if readJSON(f, &doc) != nil {
			continue
		}
		for _, k := range doc.CryptoKeys {
			if k.Name == "" {
				continue
			}
			if k.RotationPeriod == "" {
				r.Add("MEDIUM", "Cloud KMS key has no rotation period",
					"Set rotationPeriod so new key versions are created automatically.", k.Name)
			}
			if k.Primary.State == "DESTROY_SCHEDULED" || k.Primary.State == "DESTROYED" {
				r.Add("HIGH", "Cloud KMS key is scheduled for destruction",
					"primary.state is "+k.Primary.State+".", k.Name)
			}
		}
	}
}

func orgPolicies(dir string, r *report.Report) {
	for _, constraint := range []string{
		"compute.vmExternalIpAccess",
		"storage.publicAccessPrevention",
		"sql.restrictPublicIp",
		"iam.disableServiceAccountKeyCreation",
	} {
		path := filepath.Join(dir, "global", "orgpolicy", constraint+".json")
		if emptyJSON(path) {
			continue
		}
		var doc struct {
			Spec struct {
				Rules []orgRule `json:"rules"`
			} `json:"spec"`
			Rules []orgRule `json:"rules"`
		}
		if readJSON(path, &doc) != nil {
			continue
		}
		enforced := false
		for _, rule := range append(doc.Spec.Rules, doc.Rules...) {
			if rule.enforced() {
				enforced = true
				break
			}
		}
		if !enforced {
			r.Add("MEDIUM", "Organization policy does not enforce "+constraint,
				"The effective policy does not set spec.rules.enforce or an equivalent restriction.", constraint)
		}
	}
}

type orgRule struct {
	Enforce  bool `json:"enforce"`
	DenyAll  bool `json:"denyAll"`
	AllowAll bool `json:"allowAll"`
	Values   struct {
		AllowedValues []string `json:"allowedValues"`
		DeniedValues  []string `json:"deniedValues"`
	} `json:"values"`
}

func (r orgRule) enforced() bool {
	return r.Enforce || r.DenyAll || len(r.Values.AllowedValues) > 0 || len(r.Values.DeniedValues) > 0
}

func apiKeys(dir string, r *report.Report) {
	path := filepath.Join(dir, "global", "apikeys", "keys.json")
	if emptyJSON(path) {
		return
	}
	var doc struct {
		Keys []struct {
			Name         string `json:"name"`
			Restrictions struct {
				APITargets []struct {
					Service string `json:"service"`
				} `json:"apiTargets"`
				BrowserKeyRestrictions *struct {
					AllowedReferrers []string `json:"allowedReferrers"`
				} `json:"browserKeyRestrictions"`
				ServerKeyRestrictions *struct {
					AllowedIps []string `json:"allowedIps"`
				} `json:"serverKeyRestrictions"`
				AndroidKeyRestrictions *struct {
					AllowedApplications []struct {
						PackageName string `json:"packageName"`
					} `json:"allowedApplications"`
				} `json:"androidKeyRestrictions"`
				IosKeyRestrictions *struct {
					AllowedBundleIds []string `json:"allowedBundleIds"`
				} `json:"iosKeyRestrictions"`
			} `json:"restrictions"`
		} `json:"keys"`
	}
	if readJSON(path, &doc) != nil {
		return
	}
	for _, k := range doc.Keys {
		if k.Name == "" {
			continue
		}
		rest := k.Restrictions
		app := (rest.BrowserKeyRestrictions != nil && len(rest.BrowserKeyRestrictions.AllowedReferrers) > 0) ||
			(rest.ServerKeyRestrictions != nil && len(rest.ServerKeyRestrictions.AllowedIps) > 0) ||
			(rest.AndroidKeyRestrictions != nil && len(rest.AndroidKeyRestrictions.AllowedApplications) > 0) ||
			(rest.IosKeyRestrictions != nil && len(rest.IosKeyRestrictions.AllowedBundleIds) > 0)
		if len(rest.APITargets) == 0 && !app {
			r.Add("HIGH", "API key has no application or API restrictions",
				"Restrict the key to specific APIs and callers. The key string is not included here.", k.Name)
		}
	}
}

func workloadIdentity(dir string, r *report.Report) {
	matches, _ := filepath.Glob(filepath.Join(dir, "global", "iam", "workload-identity-pools", "*-providers.json"))
	for _, f := range matches {
		if emptyJSON(f) {
			continue
		}
		var doc struct {
			Providers []struct {
				Name               string `json:"name"`
				AttributeCondition string `json:"attributeCondition"`
			} `json:"workloadIdentityPoolProviders"`
		}
		if readJSON(f, &doc) != nil {
			continue
		}
		for _, p := range doc.Providers {
			if p.Name == "" || strings.TrimSpace(p.AttributeCondition) != "" {
				continue
			}
			r.Add("HIGH", "Workload Identity provider has no attribute condition",
				"Set attributeCondition so only expected external identities can federate.", p.Name)
		}
	}
}

package summarize

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindingOnlyChecks(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("global/iam-policy.json", `{
		"etag":"abc",
		"auditConfigs":[{"service":"storage.googleapis.com","auditLogConfigs":[{"logType":"DATA_READ"}]}]
	}`)
	write("global/compute/firewalls.json", `{
		"items":[
			{"name":"egress-all","direction":"EGRESS","sourceRanges":["0.0.0.0/0"],"allowed":[{"IPProtocol":"all"}]},
			{"name":"ingress-ssh","direction":"INGRESS","sourceRanges":["0.0.0.0/0"],"allowed":[{"IPProtocol":"tcp","ports":["22"]}]}
		]
	}`)
	write("locations/europe-west1/sql/instances.json", `{
		"items":[{"name":"db","settings":{
			"ipConfiguration":{"ipv4Enabled":false,"requireSsl":false,"authorizedNetworks":[{"value":"0.0.0.0/0"}]},
			"backupConfiguration":{"enabled":false,"pointInTimeRecoveryEnabled":false},
			"deletionProtectionEnabled":false
		}}]
	}`)
	write("locations/europe-west1/container/clusters.json", `{
		"clusters":[{"name":"prod",
			"privateClusterConfig":{"enablePrivateNodes":true,"enablePrivateEndpoint":false},
			"masterAuthorizedNetworksConfig":{"enabled":false},
			"databaseEncryption":{"state":"DECRYPTED"},
			"masterAuth":{"clientCertificateConfig":{"issueClientCertificate":true}},
			"nodePools":[{"name":"pool","config":{"serviceAccount":"123-compute@developer.gserviceaccount.com"}}]
		}]
	}`)
	write("global/compute/instances-aggregated.json", `{
		"items":{"zones/europe-west1-b":{"instances":[{
			"name":"web",
			"networkInterfaces":[{"accessConfigs":[{"natIP":"1.2.3.4"}]}],
			"serviceAccounts":[{"email":"123-compute@developer.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/cloud-platform"]}],
			"metadata":{"items":[{"key":"ssh-keys","value":"alice:ssh-rsa AAAA"},{"key":"serial-port-enable","value":"true"}]}
		}]}}
	}`)
	write("locations/europe-west1/compute/subnetworks.json", `{"items":[{"name":"apps","enableFlowLogs":false},{"name":"logged","enableFlowLogs":true}]}`)
	write("global/dns/managed-zones.json", `{
		"managedZones":[
			{"name":"public","visibility":"public","dnssecConfig":{"state":"off"}},
			{"name":"internal","visibility":"private","dnssecConfig":{"state":"off"}}
		]
	}`)
	write("global/logging/sinks.json", `{
		"sinks":[
			{"name":"audit","disabled":true,"filter":"NOT logName:\"cloudaudit.googleapis.com\""},
			{"name":"keep","filter":"logName:\"cloudaudit.googleapis.com\""}
		]
	}`)

	rep, err := Build(dir)
	if err != nil {
		t.Fatal(err)
	}
	md := rep.Markdown()
	needles := []string{
		"Data Access audit logs are not enabled",
		"Firewall allows ingress from the public internet",
		"Cloud SQL instance authorizes the public internet",
		"Cloud SQL instance does not require SSL",
		"Cloud SQL backups are disabled",
		"Cloud SQL point-in-time recovery is disabled",
		"Cloud SQL deletion protection is disabled",
		"GKE control plane is public with no authorized networks",
		"GKE secrets are not encrypted with a customer-managed key",
		"GKE Workload Identity is disabled",
		"GKE issues client certificates",
		"GKE node pool uses the default compute service account",
		"VM has an external IP address",
		"VM uses the default compute service account with cloud-platform scope",
		"VM has project or instance SSH keys in metadata",
		"VM serial port is enabled",
		"VM does not enable OS Login",
		"Subnet flow logs are disabled",
		"Public DNS zone does not have DNSSEC enabled",
		"Cloud Logging sink is disabled",
		"Cloud Logging sink excludes audit logs",
	}
	for _, n := range needles {
		if !strings.Contains(md, n) {
			t.Errorf("missing %q\n%s", n, md)
		}
	}
	if strings.Contains(md, "egress-all") {
		t.Fatal("egress firewall was reported as public ingress")
	}
	if strings.Contains(md, "internal") && strings.Contains(md, "DNSSEC") {
		t.Fatal("private DNS zone was flagged")
	}
	if strings.Contains(md, "`keep`") || strings.Contains(md, "keep") && strings.Count(md, "excludes audit logs") != 1 {
		t.Fatalf("audit-only sink was treated as an exclusion:\n%s", md)
	}
}

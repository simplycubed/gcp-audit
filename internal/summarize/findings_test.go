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

func TestNewCollectionFindings(t *testing.T) {
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
	write("global/storage/buckets/public.json", `{
		"name":"public","iamConfiguration":{"publicAccessPrevention":"inherited"}
	}`)
	write("global/storage/buckets/public-iam.json", `{
		"bindings":[{"role":"roles/storage.objectViewer","members":["allUsers"]}]
	}`)
	write("global/storage/buckets/locked.json", `{
		"name":"locked","iamConfiguration":{"publicAccessPrevention":"enforced"}
	}`)
	write("global/storage/buckets/locked-iam.json", `{
		"bindings":[{"role":"roles/storage.objectViewer","members":["projectViewer:example"]}]
	}`)
	write("global/storage/buckets/missing.json", `{}`)
	write("locations/europe-west1/run/api-iam.json", `{
		"bindings":[{"role":"roles/iam.serviceAccountTokenCreator","members":["allAuthenticatedUsers"]}]
	}`)
	write("locations/europe-west1/functions/empty-iam.json", `{}`)
	write("locations/europe-west1/kms/app-iam.json", `{
		"bindings":[{"role":"roles/cloudkms.viewer","members":["user:a@example.com"]}]
	}`)
	write("locations/europe-west1/kms/key-rings/app/keys.json", `{
		"cryptoKeys":[
			{"name":"","rotationPeriod":""},
			{"name":"projects/p/locations/europe-west1/keyRings/app/cryptoKeys/data","rotationPeriod":"","primary":{"state":"ENABLED"}},
			{"name":"projects/p/locations/europe-west1/keyRings/app/cryptoKeys/old","rotationPeriod":"7776000s","primary":{"state":"DESTROY_SCHEDULED"}}
		]
	}`)
	write("locations/europe-west1/kms/key-rings/app/old-iam.json", `{
		"bindings":[{"role":"roles/iam.serviceAccountTokenCreator","members":["serviceAccount:a@example.com"]}]
	}`)
	write("global/orgpolicy/storage.publicAccessPrevention.json", `{"spec":{"rules":[{"enforce":true}]}}`)
	write("global/orgpolicy/sql.restrictPublicIp.json", `{"spec":{"rules":[{"enforce":false}]}}`)
	write("global/orgpolicy/iam.disableServiceAccountKeyCreation.json", `{}`)
	write("global/orgpolicy/compute.vmExternalIpAccess.json", `{"spec":{"rules":[{"denyAll":true}]}}`)
	write("global/apikeys/keys.json", `{
		"keys":[
			{"name":"","keyString":"AIzaEmptyName"},
			{"name":"projects/p/locations/global/keys/open","keyString":"AIzaShouldNotAppear","restrictions":{}},
			{"name":"projects/p/locations/global/keys/web","restrictions":{"browserKeyRestrictions":{"allowedReferrers":["https://example.com/*"]}}},
			{"name":"projects/p/locations/global/keys/api","restrictions":{"apiTargets":[{"service":"storage.googleapis.com"}]}}
		]
	}`)
	write("global/iam/workload-identity-pools/gha-providers.json", `{
		"workloadIdentityPoolProviders":[
			{"name":"","attributeCondition":""},
			{"name":"projects/p/locations/global/workloadIdentityPools/gha/providers/open","attributeCondition":""},
			{"name":"projects/p/locations/global/workloadIdentityPools/gha/providers/locked","attributeCondition":"assertion.repository=='acme/app'"}
		]
	}`)

	rep, err := Build(dir)
	if err != nil {
		t.Fatal(err)
	}
	md := rep.Markdown()
	needles := []string{
		"Cloud Storage bucket is public",
		"Cloud Storage public access prevention is not enforced",
		"Cloud Run service is public",
		"Cloud Run service grants service account token creator",
		"Cloud KMS key grants service account token creator",
		"Cloud KMS key has no rotation period",
		"Cloud KMS key is scheduled for destruction",
		"Organization policy does not enforce sql.restrictPublicIp",
		"API key has no application or API restrictions",
		"Workload Identity provider has no attribute condition",
	}
	for _, n := range needles {
		if !strings.Contains(md, n) {
			t.Errorf("missing %q\n%s", n, md)
		}
	}
	absent := []string{
		"AIzaShouldNotAppear",
		"AIzaEmptyName",
		"Organization policy does not enforce storage.publicAccessPrevention",
		"Organization policy does not enforce iam.disableServiceAccountKeyCreation",
		"Organization policy does not enforce compute.vmExternalIpAccess",
		"projects/p/locations/global/keys/web",
		"projects/p/locations/global/keys/api",
		"providers/locked",
		"`locked`",
		"Cloud KMS key ring is public",
	}
	for _, n := range absent {
		if strings.Contains(md, n) {
			t.Errorf("unexpected %q\n%s", n, md)
		}
	}
	if strings.Count(md, "Cloud Storage public access prevention is not enforced") != 1 {
		t.Fatalf("enforced bucket was flagged:\n%s", md)
	}
	if strings.Count(md, "Workload Identity provider has no attribute condition") != 1 {
		t.Fatalf("conditioned provider was flagged:\n%s", md)
	}
}

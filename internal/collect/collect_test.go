package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simplycubed/gcp-audit/internal/gcpapi"
)

func testOpts(t *testing.T, fake *gcpapi.Fake) Options {
	t.Helper()
	if fake.Ident.ProjectID == "" {
		fake.Ident = gcpapi.Identity{ProjectID: "example-project", ProjectNumber: "1", Principal: "auditor@example.com"}
	}
	if fake.Regions == nil {
		fake.Regions = []string{"europe-west1", "us-central1"}
	}
	return Options{
		Project:  "example-project",
		OutDir:   t.TempDir(),
		Parallel: 2,
		Client:   fake,
		Formats:  []string{"md", "csv", "json"},
	}
}

func TestUnknownLocationRejectedWithoutDump(t *testing.T) {
	fake := &gcpapi.Fake{}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "us-east-1"
	err := Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "us-east-1") {
		t.Fatalf("got %v", err)
	}
	if len(fake.Calls) != 0 {
		t.Fatalf("must not call GCP before rejecting unknown codes")
	}
}

func TestWritesMetaAndReports(t *testing.T) {
	fake := &gcpapi.Fake{}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "europe-west1"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(opts.OutDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(filepath.Join(opts.OutDir, "meta.json"))
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	if meta["project_id"] != "example-project" || meta["cloud"] != "gcp" {
		t.Fatalf("%s", raw)
	}
	for _, name := range []string{"summary.md", "summary.csv", "summary.json"} {
		if _, err := os.Stat(filepath.Join(opts.OutDir, name)); err != nil {
			t.Fatal(name, err)
		}
	}
}

func TestRedactsVPNSecret(t *testing.T) {
	fake := &gcpapi.Fake{
		Bodies: map[string]json.RawMessage{
			"|compute|AggregatedListVpnTunnels": json.RawMessage(`{"items":{"europe-west1":{"vpnTunnels":[{"sharedSecret":"supersecret"}]}}}`),
		},
	}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "europe-west1"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(opts.OutDir, "global", "compute", "vpn-tunnels-aggregated.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "supersecret") {
		t.Fatalf("secret leaked: %s", raw)
	}
}

func TestFollowUpDumpsUseResourceNames(t *testing.T) {
	fake := &gcpapi.Fake{
		Bodies: map[string]json.RawMessage{
			"|storage|ListBuckets":                 json.RawMessage(`{"items":[{"name":"logs"},{"name":""}]}`),
			"|iam|ListServiceAccounts":             json.RawMessage(`{"accounts":[{"name":"projects/example-project/serviceAccounts/a@example.com","email":"a@example.com"}]}`),
			"|pubsub|ListTopics":                   json.RawMessage(`{"topics":[{"name":"projects/example-project/topics/events"}]}`),
			"|iam|ListWorkloadIdentityPools":       json.RawMessage(`{"workloadIdentityPools":[{"name":"projects/example-project/locations/global/workloadIdentityPools/gha"}]}`),
			"europe-west1|run|ListServices":        json.RawMessage(`{"services":[{"name":"projects/example-project/locations/europe-west1/services/api"}]}`),
			"europe-west1|cloudkms|ListKeyRings":   json.RawMessage(`{"keyRings":[{"name":"projects/example-project/locations/europe-west1/keyRings/app"}]}`),
			"europe-west1|cloudkms|ListCryptoKeys": json.RawMessage(`{"cryptoKeys":[{"name":"projects/example-project/locations/europe-west1/keyRings/app/cryptoKeys/data"},{"name":""}]}`),
			"|apikeys|ListKeys":                    json.RawMessage(`{"keys":[{"name":"projects/example-project/locations/global/keys/abc","keyString":"AIzaSecret"}]}`),
		},
	}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "europe-west1"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{
		"global/storage/buckets/logs.json",
		"global/storage/buckets/logs-iam.json",
		"global/iam/a@example.com-iam.json",
		"global/pubsub/events-iam.json",
		"global/iam/workload-identity-pools.json",
		"global/iam/workload-identity-pools/gha-providers.json",
		"global/apikeys/keys.json",
		"global/orgpolicy/compute.vmExternalIpAccess.json",
		"global/orgpolicy/storage.publicAccessPrevention.json",
		"global/orgpolicy/sql.restrictPublicIp.json",
		"global/orgpolicy/iam.disableServiceAccountKeyCreation.json",
		"locations/europe-west1/run/api-iam.json",
		"locations/europe-west1/kms/app-iam.json",
		"locations/europe-west1/kms/key-rings/app/keys.json",
		"locations/europe-west1/kms/key-rings/app/data-iam.json",
	} {
		if _, err := os.Stat(filepath.Join(opts.OutDir, rel)); err != nil {
			t.Error(rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(opts.OutDir, "global/storage/buckets/-iam.json")); err == nil {
		t.Fatal("empty bucket name was dumped")
	}
	raw, err := os.ReadFile(filepath.Join(opts.OutDir, "global/apikeys/keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "AIzaSecret") {
		t.Fatalf("key material written: %s", raw)
	}
	seen := map[string]bool{}
	for _, call := range fake.Calls {
		if call.Operation == "GetBucket" && call.Input["Resource"] == "logs" {
			seen["bucket"] = true
		}
		if call.Operation == "ListCryptoKeys" && call.Input["Resource"] == "projects/example-project/locations/europe-west1/keyRings/app" {
			seen["keys"] = true
		}
		if call.Operation == "GetEffectivePolicy" && call.Input["Constraint"] == "sql.restrictPublicIp" {
			seen["org"] = true
		}
		if call.Operation == "ListWorkloadIdentityPoolProviders" && strings.HasSuffix(call.Input["Resource"], "/gha") {
			seen["wif"] = true
		}
	}
	for _, k := range []string{"bucket", "keys", "org", "wif"} {
		if !seen[k] {
			t.Errorf("missing call %s", k)
		}
	}
}

func TestDumpFailureWritesEmptyObject(t *testing.T) {
	fake := &gcpapi.Fake{
		Errs: map[string]error{
			"|cloudresourcemanager|GetIamPolicy": fmtErr("403"),
		},
	}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "europe-west1"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(opts.OutDir, "global", "iam-policy.json"))
	if strings.TrimSpace(string(raw)) != "{}" {
		t.Fatalf("got %s", raw)
	}
	elog, _ := os.ReadFile(filepath.Join(opts.OutDir, "errors.log"))
	if !strings.Contains(string(elog), "403") {
		t.Fatalf("errors.log: %s", elog)
	}
}

type fmtErr string

func (e fmtErr) Error() string { return string(e) }

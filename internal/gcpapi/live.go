package gcpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/oauth2/google"
	apikeys "google.golang.org/api/apikeys/v2"
	artifactregistry "google.golang.org/api/artifactregistry/v1"
	cloudfunctions "google.golang.org/api/cloudfunctions/v2"
	cloudkms "google.golang.org/api/cloudkms/v1"
	crm "google.golang.org/api/cloudresourcemanager/v3"
	compute "google.golang.org/api/compute/v1"
	container "google.golang.org/api/container/v1"
	dns "google.golang.org/api/dns/v1"
	iam "google.golang.org/api/iam/v1"
	logging "google.golang.org/api/logging/v2"
	"google.golang.org/api/option"
	orgpolicy "google.golang.org/api/orgpolicy/v2"
	pubsub "google.golang.org/api/pubsub/v1"
	run "google.golang.org/api/run/v2"
	secretmanager "google.golang.org/api/secretmanager/v1"
	serviceusage "google.golang.org/api/serviceusage/v1"
	sqladmin "google.golang.org/api/sqladmin/v1"
	storage "google.golang.org/api/storage/v1"
)

// Live is the production Client using Google APIs and ADC.
type Live struct {
	opts []option.ClientOption
}

// NewLive uses Application Default Credentials.
func NewLive(ctx context.Context) (*Live, error) {
	creds, err := google.FindDefaultCredentials(ctx,
		"https://www.googleapis.com/auth/cloud-platform.read-only",
		"https://www.googleapis.com/auth/cloud-platform",
	)
	if err != nil {
		return nil, err
	}
	return &Live{opts: []option.ClientOption{option.WithTokenSource(creds.TokenSource)}}, nil
}

func (l *Live) Identity(ctx context.Context, project string) (Identity, error) {
	svc, err := crm.NewService(ctx, l.opts...)
	if err != nil {
		return Identity{}, err
	}
	p, err := svc.Projects.Get("projects/" + project).Context(ctx).Do()
	if err != nil {
		return Identity{}, err
	}
	principal := os.Getenv("GOOGLE_ACCOUNT")
	if creds, err := google.FindDefaultCredentials(ctx); err == nil && creds.JSON != nil {
		var raw struct {
			ClientEmail string `json:"client_email"`
		}
		if json.Unmarshal(creds.JSON, &raw) == nil {
			principal = raw.ClientEmail
		}
	}
	num := strings.TrimPrefix(p.Name, "projects/")
	return Identity{
		ProjectID:     p.ProjectId,
		ProjectNumber: num,
		Principal:     principal,
	}, nil
}

func (l *Live) ListRegions(ctx context.Context, project string) ([]string, error) {
	svc, err := compute.NewService(ctx, l.opts...)
	if err != nil {
		return nil, err
	}
	var names []string
	err = svc.Regions.List(project).Pages(ctx, func(page *compute.RegionList) error {
		for _, r := range page.Items {
			if r.Status == "UP" || r.Status == "" {
				names = append(names, r.Name)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return names, nil
}

func (l *Live) Dump(ctx context.Context, req Dump) (json.RawMessage, error) {
	project := req.Input["Project"]
	loc := req.Input["Location"]
	if loc == "" {
		loc = req.Location
	}
	key := req.Service + "." + req.Operation
	var (
		v   any
		err error
	)
	switch key {
	case "cloudresourcemanager.GetProject":
		svc, e := crm.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = svc.Projects.Get("projects/" + project).Context(ctx).Do()
	case "cloudresourcemanager.GetIamPolicy":
		svc, e := crm.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = svc.Projects.GetIamPolicy("projects/"+project, &crm.GetIamPolicyRequest{}).Context(ctx).Do()
	case "iam.ListServiceAccounts":
		svc, e := iam.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Projects.ServiceAccounts.List("projects/"+project).Pages,
			func(p *iam.ListServiceAccountsResponse) []*iam.ServiceAccount { return p.Accounts },
			func(p *iam.ListServiceAccountsResponse, items []*iam.ServiceAccount) { p.Accounts = items },
			func(p *iam.ListServiceAccountsResponse) { p.NextPageToken = "" },
		)
	case "iam.GetServiceAccountIamPolicy":
		svc, e := iam.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		name, e := requiredInput(req, "Resource")
		if e != nil {
			return nil, e
		}
		v, err = svc.Projects.ServiceAccounts.GetIamPolicy(name).Context(ctx).Do()
	case "iam.ListServiceAccountKeys":
		svc, e := iam.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		name := "projects/" + project + "/serviceAccounts/" + req.Input["ServiceAccount"]
		// Keys.List has no page token in google.golang.org/api v0.298.0.
		v, err = svc.Projects.ServiceAccounts.Keys.List(name).Context(ctx).Do()
	case "iam.ListWorkloadIdentityPools":
		svc, e := iam.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		parent := "projects/" + project + "/locations/global"
		v, err = concatPages(ctx, svc.Projects.Locations.WorkloadIdentityPools.List(parent).Pages,
			func(p *iam.ListWorkloadIdentityPoolsResponse) []*iam.WorkloadIdentityPool {
				return p.WorkloadIdentityPools
			},
			func(p *iam.ListWorkloadIdentityPoolsResponse, items []*iam.WorkloadIdentityPool) {
				p.WorkloadIdentityPools = items
			},
			func(p *iam.ListWorkloadIdentityPoolsResponse) { p.NextPageToken = "" },
		)
	case "iam.ListWorkloadIdentityPoolProviders":
		svc, e := iam.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		parent, e := requiredInput(req, "Resource")
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Projects.Locations.WorkloadIdentityPools.Providers.List(parent).Pages,
			func(p *iam.ListWorkloadIdentityPoolProvidersResponse) []*iam.WorkloadIdentityPoolProvider {
				return p.WorkloadIdentityPoolProviders
			},
			func(p *iam.ListWorkloadIdentityPoolProvidersResponse, items []*iam.WorkloadIdentityPoolProvider) {
				p.WorkloadIdentityPoolProviders = items
			},
			func(p *iam.ListWorkloadIdentityPoolProvidersResponse) { p.NextPageToken = "" },
		)
	case "serviceusage.ListServices":
		svc, e := serviceusage.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Services.List("projects/"+project).Filter("state:ENABLED").Pages,
			func(p *serviceusage.ListServicesResponse) []*serviceusage.GoogleApiServiceusageV1Service {
				return p.Services
			},
			func(p *serviceusage.ListServicesResponse, items []*serviceusage.GoogleApiServiceusageV1Service) {
				p.Services = items
			},
			func(p *serviceusage.ListServicesResponse) { p.NextPageToken = "" },
		)
	case "storage.ListBuckets":
		svc, e := storage.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Buckets.List(project).Pages,
			func(p *storage.Buckets) []*storage.Bucket { return p.Items },
			func(p *storage.Buckets, items []*storage.Bucket) { p.Items = items },
			func(p *storage.Buckets) { p.NextPageToken = "" },
		)
	case "storage.GetBucket":
		svc, e := storage.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		name, e := requiredInput(req, "Resource")
		if e != nil {
			return nil, e
		}
		v, err = svc.Buckets.Get(name).Context(ctx).Do()
	case "storage.GetBucketIamPolicy":
		svc, e := storage.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		name, e := requiredInput(req, "Resource")
		if e != nil {
			return nil, e
		}
		v, err = svc.Buckets.GetIamPolicy(name).Context(ctx).Do()
	case "compute.ListNetworks":
		svc, e := compute.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Networks.List(project).Pages,
			func(p *compute.NetworkList) []*compute.Network { return p.Items },
			func(p *compute.NetworkList, items []*compute.Network) { p.Items = items },
			func(p *compute.NetworkList) { p.NextPageToken = "" },
		)
	case "compute.ListFirewalls":
		svc, e := compute.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Firewalls.List(project).Pages,
			func(p *compute.FirewallList) []*compute.Firewall { return p.Items },
			func(p *compute.FirewallList, items []*compute.Firewall) { p.Items = items },
			func(p *compute.FirewallList) { p.NextPageToken = "" },
		)
	case "compute.AggregatedListInstances":
		svc, e := compute.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = pageInstances(ctx, svc.Instances.AggregatedList(project).Pages)
	case "compute.AggregatedListDisks":
		svc, e := compute.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = pageDisks(ctx, svc.Disks.AggregatedList(project).Pages)
	case "compute.AggregatedListVpnTunnels":
		svc, e := compute.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = pageVPNTunnels(ctx, svc.VpnTunnels.AggregatedList(project).Pages)
	case "compute.ListSubnetworks":
		svc, e := compute.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Subnetworks.List(project, loc).Pages,
			func(p *compute.SubnetworkList) []*compute.Subnetwork { return p.Items },
			func(p *compute.SubnetworkList, items []*compute.Subnetwork) { p.Items = items },
			func(p *compute.SubnetworkList) { p.NextPageToken = "" },
		)
	case "compute.ListAddresses":
		svc, e := compute.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Addresses.List(project, loc).Pages,
			func(p *compute.AddressList) []*compute.Address { return p.Items },
			func(p *compute.AddressList, items []*compute.Address) { p.Items = items },
			func(p *compute.AddressList) { p.NextPageToken = "" },
		)
	case "compute.ListForwardingRules":
		svc, e := compute.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.ForwardingRules.List(project, loc).Pages,
			func(p *compute.ForwardingRuleList) []*compute.ForwardingRule { return p.Items },
			func(p *compute.ForwardingRuleList, items []*compute.ForwardingRule) { p.Items = items },
			func(p *compute.ForwardingRuleList) { p.NextPageToken = "" },
		)
	case "compute.ListRouters":
		svc, e := compute.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Routers.List(project, loc).Pages,
			func(p *compute.RouterList) []*compute.Router { return p.Items },
			func(p *compute.RouterList, items []*compute.Router) { p.Items = items },
			func(p *compute.RouterList) { p.NextPageToken = "" },
		)
	case "dns.ListManagedZones":
		svc, e := dns.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.ManagedZones.List(project).Pages,
			func(p *dns.ManagedZonesListResponse) []*dns.ManagedZone { return p.ManagedZones },
			func(p *dns.ManagedZonesListResponse, items []*dns.ManagedZone) { p.ManagedZones = items },
			func(p *dns.ManagedZonesListResponse) { p.NextPageToken = "" },
		)
	case "logging.ListSinks":
		svc, e := logging.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Sinks.List("projects/"+project).Pages,
			func(p *logging.ListSinksResponse) []*logging.LogSink { return p.Sinks },
			func(p *logging.ListSinksResponse, items []*logging.LogSink) { p.Sinks = items },
			func(p *logging.ListSinksResponse) { p.NextPageToken = "" },
		)
	case "pubsub.ListTopics":
		svc, e := pubsub.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Projects.Topics.List("projects/"+project).Pages,
			func(p *pubsub.ListTopicsResponse) []*pubsub.Topic { return p.Topics },
			func(p *pubsub.ListTopicsResponse, items []*pubsub.Topic) { p.Topics = items },
			func(p *pubsub.ListTopicsResponse) { p.NextPageToken = "" },
		)
	case "pubsub.GetTopicIamPolicy":
		svc, e := pubsub.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		name, e := requiredInput(req, "Resource")
		if e != nil {
			return nil, e
		}
		v, err = svc.Projects.Topics.GetIamPolicy(name).Context(ctx).Do()
	case "sqladmin.ListInstances":
		svc, e := sqladmin.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Instances.List(project).Pages,
			func(p *sqladmin.InstancesListResponse) []*sqladmin.DatabaseInstance { return p.Items },
			func(p *sqladmin.InstancesListResponse, items []*sqladmin.DatabaseInstance) { p.Items = items },
			func(p *sqladmin.InstancesListResponse) { p.NextPageToken = "" },
		)
	case "container.ListClusters":
		svc, e := container.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		parent := "projects/" + project + "/locations/" + loc
		// ListClusters has no Pages method in google.golang.org/api v0.298.0.
		v, err = svc.Projects.Locations.Clusters.List(parent).Context(ctx).Do()
	case "run.ListServices":
		svc, e := run.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		parent := "projects/" + project + "/locations/" + loc
		v, err = concatPages(ctx, svc.Projects.Locations.Services.List(parent).Pages,
			func(p *run.GoogleCloudRunV2ListServicesResponse) []*run.GoogleCloudRunV2Service { return p.Services },
			func(p *run.GoogleCloudRunV2ListServicesResponse, items []*run.GoogleCloudRunV2Service) {
				p.Services = items
			},
			func(p *run.GoogleCloudRunV2ListServicesResponse) { p.NextPageToken = "" },
		)
	case "run.GetServiceIamPolicy":
		svc, e := run.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		name, e := requiredInput(req, "Resource")
		if e != nil {
			return nil, e
		}
		v, err = svc.Projects.Locations.Services.GetIamPolicy(name).Context(ctx).Do()
	case "cloudfunctions.ListFunctions":
		svc, e := cloudfunctions.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		parent := "projects/" + project + "/locations/" + loc
		v, err = concatPages(ctx, svc.Projects.Locations.Functions.List(parent).Pages,
			func(p *cloudfunctions.ListFunctionsResponse) []*cloudfunctions.Function { return p.Functions },
			func(p *cloudfunctions.ListFunctionsResponse, items []*cloudfunctions.Function) { p.Functions = items },
			func(p *cloudfunctions.ListFunctionsResponse) { p.NextPageToken = "" },
		)
	case "cloudfunctions.GetFunctionIamPolicy":
		svc, e := cloudfunctions.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		name, e := requiredInput(req, "Resource")
		if e != nil {
			return nil, e
		}
		v, err = svc.Projects.Locations.Functions.GetIamPolicy(name).Context(ctx).Do()
	case "cloudkms.ListKeyRings":
		svc, e := cloudkms.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		parent := "projects/" + project + "/locations/" + loc
		v, err = concatPages(ctx, svc.Projects.Locations.KeyRings.List(parent).Pages,
			func(p *cloudkms.ListKeyRingsResponse) []*cloudkms.KeyRing { return p.KeyRings },
			func(p *cloudkms.ListKeyRingsResponse, items []*cloudkms.KeyRing) { p.KeyRings = items },
			func(p *cloudkms.ListKeyRingsResponse) { p.NextPageToken = "" },
		)
	case "cloudkms.GetKeyRingIamPolicy":
		svc, e := cloudkms.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		name, e := requiredInput(req, "Resource")
		if e != nil {
			return nil, e
		}
		v, err = svc.Projects.Locations.KeyRings.GetIamPolicy(name).Context(ctx).Do()
	case "cloudkms.ListCryptoKeys":
		svc, e := cloudkms.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		parent, e := requiredInput(req, "Resource")
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Projects.Locations.KeyRings.CryptoKeys.List(parent).Pages,
			func(p *cloudkms.ListCryptoKeysResponse) []*cloudkms.CryptoKey { return p.CryptoKeys },
			func(p *cloudkms.ListCryptoKeysResponse, items []*cloudkms.CryptoKey) { p.CryptoKeys = items },
			func(p *cloudkms.ListCryptoKeysResponse) { p.NextPageToken = "" },
		)
	case "cloudkms.GetCryptoKeyIamPolicy":
		svc, e := cloudkms.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		name, e := requiredInput(req, "Resource")
		if e != nil {
			return nil, e
		}
		v, err = svc.Projects.Locations.KeyRings.CryptoKeys.GetIamPolicy(name).Context(ctx).Do()
	case "secretmanager.ListSecrets":
		svc, e := secretmanager.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		v, err = concatPages(ctx, svc.Projects.Secrets.List("projects/"+project).Pages,
			func(p *secretmanager.ListSecretsResponse) []*secretmanager.Secret { return p.Secrets },
			func(p *secretmanager.ListSecretsResponse, items []*secretmanager.Secret) { p.Secrets = items },
			func(p *secretmanager.ListSecretsResponse) { p.NextPageToken = "" },
		)
	case "secretmanager.GetSecretIamPolicy":
		svc, e := secretmanager.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		name, e := requiredInput(req, "Resource")
		if e != nil {
			return nil, e
		}
		v, err = svc.Projects.Secrets.GetIamPolicy(name).Context(ctx).Do()
	case "artifactregistry.ListRepositories":
		svc, e := artifactregistry.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		parent := "projects/" + project + "/locations/" + loc
		v, err = concatPages(ctx, svc.Projects.Locations.Repositories.List(parent).Pages,
			func(p *artifactregistry.ListRepositoriesResponse) []*artifactregistry.Repository {
				return p.Repositories
			},
			func(p *artifactregistry.ListRepositoriesResponse, items []*artifactregistry.Repository) {
				p.Repositories = items
			},
			func(p *artifactregistry.ListRepositoriesResponse) { p.NextPageToken = "" },
		)
	case "artifactregistry.GetRepositoryIamPolicy":
		svc, e := artifactregistry.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		name, e := requiredInput(req, "Resource")
		if e != nil {
			return nil, e
		}
		v, err = svc.Projects.Locations.Repositories.GetIamPolicy(name).Context(ctx).Do()
	case "orgpolicy.GetEffectivePolicy":
		svc, e := orgpolicy.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		constraint, e := requiredInput(req, "Constraint")
		if e != nil {
			return nil, e
		}
		name := "projects/" + project + "/policies/" + constraint
		v, err = svc.Projects.Policies.GetEffectivePolicy(name).Context(ctx).Do()
	case "apikeys.ListKeys":
		svc, e := apikeys.NewService(ctx, l.opts...)
		if e != nil {
			return nil, e
		}
		parent := "projects/" + project + "/locations/global"
		v, err = concatPages(ctx, svc.Projects.Locations.Keys.List(parent).Pages,
			func(p *apikeys.V2ListKeysResponse) []*apikeys.V2Key { return p.Keys },
			func(p *apikeys.V2ListKeysResponse, items []*apikeys.V2Key) { p.Keys = items },
			func(p *apikeys.V2ListKeysResponse) { p.NextPageToken = "" },
		)
	default:
		return nil, fmt.Errorf("unmapped GCP operation %s", key)
	}
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(v)
	return b, err
}

func requiredInput(req Dump, key string) (string, error) {
	v := ""
	if req.Input != nil {
		v = req.Input[key]
	}
	if v == "" {
		return "", fmt.Errorf("%s.%s requires %s", req.Service, req.Operation, key)
	}
	return v, nil
}

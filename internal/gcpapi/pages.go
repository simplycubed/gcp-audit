package gcpapi

import (
	"context"

	compute "google.golang.org/api/compute/v1"
)

// concatPages returns one list value: item slices concatenated, page token cleared.
func concatPages[T any, E any](
	ctx context.Context,
	pages func(context.Context, func(*T) error) error,
	items func(*T) []E,
	setItems func(*T, []E),
	clearToken func(*T),
) (*T, error) {
	var acc *T
	var all []E
	err := pages(ctx, func(page *T) error {
		if page == nil {
			return nil
		}
		if acc == nil {
			acc = page
		}
		all = append(all, items(page)...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if acc == nil {
		acc = new(T)
	}
	setItems(acc, all)
	clearToken(acc)
	return acc, nil
}

// mergeScoped merges aggregated-list pages by scope key, appending the
// resource slice inside each scope.
func mergeScoped[S any, E any](
	dst map[string]S,
	src map[string]S,
	items func(S) []E,
	join func(cur, next S, combined []E) S,
) map[string]S {
	if dst == nil {
		dst = map[string]S{}
	}
	for k, sv := range src {
		cur, ok := dst[k]
		if !ok {
			dst[k] = sv
			continue
		}
		a, b := items(cur), items(sv)
		combined := make([]E, 0, len(a)+len(b))
		combined = append(combined, a...)
		combined = append(combined, b...)
		dst[k] = join(cur, sv, combined)
	}
	return dst
}

func pageInstances(ctx context.Context, pages func(context.Context, func(*compute.InstanceAggregatedList) error) error) (*compute.InstanceAggregatedList, error) {
	var acc *compute.InstanceAggregatedList
	var items map[string]compute.InstancesScopedList
	var unreach []string
	err := pages(ctx, func(page *compute.InstanceAggregatedList) error {
		if page == nil {
			return nil
		}
		if acc == nil {
			acc = page
		}
		items = mergeScoped(items, page.Items,
			func(s compute.InstancesScopedList) []*compute.Instance { return s.Instances },
			func(cur, next compute.InstancesScopedList, combined []*compute.Instance) compute.InstancesScopedList {
				w := cur.Warning
				if w == nil {
					w = next.Warning
				}
				return compute.InstancesScopedList{Instances: combined, Warning: w}
			},
		)
		unreach = append(unreach, page.Unreachables...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if acc == nil {
		acc = &compute.InstanceAggregatedList{}
	}
	acc.Items = items
	acc.Unreachables = unreach
	acc.NextPageToken = ""
	return acc, nil
}

func pageDisks(ctx context.Context, pages func(context.Context, func(*compute.DiskAggregatedList) error) error) (*compute.DiskAggregatedList, error) {
	var acc *compute.DiskAggregatedList
	var items map[string]compute.DisksScopedList
	var unreach []string
	err := pages(ctx, func(page *compute.DiskAggregatedList) error {
		if page == nil {
			return nil
		}
		if acc == nil {
			acc = page
		}
		items = mergeScoped(items, page.Items,
			func(s compute.DisksScopedList) []*compute.Disk { return s.Disks },
			func(cur, next compute.DisksScopedList, combined []*compute.Disk) compute.DisksScopedList {
				w := cur.Warning
				if w == nil {
					w = next.Warning
				}
				return compute.DisksScopedList{Disks: combined, Warning: w}
			},
		)
		unreach = append(unreach, page.Unreachables...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if acc == nil {
		acc = &compute.DiskAggregatedList{}
	}
	acc.Items = items
	acc.Unreachables = unreach
	acc.NextPageToken = ""
	return acc, nil
}

func pageVPNTunnels(ctx context.Context, pages func(context.Context, func(*compute.VpnTunnelAggregatedList) error) error) (*compute.VpnTunnelAggregatedList, error) {
	var acc *compute.VpnTunnelAggregatedList
	var items map[string]compute.VpnTunnelsScopedList
	var unreach []string
	err := pages(ctx, func(page *compute.VpnTunnelAggregatedList) error {
		if page == nil {
			return nil
		}
		if acc == nil {
			acc = page
		}
		items = mergeScoped(items, page.Items,
			func(s compute.VpnTunnelsScopedList) []*compute.VpnTunnel { return s.VpnTunnels },
			func(cur, next compute.VpnTunnelsScopedList, combined []*compute.VpnTunnel) compute.VpnTunnelsScopedList {
				w := cur.Warning
				if w == nil {
					w = next.Warning
				}
				return compute.VpnTunnelsScopedList{VpnTunnels: combined, Warning: w}
			},
		)
		unreach = append(unreach, page.Unreachables...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if acc == nil {
		acc = &compute.VpnTunnelAggregatedList{}
	}
	acc.Items = items
	acc.Unreachables = unreach
	acc.NextPageToken = ""
	return acc, nil
}

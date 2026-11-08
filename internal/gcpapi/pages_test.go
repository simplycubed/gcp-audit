package gcpapi

import (
	"context"
	"strings"
	"testing"
)

func TestConcatPagesClearsToken(t *testing.T) {
	type page struct {
		Items         []string
		NextPageToken string
	}
	got, err := concatPages(context.Background(), func(_ context.Context, f func(*page) error) error {
		if err := f(&page{Items: []string{"a"}, NextPageToken: "t1"}); err != nil {
			return err
		}
		return f(&page{Items: []string{"b", "c"}, NextPageToken: "t2"})
	}, func(p *page) []string { return p.Items }, func(p *page, items []string) { p.Items = items }, func(p *page) { p.NextPageToken = "" })
	if err != nil {
		t.Fatal(err)
	}
	if got.NextPageToken != "" {
		t.Fatalf("token %q", got.NextPageToken)
	}
	if strings.Join(got.Items, ",") != "a,b,c" {
		t.Fatalf("%v", got.Items)
	}
}

func TestMergeScopedAppendsByKey(t *testing.T) {
	type scope struct {
		Items []string
		Note  string
	}
	join := func(cur, next scope, combined []string) scope {
		note := cur.Note
		if note == "" {
			note = next.Note
		}
		return scope{Items: combined, Note: note}
	}
	items := func(s scope) []string { return s.Items }
	got := mergeScoped(nil, map[string]scope{
		"zones/a": {Items: []string{"i1"}, Note: "first"},
	}, items, join)
	got = mergeScoped(got, map[string]scope{
		"zones/a": {Items: []string{"i2"}, Note: "second"},
		"zones/b": {Items: []string{"b1"}, Note: "b"},
	}, items, join)
	if strings.Join(got["zones/a"].Items, ",") != "i1,i2" || got["zones/a"].Note != "first" {
		t.Fatalf("zones/a %+v", got["zones/a"])
	}
	if strings.Join(got["zones/b"].Items, ",") != "b1" || got["zones/b"].Note != "b" {
		t.Fatalf("zones/b %+v", got["zones/b"])
	}
}

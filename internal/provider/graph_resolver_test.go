package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type fakeTokenCredential struct{}

func (fakeTokenCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestGraphResolverUserUPNUsesOnPremSIDForHybrid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("unexpected authorization header: %s", r.Header.Get("Authorization"))
		}
		expectedPath := "/beta/users/trong-hybrid@day0.sh"
		if r.URL.Path != expectedPath {
			t.Fatalf("unexpected path\nexpected: %s\nactual:   %s", expectedPath, r.URL.Path)
		}
		fmt.Fprint(w, `{"id":"user-id","userPrincipalName":"trong-hybrid@day0.sh","securityIdentifier":"S-1-12-1-1-2-3-4","onPremisesSecurityIdentifier":"S-1-5-21-1-2-3-1001"}`)
	}))
	defer server.Close()

	resolver := &graphPrincipalResolver{
		endpoint:   server.URL,
		apiVersion: "beta",
		scope:      server.URL + "/.default",
		credential: fakeTokenCredential{},
		client:     server.Client(),
	}

	sids, err := resolver.ResolvePrincipalSIDs(context.Background(), "trong-hybrid@day0.sh", "user", "entra_kerberos_hybrid")
	if err != nil {
		t.Fatalf("ResolvePrincipalSIDs returned error: %v", err)
	}
	if len(sids) != 1 || sids[0] != "S-1-5-21-1-2-3-1001" {
		t.Fatalf("unexpected SIDs: %#v", sids)
	}
}

func TestGraphResolverGroupObjectIDUsesOnPremSIDForHybrid(t *testing.T) {
	groupID := "00000000-0000-0000-0000-000000000001"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/beta/groups/" + groupID
		if r.URL.Path != expectedPath {
			t.Fatalf("unexpected path\nexpected: %s\nactual:   %s", expectedPath, r.URL.Path)
		}
		fmt.Fprint(w, `{"id":"`+groupID+`","displayName":"desktop-users","securityIdentifier":"S-1-12-1-1-2-3-4","onPremisesSecurityIdentifier":"S-1-5-21-1-2-3-2001"}`)
	}))
	defer server.Close()

	resolver := &graphPrincipalResolver{
		endpoint:   server.URL,
		apiVersion: "beta",
		scope:      server.URL + "/.default",
		credential: fakeTokenCredential{},
		client:     server.Client(),
	}

	sids, err := resolver.ResolvePrincipalSIDs(context.Background(), groupID, "group", "ad_ds")
	if err != nil {
		t.Fatalf("ResolvePrincipalSIDs returned error: %v", err)
	}
	if len(sids) != 1 || sids[0] != "S-1-5-21-1-2-3-2001" {
		t.Fatalf("unexpected SIDs: %#v", sids)
	}
}

func TestGraphResolverMissingOnPremSIDDiagnostic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"user-id","userPrincipalName":"cloud@day0.sh"}`)
	}))
	defer server.Close()

	resolver := &graphPrincipalResolver{
		endpoint:   server.URL,
		apiVersion: "beta",
		scope:      server.URL + "/.default",
		credential: fakeTokenCredential{},
		client:     server.Client(),
	}

	_, err := resolver.ResolvePrincipalSIDs(context.Background(), "cloud@day0.sh", "user", "entra_kerberos_hybrid")
	if err == nil {
		t.Fatal("expected missing SID error")
	}
	if got := err.Error(); !containsAll(got, "onPremisesSecurityIdentifier", "AD DS", "direct SID") {
		t.Fatalf("diagnostic did not include expected guidance: %s", got)
	}
}

func TestGraphResolverCloudOnlyUserUPNUsesCloudSID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/beta/users/cloud@day0.sh"
		if r.URL.Path != expectedPath {
			t.Fatalf("unexpected path\nexpected: %s\nactual:   %s", expectedPath, r.URL.Path)
		}
		fmt.Fprint(w, `{"id":"user-id","userPrincipalName":"cloud@day0.sh","securityIdentifier":"S-1-12-1-10-20-30-40"}`)
	}))
	defer server.Close()

	resolver := &graphPrincipalResolver{
		endpoint:   server.URL,
		apiVersion: "beta",
		scope:      server.URL + "/.default",
		credential: fakeTokenCredential{},
		client:     server.Client(),
	}

	sids, err := resolver.ResolvePrincipalSIDs(context.Background(), "cloud@day0.sh", "user", "entra_kerberos_cloud_only")
	if err != nil {
		t.Fatalf("ResolvePrincipalSIDs returned error: %v", err)
	}
	if len(sids) != 1 || sids[0] != "S-1-12-1-10-20-30-40" {
		t.Fatalf("unexpected SIDs: %#v", sids)
	}
}

func TestGraphResolverCloudOnlyPreviewGroupObjectIDUsesCloudSID(t *testing.T) {
	groupID := "00000000-0000-0000-0000-000000000001"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/beta/groups/" + groupID
		if r.URL.Path != expectedPath {
			t.Fatalf("unexpected path\nexpected: %s\nactual:   %s", expectedPath, r.URL.Path)
		}
		fmt.Fprint(w, `{"id":"`+groupID+`","displayName":"cloud-users","securityIdentifier":"S-1-12-1-50-60-70-80"}`)
	}))
	defer server.Close()

	resolver := &graphPrincipalResolver{
		endpoint:   server.URL,
		apiVersion: "beta",
		scope:      server.URL + "/.default",
		credential: fakeTokenCredential{},
		client:     server.Client(),
	}

	sids, err := resolver.ResolvePrincipalSIDs(context.Background(), groupID, "group", "entra_kerberos_cloud_only_preview")
	if err != nil {
		t.Fatalf("ResolvePrincipalSIDs returned error: %v", err)
	}
	if len(sids) != 1 || sids[0] != "S-1-12-1-50-60-70-80" {
		t.Fatalf("unexpected SIDs: %#v", sids)
	}
}

func TestGraphResolverMissingCloudSIDDiagnostic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"user-id","userPrincipalName":"cloud@day0.sh"}`)
	}))
	defer server.Close()

	resolver := &graphPrincipalResolver{
		endpoint:   server.URL,
		apiVersion: "beta",
		scope:      server.URL + "/.default",
		credential: fakeTokenCredential{},
		client:     server.Client(),
	}

	_, err := resolver.ResolvePrincipalSIDs(context.Background(), "cloud@day0.sh", "user", "entra_kerberos_cloud_only")
	if err == nil {
		t.Fatal("expected missing cloud SID error")
	}
	if got := err.Error(); !containsAll(got, "securityIdentifier", "cloud SID", "direct SID") {
		t.Fatalf("diagnostic did not include expected guidance: %s", got)
	}
}

func TestGraphResolverRejectsGroupUPN(t *testing.T) {
	resolver := &graphPrincipalResolver{}

	_, err := resolver.ResolvePrincipalSIDs(context.Background(), "group@day0.sh", "group", "entra_kerberos_hybrid")
	if err == nil {
		t.Fatal("expected group UPN error")
	}
}

func containsAll(value string, fragments ...string) bool {
	for _, fragment := range fragments {
		if !strings.Contains(value, fragment) {
			return false
		}
	}
	return true
}

package provider

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

type fakePrincipalResolver struct {
	resolved map[string][]string
	calls    int
}

func (r *fakePrincipalResolver) ResolvePrincipalSIDs(ctx context.Context, principalID string, principalType string, identityMode string) ([]string, error) {
	r.calls++
	key := fmt.Sprintf("%s:%s:%s", identityMode, principalType, principalID)
	sids, ok := r.resolved[key]
	if !ok {
		return nil, fmt.Errorf("unexpected principal lookup %s", key)
	}
	return sids, nil
}

func TestBuildManagedACEs(t *testing.T) {
	resolver := &fakePrincipalResolver{}
	aces, err := buildManagedACEs(context.Background(), []aceInput{
		{
			PrincipalID:   "SY",
			PrincipalType: "sid",
			Type:          "allow",
			Rights:        "full_control",
			AppliesTo:     "this_folder_subfolders_files",
		},
		{
			PrincipalID:   "CO",
			PrincipalType: "sid",
			Type:          "allow",
			Rights:        "modify",
			AppliesTo:     "subfolders_files_only",
		},
		{
			PrincipalID:    "BA",
			PrincipalType:  "sid",
			Type:           "deny",
			AdvancedRights: []string{"read_data", "write_data", "delete"},
			Flags:          "CI",
		},
		{
			PrincipalID:   "SY",
			PrincipalType: "sid",
			Type:          "allow",
			Rights:        "full_control",
			AppliesTo:     "this_folder_subfolders_files",
		},
	}, "", resolver)
	if err != nil {
		t.Fatalf("buildManagedACEs returned error: %v", err)
	}

	expected := []string{
		"(D;CI;0x10003;;;BA)",
		"(A;OICI;FA;;;SY)",
		"(A;OICIIO;0x1301bf;;;CO)",
	}
	if !reflect.DeepEqual(expected, aces) {
		t.Fatalf("unexpected ACEs\nexpected: %#v\nactual:   %#v", expected, aces)
	}
	if resolver.calls != 0 {
		t.Fatalf("SID-only ACEs should not call resolver, got %d calls", resolver.calls)
	}
}

func TestBuildManagedACEsResolvesGraphPrincipals(t *testing.T) {
	resolver := &fakePrincipalResolver{
		resolved: map[string][]string{
			"entra_kerberos_hybrid:user:trong-hybrid@day0.sh":                  {"S-1-5-21-1-2-3-1001"},
			"entra_kerberos_hybrid:group:00000000-0000-0000-0000-000000000001": {"S-1-5-21-1-2-3-2001"},
		},
	}

	aces, err := buildManagedACEs(context.Background(), []aceInput{
		{
			PrincipalID:   "trong-hybrid@day0.sh",
			PrincipalType: "user",
			Rights:        "modify",
			AppliesTo:     "this_folder_only",
		},
		{
			PrincipalID:   "00000000-0000-0000-0000-000000000001",
			PrincipalType: "group",
			Rights:        "full_control",
			AppliesTo:     "this_folder_subfolders_files",
		},
	}, "entra_kerberos_hybrid", resolver)
	if err != nil {
		t.Fatalf("buildManagedACEs returned error: %v", err)
	}

	expected := []string{
		"(A;;0x1301bf;;;S-1-5-21-1-2-3-1001)",
		"(A;OICI;FA;;;S-1-5-21-1-2-3-2001)",
	}
	if !reflect.DeepEqual(expected, aces) {
		t.Fatalf("unexpected ACEs\nexpected: %#v\nactual:   %#v", expected, aces)
	}
}

func TestBuildManagedACEsRequiresIdentityModeForGraph(t *testing.T) {
	_, err := buildManagedACEs(context.Background(), []aceInput{
		{PrincipalID: "00000000-0000-0000-0000-000000000000", PrincipalType: "group"},
	}, "", &fakePrincipalResolver{})
	if err == nil {
		t.Fatal("expected identity_mode error")
	}
}

func TestMergeAdditiveSDDLPreservesSACL(t *testing.T) {
	existing := "O:BAG:SYD:P(A;;FA;;;SY)S:(AU;SA;FA;;;WD)"
	merged, missing, err := mergeAdditiveSDDL(existing, []string{"(A;;FA;;;SY)", "(A;;FR;;;BU)"})
	if err != nil {
		t.Fatalf("mergeAdditiveSDDL returned error: %v", err)
	}

	if len(missing) != 1 || missing[0] != "(A;;FR;;;BU)" {
		t.Fatalf("unexpected missing ACEs: %#v", missing)
	}

	expected := "O:BAG:SYD:P(A;;FA;;;SY)(A;;FR;;;BU)S:(AU;SA;FA;;;WD)"
	if merged != expected {
		t.Fatalf("unexpected merged SDDL\nexpected: %s\nactual:   %s", expected, merged)
	}
}

func TestBuildAuthoritativeSDDL(t *testing.T) {
	sddl, err := buildAuthoritativeSDDL("O:BAG:SYD:AI(A;;FR;;;BU)S:(AU;SA;FA;;;WD)", []string{"(A;;FA;;;SY)"}, "preserve", "SY", true)
	if err != nil {
		t.Fatalf("buildAuthoritativeSDDL returned error: %v", err)
	}

	expected := "O:BAG:SYD:P(A;;FA;;;SY)S:(AU;SA;FA;;;WD)"
	if sddl != expected {
		t.Fatalf("unexpected authoritative SDDL\nexpected: %s\nactual:   %s", expected, sddl)
	}
}

func TestRemoveManagedACEsFromSDDLPreservesUnknownACEsAndSACL(t *testing.T) {
	existing := "O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FR;;;BU)(A;OICI;FA;;;BA)S:(AU;SA;FA;;;WD)"
	managed := []string{"(A;;FA;;;SY)", "(A;OICI;FA;;;BA)"}

	updated, removed, err := removeManagedACEsFromSDDL(existing, managed)
	if err != nil {
		t.Fatalf("removeManagedACEsFromSDDL returned error: %v", err)
	}

	expectedRemoved := []string{"(A;;FA;;;SY)", "(A;OICI;FA;;;BA)"}
	if !reflect.DeepEqual(expectedRemoved, removed) {
		t.Fatalf("unexpected removed ACEs\nexpected: %#v\nactual:   %#v", expectedRemoved, removed)
	}

	expected := "O:BAG:SYD:PAI(A;;FR;;;BU)S:(AU;SA;FA;;;WD)"
	if updated != expected {
		t.Fatalf("unexpected updated SDDL\nexpected: %s\nactual:   %s", expected, updated)
	}
}

func TestRemoveManagedACEsFromSDDLNoMatchDoesNotChangeSDDL(t *testing.T) {
	existing := "O:BAG:SYD:AI(A;;FR;;;BU)S:(AU;SA;FA;;;WD)"
	updated, removed, err := removeManagedACEsFromSDDL(existing, []string{"(A;;FA;;;SY)"})
	if err != nil {
		t.Fatalf("removeManagedACEsFromSDDL returned error: %v", err)
	}

	if len(removed) != 0 {
		t.Fatalf("expected no removed ACEs, got %#v", removed)
	}
	if updated != existing {
		t.Fatalf("expected SDDL to stay unchanged\nexpected: %s\nactual:   %s", existing, updated)
	}
}

func TestPopulateComputedMissingManagedACEsList(t *testing.T) {
	model := populateComputed(
		FileACLResourceModel{},
		fileACLTarget{
			StorageAccountName: "sttest",
			ShareName:          "profiles",
			Path:               "/",
			ResourceType:       "directory",
		},
		"O:BAG:SYD:(A;;FA;;;SY)",
		"O:BAG:SYD:",
		"permission-key",
		[]string{"(A;;FA;;;SY)"},
	)

	var missing []string
	diags := model.MissingManagedACEs.ElementsAs(context.Background(), &missing, false)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	expected := []string{"(A;;FA;;;SY)"}
	if !reflect.DeepEqual(expected, missing) {
		t.Fatalf("unexpected missing ACEs\nexpected: %#v\nactual:   %#v", expected, missing)
	}
}

func TestStorageAccountNameFromResourceID(t *testing.T) {
	name, err := storageAccountNameFromResourceID("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Storage/storageAccounts/sttest")
	if err != nil {
		t.Fatalf("storageAccountNameFromResourceID returned error: %v", err)
	}
	if name != "sttest" {
		t.Fatalf("unexpected storage account name\nexpected: sttest\nactual:   %s", name)
	}
}

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const defaultRootDirectorySDDL = "O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;;0x1200A9;;;BU)(A;OICIIO;0x1200A9;;;BU)(A;OICI;0x1301BF;;;AU)(A;OICI;FA;;;SY)(A;;FA;;;SY)(A;OICIIO;FA;;;CO)"

var (
	sidPattern           = regexp.MustCompile(`^S-1-(\d+-){1,14}\d+$`)
	guidPattern          = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	upnPattern           = regexp.MustCompile(`^[^@]+@[^.]+\..+$`)
	sddlSectionPattern   = regexp.MustCompile(`[OGDS]:`)
	sddlACEPattern       = regexp.MustCompile(`\([^()]+\)`)
	supportedSDDLAliases = map[string]struct{}{
		"SY": {},
		"CO": {},
		"BA": {},
		"BU": {},
		"AU": {},
		"WD": {},
	}
)

var namedRights = map[string]string{
	"full_control":         "FA",
	"modify":               "0x1301bf",
	"read_and_execute":     "FRFX",
	"list_folder_contents": "FRFX",
	"read":                 "FR",
	"write":                "FW",
}

var advancedRights = map[string]uint32{
	"read_data":                 0x000001,
	"list_directory":            0x000001,
	"write_data":                0x000002,
	"add_file":                  0x000002,
	"append_data":               0x000004,
	"add_subdirectory":          0x000004,
	"read_extended_attributes":  0x000008,
	"write_extended_attributes": 0x000010,
	"execute":                   0x000020,
	"traverse":                  0x000020,
	"delete_child":              0x000040,
	"read_attributes":           0x000080,
	"write_attributes":          0x000100,
	"delete":                    0x010000,
	"read_permissions":          0x020000,
	"change_permissions":        0x040000,
	"take_ownership":            0x080000,
	"synchronize":               0x100000,
}

var appliesToFlags = map[string]string{
	"this_folder_only":             "",
	"this_folder_subfolders_files": "OICI",
	"subfolders_files_only":        "OICIIO",
	"this_folder_subfolders":       "CI",
	"this_folder_files":            "OI",
	"subfolders_only":              "CIIO",
	"files_only":                   "OIIO",
}

type aceInput struct {
	PrincipalID    string
	PrincipalType  string
	Type           string
	Rights         string
	AdvancedRights []string
	AppliesTo      string
	Flags          string
}

type principalResolver interface {
	ResolvePrincipalSIDs(ctx context.Context, principalID string, principalType string, identityMode string) ([]string, error)
}

func isSIDOrAlias(value string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	if _, ok := supportedSDDLAliases[normalized]; ok {
		return true
	}
	return sidPattern.MatchString(normalized)
}

func buildManagedACEs(ctx context.Context, entries []aceInput, identityMode string, resolver principalResolver) ([]string, error) {
	aces := make([]string, 0, len(entries))
	seen := make(map[string]struct{})

	for _, entry := range entries {
		sids, err := resolvePrincipalSIDs(ctx, entry, identityMode, resolver)
		if err != nil {
			return nil, err
		}

		rights, err := resolveRights(entry)
		if err != nil {
			return nil, err
		}

		flags, err := resolveFlags(entry)
		if err != nil {
			return nil, err
		}

		aceType := "A"
		switch entry.Type {
		case "", "allow":
			aceType = "A"
		case "deny":
			aceType = "D"
		default:
			return nil, fmt.Errorf("unsupported access_control_entry.type %q; supported values are allow and deny", entry.Type)
		}

		for _, sid := range sids {
			ace := fmt.Sprintf("(%s;%s;%s;;;%s)", aceType, flags, rights, sid)
			if _, ok := seen[ace]; ok {
				continue
			}
			seen[ace] = struct{}{}
			aces = append(aces, ace)
		}
	}

	sort.SliceStable(aces, func(i, j int) bool {
		leftDeny := strings.HasPrefix(aces[i], "(D;")
		rightDeny := strings.HasPrefix(aces[j], "(D;")
		if leftDeny != rightDeny {
			return leftDeny
		}
		return aces[i] < aces[j]
	})

	return aces, nil
}

func resolvePrincipalSIDs(ctx context.Context, entry aceInput, identityMode string, resolver principalResolver) ([]string, error) {
	principalID := strings.TrimSpace(entry.PrincipalID)
	principalType := strings.TrimSpace(entry.PrincipalType)

	switch principalType {
	case "sid":
		if !isSIDOrAlias(principalID) {
			return nil, fmt.Errorf("principal_id %q is not a SID or supported SDDL alias, but principal_type is sid", principalID)
		}
		if _, ok := supportedSDDLAliases[strings.ToUpper(principalID)]; ok {
			return []string{strings.ToUpper(principalID)}, nil
		}
		return []string{principalID}, nil
	case "user", "group":
		if identityMode == "" {
			return nil, fmt.Errorf("identity_mode is required when principal_type is %q and principal_id must be resolved through Microsoft Graph", principalType)
		}
		if resolver == nil {
			return nil, fmt.Errorf("Microsoft Graph resolver is not configured; pass a direct SID with principal_type = \"sid\"")
		}
		return resolver.ResolvePrincipalSIDs(ctx, principalID, principalType, identityMode)
	default:
		return nil, fmt.Errorf("unsupported principal_type %q; supported values are sid, user, and group", principalType)
	}
}

func resolveRights(entry aceInput) (string, error) {
	rights := strings.TrimSpace(entry.Rights)
	if rights != "" && len(entry.AdvancedRights) > 0 {
		return "", fmt.Errorf("rights and advanced_rights are mutually exclusive")
	}

	if len(entry.AdvancedRights) > 0 {
		var mask uint32
		for _, right := range entry.AdvancedRights {
			value, ok := advancedRights[strings.TrimSpace(strings.ToLower(right))]
			if !ok {
				return "", fmt.Errorf("unsupported advanced_rights value %q", right)
			}
			mask |= value
		}
		return fmt.Sprintf("0x%X", mask), nil
	}

	if rights == "" {
		rights = "read"
	}

	normalized := strings.ToLower(rights)
	if named, ok := namedRights[normalized]; ok {
		return named, nil
	}

	switch strings.ToUpper(rights) {
	case "FA", "FR", "FW", "FRFX":
		return strings.ToUpper(rights), nil
	}

	if regexp.MustCompile(`(?i)^0x[0-9a-f]+$`).MatchString(rights) {
		return strings.ToLower(rights), nil
	}

	return "", fmt.Errorf("unsupported rights value %q", rights)
}

func resolveFlags(entry aceInput) (string, error) {
	if strings.TrimSpace(entry.Flags) != "" {
		return strings.TrimSpace(entry.Flags), nil
	}

	appliesTo := strings.TrimSpace(entry.AppliesTo)
	if appliesTo == "" {
		appliesTo = "this_folder_subfolders_files"
	}
	flags, ok := appliesToFlags[appliesTo]
	if !ok {
		return "", fmt.Errorf("unsupported applies_to value %q", appliesTo)
	}
	return flags, nil
}

func splitSDDLSections(sddl string) map[string]string {
	sections := make(map[string]string)
	markers := sddlSectionPattern.FindAllStringIndex(sddl, -1)
	for i, marker := range markers {
		name := sddl[marker[0] : marker[0]+1]
		start := marker[1]
		end := len(sddl)
		if i+1 < len(markers) {
			end = markers[i+1][0]
		}
		sections[name] = sddl[start:end]
	}
	return sections
}

func mergeAdditiveSDDL(existingSDDL string, newACEs []string) (string, []string, error) {
	sections := splitSDDLSections(existingSDDL)
	dacl, ok := sections["D"]
	if !ok {
		return "", nil, fmt.Errorf("existing Azure Files ACL does not include a DACL section")
	}

	existingACEs := sddlACEPattern.FindAllString(dacl, -1)
	existingSet := make(map[string]struct{}, len(existingACEs))
	for _, ace := range existingACEs {
		existingSet[ace] = struct{}{}
	}

	missing := make([]string, 0)
	for _, ace := range newACEs {
		if _, ok := existingSet[ace]; !ok {
			missing = append(missing, ace)
		}
	}

	if len(missing) == 0 {
		return rebuildSDDL(sections), missing, nil
	}

	daclPrefix := strings.TrimSpace(sddlACEPattern.ReplaceAllString(dacl, ""))
	sections["D"] = daclPrefix + strings.Join(existingACEs, "") + strings.Join(missing, "")
	return rebuildSDDL(sections), missing, nil
}

func removeManagedACEsFromSDDL(existingSDDL string, managedACEs []string) (string, []string, error) {
	sections := splitSDDLSections(existingSDDL)
	dacl, ok := sections["D"]
	if !ok {
		return "", nil, fmt.Errorf("existing Azure Files ACL does not include a DACL section")
	}

	managedSet := make(map[string]struct{}, len(managedACEs))
	for _, ace := range managedACEs {
		managedSet[ace] = struct{}{}
	}

	existingACEs := sddlACEPattern.FindAllString(dacl, -1)
	keptACEs := make([]string, 0, len(existingACEs))
	removedACEs := make([]string, 0)
	removedSet := make(map[string]struct{})

	for _, ace := range existingACEs {
		if _, ok := managedSet[ace]; ok {
			if _, alreadyRemoved := removedSet[ace]; !alreadyRemoved {
				removedACEs = append(removedACEs, ace)
				removedSet[ace] = struct{}{}
			}
			continue
		}
		keptACEs = append(keptACEs, ace)
	}

	if len(removedACEs) == 0 {
		return rebuildSDDL(sections), removedACEs, nil
	}

	daclPrefix := strings.TrimSpace(sddlACEPattern.ReplaceAllString(dacl, ""))
	sections["D"] = daclPrefix + strings.Join(keptACEs, "")
	return rebuildSDDL(sections), removedACEs, nil
}

func buildAuthoritativeSDDL(existingSDDL string, managedACEs []string, ownerSID, groupSID string, daclProtected bool) (string, error) {
	sections := splitSDDLSections(existingSDDL)

	owner := resolveOwnerGroup("owner_sid", ownerSID, sections["O"])
	group := resolveOwnerGroup("group_sid", groupSID, sections["G"])
	if owner == "" || group == "" {
		return "", fmt.Errorf("existing SDDL must include owner and group when owner_sid/group_sid are omitted or preserve")
	}

	daclFlags := ""
	if daclProtected {
		daclFlags = "P"
	}

	sections["O"] = owner
	sections["G"] = group
	sections["D"] = daclFlags + strings.Join(managedACEs, "")
	return rebuildSDDL(sections), nil
}

func resolveOwnerGroup(fieldName, configured, existing string) string {
	value := strings.TrimSpace(configured)
	if value == "" || strings.EqualFold(value, "preserve") {
		return existing
	}
	if _, ok := supportedSDDLAliases[strings.ToUpper(value)]; ok {
		return strings.ToUpper(value)
	}
	return value
}

func rebuildSDDL(sections map[string]string) string {
	var builder strings.Builder
	for _, name := range []string{"O", "G", "D", "S"} {
		if value, ok := sections[name]; ok {
			builder.WriteString(name)
			builder.WriteString(":")
			builder.WriteString(value)
		}
	}
	return builder.String()
}

func sddlHash(sddl string) string {
	sum := sha256.Sum256([]byte(sddl))
	return hex.EncodeToString(sum[:])
}

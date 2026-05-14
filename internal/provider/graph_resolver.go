package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

type graphPrincipalResolver struct {
	endpoint   string
	apiVersion string
	scope      string
	credential azcore.TokenCredential
	client     *http.Client
}

type graphPrincipal struct {
	ID                           string `json:"id"`
	UserPrincipalName            string `json:"userPrincipalName"`
	DisplayName                  string `json:"displayName"`
	OnPremisesSecurityIdentifier string `json:"onPremisesSecurityIdentifier"`
	SecurityIdentifier           string `json:"securityIdentifier"`
}

func newGraphPrincipalResolver(config *ProviderConfig) (*graphPrincipalResolver, error) {
	options := &azidentity.DefaultAzureCredentialOptions{}
	if config.TenantID != "" {
		options.TenantID = config.TenantID
	}

	credential, err := azidentity.NewDefaultAzureCredential(options)
	if err != nil {
		return nil, fmt.Errorf("create Azure default credential for Microsoft Graph: %w", err)
	}

	endpoint := strings.TrimRight(config.GraphEndpoint, "/")
	return &graphPrincipalResolver{
		endpoint:   endpoint,
		apiVersion: strings.Trim(config.GraphAPIVersion, "/"),
		scope:      endpoint + "/.default",
		credential: credential,
		client:     http.DefaultClient,
	}, nil
}

func (r *graphPrincipalResolver) ResolvePrincipalSIDs(ctx context.Context, principalID string, principalType string, identityMode string) ([]string, error) {
	principalID = strings.TrimSpace(principalID)
	principalType = strings.TrimSpace(principalType)

	if !supportedGraphIdentityMode(identityMode) {
		return nil, fmt.Errorf("unsupported identity_mode %q for Microsoft Graph SID resolution", identityMode)
	}

	var principal graphPrincipal
	var description string
	var err error

	switch principalType {
	case "user":
		if !guidPattern.MatchString(principalID) && !upnPattern.MatchString(principalID) {
			return nil, fmt.Errorf("user principal_id %q is unsupported; use a user object ID, user principal name, or direct SID", principalID)
		}
		description = fmt.Sprintf("user %q", principalID)
		principal, err = r.getPrincipal(ctx, "users", principalID, "id,userPrincipalName,securityIdentifier,onPremisesSecurityIdentifier")
	case "group":
		if upnPattern.MatchString(principalID) {
			return nil, fmt.Errorf("UPN lookup is only supported for principal_type = \"user\"; use a group object ID or direct SID")
		}
		if !guidPattern.MatchString(principalID) {
			return nil, fmt.Errorf("group principal_id %q is unsupported; use a group object ID or direct SID. Display name lookup is not supported", principalID)
		}
		description = fmt.Sprintf("group object %q", principalID)
		principal, err = r.getPrincipal(ctx, "groups", principalID, "id,displayName,securityIdentifier,onPremisesSecurityIdentifier")
	default:
		return nil, fmt.Errorf("unsupported principal_type %q for Microsoft Graph SID resolution", principalType)
	}
	if err != nil {
		return nil, err
	}

	sid, err := resolveGraphPrincipalSID(principal, description, identityMode)
	if err != nil {
		return nil, err
	}

	return []string{sid}, nil
}

func supportedGraphIdentityMode(identityMode string) bool {
	switch identityMode {
	case "ad_ds", "entra_domain_services", "entra_kerberos_hybrid", "entra_kerberos_cloud_only", "entra_kerberos_cloud_only_preview":
		return true
	default:
		return false
	}
}

func resolveGraphPrincipalSID(principal graphPrincipal, description string, identityMode string) (string, error) {
	switch identityMode {
	case "ad_ds", "entra_domain_services", "entra_kerberos_hybrid":
		if principal.OnPremisesSecurityIdentifier != "" {
			return principal.OnPremisesSecurityIdentifier, nil
		}

		return "", fmt.Errorf(
			"resolved %s through Microsoft Graph, but onPremisesSecurityIdentifier was not returned. For identity_mode = %q, the principal must be synced from AD DS. The identity_mode may be wrong, the object may not be AD-synced, or you can pass a direct SID with principal_type = \"sid\"",
			description,
			identityMode,
		)
	case "entra_kerberos_cloud_only", "entra_kerberos_cloud_only_preview":
		if principal.SecurityIdentifier != "" {
			return principal.SecurityIdentifier, nil
		}

		return "", fmt.Errorf(
			"resolved %s through Microsoft Graph, but securityIdentifier was not returned. For identity_mode = %q, the principal must expose a Microsoft Entra cloud SID. The identity_mode may be wrong, the object may not be usable for cloud-only Azure Files ACLs, or you can pass a direct SID with principal_type = \"sid\"",
			description,
			identityMode,
		)
	default:
		return "", fmt.Errorf("unsupported identity_mode %q for Microsoft Graph SID resolution", identityMode)
	}
}

func (r *graphPrincipalResolver) getPrincipal(ctx context.Context, collection string, principalID string, selectFields string) (graphPrincipal, error) {
	token, err := r.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{r.scope}})
	if err != nil {
		return graphPrincipal{}, fmt.Errorf("get Microsoft Graph token: %w", err)
	}

	requestURL := fmt.Sprintf(
		"%s/%s/%s/%s?$select=%s",
		r.endpoint,
		r.apiVersion,
		collection,
		url.PathEscape(principalID),
		url.QueryEscape(selectFields),
	)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return graphPrincipal{}, fmt.Errorf("create Microsoft Graph request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token.Token)
	request.Header.Set("Accept", "application/json")

	response, err := r.client.Do(request)
	if err != nil {
		return graphPrincipal{}, fmt.Errorf("call Microsoft Graph: %w", err)
	}
	defer response.Body.Close()

	body, readErr := io.ReadAll(response.Body)
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if readErr != nil {
			return graphPrincipal{}, fmt.Errorf("Microsoft Graph request failed with status %s and unreadable response body: %w", response.Status, readErr)
		}
		return graphPrincipal{}, fmt.Errorf("Microsoft Graph request failed with status %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	if readErr != nil {
		return graphPrincipal{}, fmt.Errorf("read Microsoft Graph response: %w", readErr)
	}

	var principal graphPrincipal
	if err := json.Unmarshal(body, &principal); err != nil {
		return graphPrincipal{}, fmt.Errorf("decode Microsoft Graph response: %w", err)
	}
	return principal, nil
}

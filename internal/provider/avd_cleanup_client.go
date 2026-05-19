package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	avdSessionHostAPIVersion = "2024-04-03"
	avdVMAPIVersion          = "2024-07-01"
	avdSessionDeleteAttempts = 12
)

var avdSessionDeleteWait = 5 * time.Second

type avdCleanupClient interface {
	CleanupSessionHostArtifacts(ctx context.Context, config avdCleanupConfig, progress func(string)) error
}

type avdCleanupConfig struct {
	HostPoolID                 string
	ResourceGroupName          string
	SessionHostName            string
	CurrentVMID                string
	AllowCurrentVMPresent      bool
	CleanupAVDSessionHost      bool
	CleanupEntraDevice         bool
	CleanupIntuneManagedDevice bool
	RequireVMAbsent            bool
	ForceUserSessions          bool
}

type avdCleanupHTTPClient struct {
	armEndpoint     string
	graphEndpoint   string
	graphAPIVersion string
	credential      azcore.TokenCredential
	client          *http.Client
}

type avdUserSessionsResponse struct {
	Value []avdUserSession `json:"value"`
}

type avdUserSession struct {
	Name       string `json:"name"`
	Properties struct {
		SessionState string `json:"sessionState"`
	} `json:"properties"`
}

type graphCollectionResponse struct {
	Value []graphCollectionItem `json:"value"`
}

type graphCollectionItem struct {
	ID              string `json:"id"`
	DeviceID        string `json:"deviceId"`
	AzureADDeviceID string `json:"azureADDeviceId"`
}

type azureVMResponse struct {
	Properties struct {
		VMID string `json:"vmId"`
	} `json:"properties"`
}

func newAVDCleanupClient(config *ProviderConfig) (avdCleanupClient, error) {
	options := &azidentity.DefaultAzureCredentialOptions{}
	if config.TenantID != "" {
		options.TenantID = config.TenantID
	}

	credential, err := azidentity.NewDefaultAzureCredential(options)
	if err != nil {
		return nil, fmt.Errorf("create Azure default credential for AVD cleanup: %w", err)
	}

	return &avdCleanupHTTPClient{
		armEndpoint:     strings.TrimRight(config.ARMEndpoint, "/"),
		graphEndpoint:   strings.TrimRight(config.GraphEndpoint, "/"),
		graphAPIVersion: strings.Trim(config.GraphAPIVersion, "/"),
		credential:      credential,
		client:          http.DefaultClient,
	}, nil
}

func (c *avdCleanupHTTPClient) CleanupSessionHostArtifacts(ctx context.Context, config avdCleanupConfig, progress func(string)) error {
	if strings.TrimSpace(config.SessionHostName) == "" {
		return fmt.Errorf("session_host_name must not be empty")
	}

	if !config.CleanupAVDSessionHost && !config.CleanupEntraDevice && !config.CleanupIntuneManagedDevice {
		sendCleanupProgress(progress, "No AVD, Entra, or Intune cleanup targets are enabled.")
		return nil
	}

	resourceID, err := arm.ParseResourceID(config.HostPoolID)
	if err != nil {
		return fmt.Errorf("parse host_pool_id %q: %w", config.HostPoolID, err)
	}
	if resourceID.SubscriptionID == "" {
		return fmt.Errorf("host_pool_id %q must include a subscription ID", config.HostPoolID)
	}

	if config.RequireVMAbsent {
		vm, err := c.azureVM(ctx, resourceID.SubscriptionID, config.ResourceGroupName, config.SessionHostName)
		if err != nil {
			return err
		}
		currentVMID := strings.TrimSpace(config.CurrentVMID)
		if vm.exists && !config.AllowCurrentVMPresent && (currentVMID == "" || !strings.EqualFold(vm.vmID, currentVMID)) {
			return fmt.Errorf("Azure VM %q still exists in resource group %q; refusing to delete AVD, Entra, or Intune artifacts while require_vm_absent is true", config.SessionHostName, config.ResourceGroupName)
		}
		if vm.exists && currentVMID != "" {
			sendCleanupProgress(progress, fmt.Sprintf("Confirmed Azure VM %q is the current VM instance %q.", config.SessionHostName, config.CurrentVMID))
		} else if vm.exists {
			sendCleanupProgress(progress, fmt.Sprintf("Confirmed Azure VM %q exists and allow_current_vm_present is true.", config.SessionHostName))
		} else {
			sendCleanupProgress(progress, fmt.Sprintf("Confirmed Azure VM %q is absent.", config.SessionHostName))
		}
	}

	if config.CleanupAVDSessionHost {
		if err := c.cleanupAVDSessionHost(ctx, config, progress); err != nil {
			return err
		}
	}
	if config.CleanupIntuneManagedDevice {
		if err := c.deleteGraphCollectionItems(ctx, config, "Intune managed device", c.intuneManagedDevicesListURL(config.SessionHostName), c.intuneManagedDeviceDeleteURL, progress); err != nil {
			return err
		}
	}
	if config.CleanupEntraDevice {
		if err := c.deleteGraphCollectionItems(ctx, config, "Entra device", c.entraDevicesListURL(config.SessionHostName), c.entraDeviceDeleteURL, progress); err != nil {
			return err
		}
	}

	return nil
}

type azureVMState struct {
	exists bool
	vmID   string
}

func (c *avdCleanupHTTPClient) azureVM(ctx context.Context, subscriptionID string, resourceGroupName string, vmName string) (azureVMState, error) {
	requestURL := fmt.Sprintf(
		"%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s?api-version=%s",
		c.armEndpoint,
		url.PathEscape(subscriptionID),
		url.PathEscape(resourceGroupName),
		url.PathEscape(vmName),
		url.QueryEscape(avdVMAPIVersion),
	)

	body, statusCode, err := c.doAuthenticatedRequest(ctx, http.MethodGet, requestURL, c.armScope())
	if statusCode == http.StatusNotFound {
		return azureVMState{}, nil
	}
	if err != nil {
		return azureVMState{}, fmt.Errorf("check Azure VM %q existence: %w", vmName, err)
	}

	var response azureVMResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return azureVMState{}, fmt.Errorf("decode Azure VM %q: %w", vmName, err)
	}
	return azureVMState{exists: true, vmID: response.Properties.VMID}, nil
}

func (c *avdCleanupHTTPClient) cleanupAVDSessionHost(ctx context.Context, config avdCleanupConfig, progress func(string)) error {
	for attempt := 1; attempt <= avdSessionDeleteAttempts; attempt++ {
		hasSessions, err := c.cleanupAVDUserSessions(ctx, config, progress)
		if err != nil {
			return err
		}
		if !hasSessions {
			break
		}
		if attempt == avdSessionDeleteAttempts {
			return fmt.Errorf("AVD session host %q still has userSessions after %d cleanup attempts", config.SessionHostName, attempt)
		}
		if err := waitForAVDSessionCleanup(ctx); err != nil {
			return err
		}
	}

	sessionHostURL := fmt.Sprintf(
		"%s%s/sessionHosts/%s?api-version=%s",
		c.armEndpoint,
		config.HostPoolID,
		url.PathEscape(config.SessionHostName),
		url.QueryEscape(avdSessionHostAPIVersion),
	)

	_, statusCode, err := c.doAuthenticatedRequest(ctx, http.MethodDelete, sessionHostURL, c.armScope())
	if statusCode == http.StatusNotFound {
		sendCleanupProgress(progress, fmt.Sprintf("AVD sessionHost record %q was already absent.", config.SessionHostName))
		return nil
	}
	if err != nil {
		for attempt := 2; attempt <= avdSessionDeleteAttempts && statusCode == http.StatusBadRequest; attempt++ {
			if err := waitForAVDSessionCleanup(ctx); err != nil {
				return err
			}
			if _, cleanupErr := c.cleanupAVDUserSessions(ctx, config, progress); cleanupErr != nil {
				return cleanupErr
			}
			_, statusCode, err = c.doAuthenticatedRequest(ctx, http.MethodDelete, sessionHostURL, c.armScope())
			if statusCode == http.StatusNotFound {
				sendCleanupProgress(progress, fmt.Sprintf("AVD sessionHost record %q was already absent.", config.SessionHostName))
				return nil
			}
			if err == nil {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("delete AVD sessionHost record %q: %w", config.SessionHostName, err)
		}
	}

	sendCleanupProgress(progress, fmt.Sprintf("Deleted AVD sessionHost record %q.", config.SessionHostName))
	return nil
}

func (c *avdCleanupHTTPClient) cleanupAVDUserSessions(ctx context.Context, config avdCleanupConfig, progress func(string)) (bool, error) {
	userSessionsURL := fmt.Sprintf(
		"%s%s/sessionHosts/%s/userSessions?api-version=%s",
		c.armEndpoint,
		config.HostPoolID,
		url.PathEscape(config.SessionHostName),
		url.QueryEscape(avdSessionHostAPIVersion),
	)

	body, statusCode, err := c.doAuthenticatedRequest(ctx, http.MethodGet, userSessionsURL, c.armScope())
	if statusCode == http.StatusNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("list AVD userSessions for %q: %w", config.SessionHostName, err)
	}

	var response avdUserSessionsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return false, fmt.Errorf("decode AVD userSessions for %q: %w", config.SessionHostName, err)
	}
	if len(response.Value) == 0 {
		return false, nil
	}
	if err := c.deleteUserSessions(ctx, config, response.Value, progress); err != nil {
		return false, err
	}

	return true, nil
}

func waitForAVDSessionCleanup(ctx context.Context) error {
	timer := time.NewTimer(avdSessionDeleteWait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *avdCleanupHTTPClient) deleteUserSessions(ctx context.Context, config avdCleanupConfig, sessions []avdUserSession, progress func(string)) error {
	for _, session := range sessions {
		if strings.EqualFold(session.Properties.SessionState, "Active") && !config.ForceUserSessions {
			return fmt.Errorf("AVD session host %q has active user sessions; set force_user_sessions = true to delete them during cleanup", config.SessionHostName)
		}
	}

	for _, session := range sessions {
		sessionID := sessionIDFromName(session.Name)
		if sessionID == "" {
			continue
		}

		requestURL := fmt.Sprintf(
			"%s%s/sessionHosts/%s/userSessions/%s?api-version=%s",
			c.armEndpoint,
			config.HostPoolID,
			url.PathEscape(config.SessionHostName),
			url.PathEscape(sessionID),
			url.QueryEscape(avdSessionHostAPIVersion),
		)

		_, statusCode, err := c.doAuthenticatedRequest(ctx, http.MethodDelete, requestURL, c.armScope())
		if statusCode == http.StatusNotFound {
			continue
		}
		if err != nil {
			return fmt.Errorf("delete AVD userSession %q/%s: %w", config.SessionHostName, sessionID, err)
		}
		sendCleanupProgress(progress, fmt.Sprintf("Deleted AVD userSession %q/%s.", config.SessionHostName, sessionID))
	}

	return nil
}

func (c *avdCleanupHTTPClient) deleteGraphCollectionItems(ctx context.Context, config avdCleanupConfig, itemDescription string, listURL string, deleteURL func(string) string, progress func(string)) error {
	body, statusCode, err := c.doAuthenticatedRequest(ctx, http.MethodGet, listURL, c.graphScope())
	if statusCode == http.StatusNotFound {
		sendCleanupProgress(progress, fmt.Sprintf("No matching %s objects were found.", itemDescription))
		return nil
	}
	if err != nil {
		return fmt.Errorf("list matching %s objects: %w", itemDescription, err)
	}

	var response graphCollectionResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("decode matching %s objects: %w", itemDescription, err)
	}

	for _, item := range response.Value {
		if strings.TrimSpace(item.ID) == "" {
			continue
		}
		if graphItemMatchesCurrentVM(item, config.CurrentVMID) {
			sendCleanupProgress(progress, fmt.Sprintf("Skipped current %s %q.", itemDescription, item.ID))
			continue
		}

		_, statusCode, err := c.doAuthenticatedRequest(ctx, http.MethodDelete, deleteURL(item.ID), c.graphScope())
		if statusCode == http.StatusNotFound {
			continue
		}
		if err != nil {
			return fmt.Errorf("delete %s %q: %w", itemDescription, item.ID, err)
		}
		sendCleanupProgress(progress, fmt.Sprintf("Deleted %s %q.", itemDescription, item.ID))
	}

	return nil
}

func graphItemMatchesCurrentVM(item graphCollectionItem, currentVMID string) bool {
	currentVMID = strings.TrimSpace(currentVMID)
	if currentVMID == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(item.DeviceID), currentVMID) ||
		strings.EqualFold(strings.TrimSpace(item.AzureADDeviceID), currentVMID)
}

func (c *avdCleanupHTTPClient) doAuthenticatedRequest(ctx context.Context, method string, requestURL string, scope string) ([]byte, int, error) {
	token, err := c.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		return nil, 0, fmt.Errorf("get access token for %s: %w", scope, err)
	}

	request, err := http.NewRequestWithContext(ctx, method, requestURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("create %s request to %s: %w", method, requestURL, err)
	}
	request.Header.Set("Authorization", "Bearer "+token.Token)
	request.Header.Set("Accept", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("call %s %s: %w", method, requestURL, err)
	}
	defer response.Body.Close()

	body, readErr := io.ReadAll(response.Body)
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if readErr != nil {
			return nil, response.StatusCode, fmt.Errorf("request failed with status %s and unreadable response body: %w", response.Status, readErr)
		}
		return body, response.StatusCode, fmt.Errorf("request failed with status %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	if readErr != nil {
		return nil, response.StatusCode, fmt.Errorf("read response body: %w", readErr)
	}

	return body, response.StatusCode, nil
}

func (c *avdCleanupHTTPClient) entraDevicesListURL(hostname string) string {
	query := url.Values{}
	query.Set("$filter", fmt.Sprintf("displayName eq '%s'", odataStringLiteral(hostname)))
	query.Set("$select", "id,displayName,deviceId")
	return fmt.Sprintf("%s/%s/devices?%s", c.graphEndpoint, c.graphAPIVersion, query.Encode())
}

func (c *avdCleanupHTTPClient) entraDeviceDeleteURL(id string) string {
	return fmt.Sprintf("%s/%s/devices/%s", c.graphEndpoint, c.graphAPIVersion, url.PathEscape(id))
}

func (c *avdCleanupHTTPClient) intuneManagedDevicesListURL(hostname string) string {
	query := url.Values{}
	query.Set("$filter", fmt.Sprintf("deviceName eq '%s'", odataStringLiteral(hostname)))
	query.Set("$select", "id,deviceName,azureADDeviceId")
	return fmt.Sprintf("%s/%s/deviceManagement/managedDevices?%s", c.graphEndpoint, c.graphAPIVersion, query.Encode())
}

func (c *avdCleanupHTTPClient) intuneManagedDeviceDeleteURL(id string) string {
	return fmt.Sprintf("%s/%s/deviceManagement/managedDevices/%s", c.graphEndpoint, c.graphAPIVersion, url.PathEscape(id))
}

func (c *avdCleanupHTTPClient) armScope() string {
	return c.armEndpoint + "/.default"
}

func (c *avdCleanupHTTPClient) graphScope() string {
	return c.graphEndpoint + "/.default"
}

func sessionIDFromName(name string) string {
	parts := strings.Split(strings.Trim(name, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[len(parts)-1])
}

func odataStringLiteral(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func sendCleanupProgress(progress func(string), message string) {
	if progress != nil {
		progress(message)
	}
}

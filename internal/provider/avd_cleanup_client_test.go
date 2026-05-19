package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAVDCleanupNoOpsWhenArtifactsAreMissing(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		assertBearerToken(t, r)
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := testAVDCleanupClient(server)
	err := client.CleanupSessionHostArtifacts(context.Background(), testAVDCleanupConfig("avd-test01"), nil)
	if err != nil {
		t.Fatalf("CleanupSessionHostArtifacts returned error: %v", err)
	}

	expected := []string{
		"GET /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.Compute/virtualMachines/avd-test01",
		"GET /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd/sessionHosts/avd-test01/userSessions",
		"DELETE /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd/sessionHosts/avd-test01",
		"GET /v1.0/deviceManagement/managedDevices",
		"GET /v1.0/devices",
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("unexpected calls\nexpected: %#v\nactual:   %#v", expected, calls)
	}
}

func TestAVDCleanupFailsBeforeIdentityCleanupWhenVMExists(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		assertBearerToken(t, r)
		fmt.Fprint(w, `{"id":"vm-id"}`)
	}))
	defer server.Close()

	client := testAVDCleanupClient(server)
	err := client.CleanupSessionHostArtifacts(context.Background(), testAVDCleanupConfig("avd-test01"), nil)
	if err == nil {
		t.Fatal("expected VM existence error")
	}
	if !strings.Contains(err.Error(), "still exists") {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{
		"GET /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.Compute/virtualMachines/avd-test01",
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("unexpected calls\nexpected: %#v\nactual:   %#v", expected, calls)
	}
}

func TestAVDCleanupAllowsCurrentVMAndSkipsCurrentGraphObjects(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		assertBearerToken(t, r)

		switch {
		case strings.Contains(r.URL.Path, "/virtualMachines/"):
			fmt.Fprint(w, `{"properties":{"vmId":"current-vm-id"}}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/userSessions"):
			http.NotFound(w, r)
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/sessionHosts/"):
			http.NotFound(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/deviceManagement/managedDevices":
			fmt.Fprint(w, `{"value":[{"id":"managed-current","azureADDeviceId":"current-vm-id"},{"id":"managed-old","azureADDeviceId":"old-vm-id"}]}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1.0/deviceManagement/managedDevices/managed-old":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/devices":
			fmt.Fprint(w, `{"value":[{"id":"device-current","deviceId":"current-vm-id"},{"id":"device-old","deviceId":"old-vm-id"}]}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1.0/devices/device-old":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := testAVDCleanupClient(server)
	config := testAVDCleanupConfig("avd-test01")
	config.CurrentVMID = "current-vm-id"

	err := client.CleanupSessionHostArtifacts(context.Background(), config, nil)
	if err != nil {
		t.Fatalf("CleanupSessionHostArtifacts returned error: %v", err)
	}

	expected := []string{
		"GET /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.Compute/virtualMachines/avd-test01",
		"GET /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd/sessionHosts/avd-test01/userSessions",
		"DELETE /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd/sessionHosts/avd-test01",
		"GET /v1.0/deviceManagement/managedDevices",
		"DELETE /v1.0/deviceManagement/managedDevices/managed-old",
		"GET /v1.0/devices",
		"DELETE /v1.0/devices/device-old",
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("unexpected calls\nexpected: %#v\nactual:   %#v", expected, calls)
	}
}

func TestAVDCleanupAllowsExistingVMWhenExplicitlyEnabled(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		assertBearerToken(t, r)

		switch {
		case strings.Contains(r.URL.Path, "/virtualMachines/"):
			fmt.Fprint(w, `{"properties":{"vmId":"new-vm-id"}}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/userSessions"):
			http.NotFound(w, r)
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/sessionHosts/"):
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := testAVDCleanupClient(server)
	config := testAVDCleanupConfig("avd-test01")
	config.AllowCurrentVMPresent = true
	config.CleanupEntraDevice = false
	config.CleanupIntuneManagedDevice = false

	err := client.CleanupSessionHostArtifacts(context.Background(), config, nil)
	if err != nil {
		t.Fatalf("CleanupSessionHostArtifacts returned error: %v", err)
	}

	expected := []string{
		"GET /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.Compute/virtualMachines/avd-test01",
		"GET /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd/sessionHosts/avd-test01/userSessions",
		"DELETE /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd/sessionHosts/avd-test01",
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("unexpected calls\nexpected: %#v\nactual:   %#v", expected, calls)
	}
}

func TestAVDCleanupFailsOnActiveSessionsUnlessForced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearerToken(t, r)
		switch {
		case strings.Contains(r.URL.Path, "/virtualMachines/"):
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/userSessions"):
			fmt.Fprint(w, `{"value":[{"name":"hp/avd-test01/session-1","properties":{"sessionState":"Active"}}]}`)
		default:
			t.Fatalf("unexpected request after active session check: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := testAVDCleanupClient(server)
	config := testAVDCleanupConfig("avd-test01")
	config.ForceUserSessions = false

	err := client.CleanupSessionHostArtifacts(context.Background(), config, nil)
	if err == nil {
		t.Fatal("expected active session error")
	}
	if !strings.Contains(err.Error(), "active user sessions") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAVDCleanupDeletesArtifactsInOrder(t *testing.T) {
	withFastAVDSessionDeleteWait(t)

	var calls []string
	sessionsDeleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		assertBearerToken(t, r)

		switch {
		case strings.Contains(r.URL.Path, "/virtualMachines/"):
			http.NotFound(w, r)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/userSessions"):
			if sessionsDeleted {
				fmt.Fprint(w, `{"value":[]}`)
			} else {
				fmt.Fprint(w, `{"value":[{"name":"hp/avd-test01/1","properties":{"sessionState":"Active"}},{"name":"hp/avd-test01/2","properties":{"sessionState":"Disconnected"}}]}`)
			}
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/userSessions/"):
			sessionsDeleted = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/sessionHosts/"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/deviceManagement/managedDevices":
			assertFilter(t, r.URL.Query(), "deviceName eq 'avd-test01'")
			fmt.Fprint(w, `{"value":[{"id":"managed-1"}]}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1.0/deviceManagement/managedDevices/managed-1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/devices":
			assertFilter(t, r.URL.Query(), "displayName eq 'avd-test01'")
			fmt.Fprint(w, `{"value":[{"id":"device-1"}]}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1.0/devices/device-1":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := testAVDCleanupClient(server)
	config := testAVDCleanupConfig("avd-test01")
	config.ForceUserSessions = true

	err := client.CleanupSessionHostArtifacts(context.Background(), config, nil)
	if err != nil {
		t.Fatalf("CleanupSessionHostArtifacts returned error: %v", err)
	}

	expected := []string{
		"GET /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.Compute/virtualMachines/avd-test01",
		"GET /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd/sessionHosts/avd-test01/userSessions",
		"DELETE /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd/sessionHosts/avd-test01/userSessions/1",
		"DELETE /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd/sessionHosts/avd-test01/userSessions/2",
		"GET /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd/sessionHosts/avd-test01/userSessions",
		"DELETE /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd/sessionHosts/avd-test01",
		"GET /v1.0/deviceManagement/managedDevices",
		"DELETE /v1.0/deviceManagement/managedDevices/managed-1",
		"GET /v1.0/devices",
		"DELETE /v1.0/devices/device-1",
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("unexpected calls\nexpected: %#v\nactual:   %#v", expected, calls)
	}
}

func withFastAVDSessionDeleteWait(t *testing.T) {
	t.Helper()

	previous := avdSessionDeleteWait
	avdSessionDeleteWait = time.Millisecond
	t.Cleanup(func() {
		avdSessionDeleteWait = previous
	})
}

func TestAVDCleanupSkipsDisabledTargets(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		assertBearerToken(t, r)
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := testAVDCleanupClient(server)
	config := testAVDCleanupConfig("avd-test01")
	config.CleanupEntraDevice = false
	config.CleanupIntuneManagedDevice = false

	err := client.CleanupSessionHostArtifacts(context.Background(), config, nil)
	if err != nil {
		t.Fatalf("CleanupSessionHostArtifacts returned error: %v", err)
	}

	expected := []string{
		"GET /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.Compute/virtualMachines/avd-test01",
		"GET /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd/sessionHosts/avd-test01/userSessions",
		"DELETE /subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd/sessionHosts/avd-test01",
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("unexpected calls\nexpected: %#v\nactual:   %#v", expected, calls)
	}
}

func TestAVDCleanupFailsGraphPermissionErrorsForEnabledTargets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearerToken(t, r)
		switch {
		case strings.Contains(r.URL.Path, "/virtualMachines/"):
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/userSessions"):
			http.NotFound(w, r)
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/sessionHosts/"):
			http.NotFound(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/deviceManagement/managedDevices":
			http.Error(w, "missing DeviceManagementManagedDevices.ReadWrite.All", http.StatusForbidden)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := testAVDCleanupClient(server)
	err := client.CleanupSessionHostArtifacts(context.Background(), testAVDCleanupConfig("avd-test01"), nil)
	if err == nil {
		t.Fatal("expected Graph permission error")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "Intune managed device") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func testAVDCleanupClient(server *httptest.Server) *avdCleanupHTTPClient {
	return &avdCleanupHTTPClient{
		armEndpoint:     server.URL,
		graphEndpoint:   server.URL,
		graphAPIVersion: "v1.0",
		credential:      fakeTokenCredential{},
		client:          server.Client(),
	}
}

func testAVDCleanupConfig(hostname string) avdCleanupConfig {
	return avdCleanupConfig{
		HostPoolID:                 "/subscriptions/sub-1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-avd",
		ResourceGroupName:          "rg-avd",
		SessionHostName:            hostname,
		CleanupAVDSessionHost:      true,
		CleanupEntraDevice:         true,
		CleanupIntuneManagedDevice: true,
		RequireVMAbsent:            true,
		ForceUserSessions:          false,
	}
}

func assertBearerToken(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Header.Get("Authorization") != "Bearer test-token" {
		t.Fatalf("unexpected authorization header: %s", r.Header.Get("Authorization"))
	}
}

func assertFilter(t *testing.T, query url.Values, expected string) {
	t.Helper()
	if actual := query.Get("$filter"); actual != expected {
		t.Fatalf("unexpected filter\nexpected: %s\nactual:   %s", expected, actual)
	}
}

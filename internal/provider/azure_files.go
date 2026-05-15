package provider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/directory"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/file"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/share"
)

type fileACLClient interface {
	ReadSDDL(ctx context.Context, target fileACLTarget) (string, string, error)
	SetSDDL(ctx context.Context, target fileACLTarget, sddl string) (string, string, error)
}

type fileACLTarget struct {
	StorageAccountName       string
	StorageAccountResourceID string
	ShareName                string
	Path                     string
	ResourceType             string
}

type azureFilesClient struct {
	config *ProviderConfig
}

func newAzureFilesClient(config *ProviderConfig) fileACLClient {
	return &azureFilesClient{config: config}
}

func (c *azureFilesClient) ReadSDDL(ctx context.Context, target fileACLTarget) (string, string, error) {
	return c.withRetryingShareClient(ctx, target, func(shareClient *share.Client) (string, string, error) {
		permissionKey, err := readPermissionKey(ctx, shareClient, target)
		if err != nil {
			return "", "", err
		}
		if permissionKey == "" {
			return defaultRootDirectorySDDL, "", nil
		}

		permissionFormat := share.FilePermissionFormatSddl
		permission, err := shareClient.GetPermission(ctx, permissionKey, &share.GetPermissionOptions{
			FilePermissionFormat: &permissionFormat,
		})
		if err != nil {
			return "", "", fmt.Errorf("read Azure Files permission for key %q: %w", permissionKey, err)
		}
		if permission.Permission == nil || strings.TrimSpace(*permission.Permission) == "" {
			return "", "", fmt.Errorf("Azure Files returned an empty SDDL value for permission key %q", permissionKey)
		}

		return *permission.Permission, permissionKey, nil
	})
}

func (c *azureFilesClient) SetSDDL(ctx context.Context, target fileACLTarget, sddl string) (string, string, error) {
	_, _, err := c.withRetryingShareClient(ctx, target, func(shareClient *share.Client) (string, string, error) {
		switch target.ResourceType {
		case "directory":
			directoryClient, err := directoryClientForTarget(shareClient, target.Path)
			if err != nil {
				return "", "", err
			}
			permissionFormat := directory.FilePermissionFormatSddl
			_, err = directoryClient.SetProperties(ctx, &directory.SetPropertiesOptions{
				FilePermissions:      &file.Permissions{Permission: to.Ptr(sddl)},
				FilePermissionFormat: &permissionFormat,
			})
			if err != nil {
				return "", "", fmt.Errorf("set Azure Files directory ACL: %w", err)
			}
		case "file":
			fileClient, err := fileClientForTarget(shareClient, target.Path)
			if err != nil {
				return "", "", err
			}
			permissionFormat := file.FilePermissionFormatSddl
			_, err = fileClient.SetHTTPHeaders(ctx, &file.SetHTTPHeadersOptions{
				Permissions:          &file.Permissions{Permission: to.Ptr(sddl)},
				FilePermissionFormat: &permissionFormat,
			})
			if err != nil {
				return "", "", fmt.Errorf("set Azure Files file ACL: %w", err)
			}
		default:
			return "", "", fmt.Errorf("unsupported resource_type %q", target.ResourceType)
		}

		return "", "", nil
	})
	if err != nil {
		return "", "", err
	}

	return c.ReadSDDL(ctx, target)
}

func (c *azureFilesClient) newShareClient(ctx context.Context, target fileACLTarget, useSharedKey bool) (*share.Client, error) {
	storageAccountName := target.StorageAccountName
	shareName := target.ShareName
	accountURL := fmt.Sprintf("https://%s.file.%s", storageAccountName, c.config.StorageEndpointSuffix)
	shareURL := fmt.Sprintf("%s/%s", strings.TrimRight(accountURL, "/"), url.PathEscape(shareName))

	switch c.config.AuthMethod {
	case "oauth":
		if useSharedKey {
			accountKey, err := c.resolveStorageAccountKey(ctx, target)
			if err != nil {
				return nil, err
			}
			credential, err := share.NewSharedKeyCredential(storageAccountName, accountKey)
			if err != nil {
				return nil, fmt.Errorf("create Azure Files shared key credential: %w", err)
			}
			return share.NewClientWithSharedKeyCredential(shareURL, credential, nil)
		}

		credential, err := c.newAzureCredential()
		if err != nil {
			return nil, err
		}
		return share.NewClient(shareURL, credential, &share.ClientOptions{
			FileRequestIntent: to.Ptr(share.TokenIntentBackup),
		})
	case "account_key":
		credential, err := share.NewSharedKeyCredential(storageAccountName, c.config.AccountKey)
		if err != nil {
			return nil, fmt.Errorf("create Azure Files shared key credential: %w", err)
		}
		return share.NewClientWithSharedKeyCredential(shareURL, credential, nil)
	case "sas":
		sasURL := shareURL + "?" + strings.TrimPrefix(c.config.SASToken, "?")
		return share.NewClientWithNoCredential(sasURL, nil)
	default:
		return nil, fmt.Errorf("unsupported auth_method %q", c.config.AuthMethod)
	}
}

func (c *azureFilesClient) withRetryingShareClient(ctx context.Context, target fileACLTarget, operation func(*share.Client) (string, string, error)) (string, string, error) {
	shareClient, err := c.newShareClient(ctx, target, false)
	if err != nil {
		return "", "", err
	}

	sddl, permissionKey, err := operation(shareClient)
	if err == nil || !c.shouldFallbackToSharedKey(target, err) {
		return sddl, permissionKey, err
	}

	shareClient, fallbackErr := c.newShareClient(ctx, target, true)
	if fallbackErr != nil {
		return "", "", fmt.Errorf("%w; fallback to ARM listKeys via storage_account_resource_id %q failed: %v", err, target.StorageAccountResourceID, fallbackErr)
	}

	return operation(shareClient)
}

func (c *azureFilesClient) shouldFallbackToSharedKey(target fileACLTarget, err error) bool {
	if c.config.AuthMethod != "oauth" || strings.TrimSpace(target.StorageAccountResourceID) == "" {
		return false
	}

	var responseErr *azcore.ResponseError
	if !errors.As(err, &responseErr) {
		return false
	}

	return responseErr.StatusCode == 401 || responseErr.StatusCode == 403
}

func (c *azureFilesClient) newAzureCredential() (azcore.TokenCredential, error) {
	options := &azidentity.DefaultAzureCredentialOptions{}
	if c.config.TenantID != "" {
		options.TenantID = c.config.TenantID
	}

	credential, err := azidentity.NewDefaultAzureCredential(options)
	if err != nil {
		return nil, fmt.Errorf("create Azure default credential: %w", err)
	}
	return credential, nil
}

func (c *azureFilesClient) resolveStorageAccountKey(ctx context.Context, target fileACLTarget) (string, error) {
	resourceID, err := arm.ParseResourceID(target.StorageAccountResourceID)
	if err != nil {
		return "", fmt.Errorf("parse storage_account_resource_id %q: %w", target.StorageAccountResourceID, err)
	}

	if resourceID.SubscriptionID == "" || resourceID.ResourceGroupName == "" {
		return "", fmt.Errorf("storage_account_resource_id %q must include both subscription ID and resource group name", target.StorageAccountResourceID)
	}

	credential, err := c.newAzureCredential()
	if err != nil {
		return "", err
	}

	accountsClient, err := armstorage.NewAccountsClient(resourceID.SubscriptionID, credential, nil)
	if err != nil {
		return "", fmt.Errorf("create ARM storage accounts client: %w", err)
	}

	response, err := accountsClient.ListKeys(ctx, resourceID.ResourceGroupName, resourceID.Name, nil)
	if err != nil {
		return "", fmt.Errorf("list storage account keys for %q: %w", target.StorageAccountResourceID, err)
	}

	for _, key := range response.Keys {
		if key == nil || key.Value == nil || strings.TrimSpace(*key.Value) == "" {
			continue
		}
		if key.Permissions != nil && *key.Permissions == armstorage.KeyPermissionRead {
			continue
		}
		return *key.Value, nil
	}

	return "", fmt.Errorf("ARM listKeys returned no usable storage account key for %q", target.StorageAccountResourceID)
}

func storageAccountNameFromResourceID(storageAccountResourceID string) (string, error) {
	resourceID, err := arm.ParseResourceID(storageAccountResourceID)
	if err != nil {
		return "", fmt.Errorf("parse storage_account_resource_id %q: %w", storageAccountResourceID, err)
	}
	if resourceID.Name == "" {
		return "", fmt.Errorf("storage_account_resource_id %q must include the storage account name", storageAccountResourceID)
	}
	return resourceID.Name, nil
}

func readPermissionKey(ctx context.Context, shareClient *share.Client, target fileACLTarget) (string, error) {
	switch target.ResourceType {
	case "directory":
		directoryClient, err := directoryClientForTarget(shareClient, target.Path)
		if err != nil {
			return "", err
		}
		properties, err := directoryClient.GetProperties(ctx, nil)
		if err != nil {
			return "", fmt.Errorf("read Azure Files directory properties: %w", err)
		}
		if properties.FilePermissionKey == nil {
			return "", nil
		}
		return *properties.FilePermissionKey, nil
	case "file":
		fileClient, err := fileClientForTarget(shareClient, target.Path)
		if err != nil {
			return "", err
		}
		properties, err := fileClient.GetProperties(ctx, nil)
		if err != nil {
			return "", fmt.Errorf("read Azure Files file properties: %w", err)
		}
		if properties.FilePermissionKey == nil {
			return "", nil
		}
		return *properties.FilePermissionKey, nil
	default:
		return "", fmt.Errorf("unsupported resource_type %q", target.ResourceType)
	}
}

func directoryClientForTarget(shareClient *share.Client, targetPath string) (*directory.Client, error) {
	normalized := normalizeAzureFilePath(targetPath)
	if normalized == "" {
		return shareClient.NewRootDirectoryClient(), nil
	}
	return shareClient.NewDirectoryClient(normalized), nil
}

func fileClientForTarget(shareClient *share.Client, targetPath string) (*file.Client, error) {
	normalized := normalizeAzureFilePath(targetPath)
	if normalized == "" {
		return nil, fmt.Errorf("file target path must not be /")
	}

	parent := path.Dir(normalized)
	name := path.Base(normalized)
	if parent == "." || parent == "/" {
		parent = ""
	}

	return shareClient.NewDirectoryClient(parent).NewFileClient(name), nil
}

func normalizeAzureFilePath(value string) string {
	normalized := path.Clean("/" + strings.TrimSpace(value))
	if normalized == "/" || normalized == "." {
		return ""
	}
	return strings.TrimPrefix(normalized, "/")
}

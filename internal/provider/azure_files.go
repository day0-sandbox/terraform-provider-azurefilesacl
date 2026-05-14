package provider

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/directory"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/file"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/share"
)

type fileACLClient interface {
	ReadSDDL(ctx context.Context, target fileACLTarget) (string, string, error)
	SetSDDL(ctx context.Context, target fileACLTarget, sddl string) (string, string, error)
}

type fileACLTarget struct {
	StorageAccountName string
	ShareName          string
	Path               string
	ResourceType       string
}

type azureFilesClient struct {
	config *ProviderConfig
}

func newAzureFilesClient(config *ProviderConfig) fileACLClient {
	return &azureFilesClient{config: config}
}

func (c *azureFilesClient) ReadSDDL(ctx context.Context, target fileACLTarget) (string, string, error) {
	shareClient, err := c.newShareClient(target.StorageAccountName, target.ShareName)
	if err != nil {
		return "", "", err
	}

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
}

func (c *azureFilesClient) SetSDDL(ctx context.Context, target fileACLTarget, sddl string) (string, string, error) {
	shareClient, err := c.newShareClient(target.StorageAccountName, target.ShareName)
	if err != nil {
		return "", "", err
	}

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

	return c.ReadSDDL(ctx, target)
}

func (c *azureFilesClient) newShareClient(storageAccountName, shareName string) (*share.Client, error) {
	accountURL := fmt.Sprintf("https://%s.file.%s", storageAccountName, c.config.StorageEndpointSuffix)
	shareURL := fmt.Sprintf("%s/%s", strings.TrimRight(accountURL, "/"), url.PathEscape(shareName))

	switch c.config.AuthMethod {
	case "oauth":
		options := &azidentity.DefaultAzureCredentialOptions{}
		if c.config.TenantID != "" {
			options.TenantID = c.config.TenantID
		}
		credential, err := azidentity.NewDefaultAzureCredential(options)
		if err != nil {
			return nil, fmt.Errorf("create Azure default credential: %w", err)
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

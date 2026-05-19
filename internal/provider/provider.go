package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = (*Provider)(nil)
var _ provider.ProviderWithActions = (*Provider)(nil)

type Provider struct {
	version string
}

type ProviderModel struct {
	TenantID              types.String `tfsdk:"tenant_id"`
	AuthMethod            types.String `tfsdk:"auth_method"`
	StorageEndpointSuffix types.String `tfsdk:"storage_endpoint_suffix"`
	GraphEndpoint         types.String `tfsdk:"graph_endpoint"`
	GraphAPIVersion       types.String `tfsdk:"graph_api_version"`
	ARMEndpoint           types.String `tfsdk:"arm_endpoint"`
	AccountKey            types.String `tfsdk:"account_key"`
	SASToken              types.String `tfsdk:"sas_token"`
}

type ProviderConfig struct {
	TenantID              string
	AuthMethod            string
	StorageEndpointSuffix string
	GraphEndpoint         string
	GraphAPIVersion       string
	ARMEndpoint           string
	AccountKey            string
	SASToken              string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &Provider{version: version}
	}
}

func (p *Provider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "azurefilesacl"
	resp.Version = p.version
}

func (p *Provider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Provider for managing Windows ACLs on Azure Files objects and Azure Virtual Desktop session-host cleanup operations.",
		Attributes: map[string]schema.Attribute{
			"tenant_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Tenant ID used by Azure identity authentication. Optional when the ambient Azure credential can infer it.",
			},
			"auth_method": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Authentication method for Azure Files data-plane calls. Supported values: `oauth`, `sas`, `account_key`. Defaults to `oauth`. For `azurefilesacl_file_acl`, `oauth` can fall back to ARM `listKeys` plus shared-key Azure Files calls if direct bearer-token ACL access is unauthorized.",
			},
			"storage_endpoint_suffix": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Storage endpoint suffix. Defaults to `core.windows.net`.",
			},
			"graph_endpoint": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Microsoft Graph endpoint. Defaults to `https://graph.microsoft.com`.",
			},
			"graph_api_version": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Microsoft Graph API version. Defaults to `beta`.",
			},
			"arm_endpoint": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Azure Resource Manager endpoint. Defaults to `https://management.azure.com`.",
			},
			"account_key": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "Storage account key for `account_key` authentication. Intended for prototype, testing, or break-glass use.",
			},
			"sas_token": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "SAS token for `sas` authentication.",
			},
		},
	}
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config ProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	authMethod := stringDefault(config.AuthMethod, "oauth")
	switch authMethod {
	case "oauth", "sas", "account_key":
	default:
		resp.Diagnostics.AddAttributeError(
			path.Root("auth_method"),
			"Unsupported authentication method",
			"Supported values are oauth, sas, and account_key.",
		)
	}

	if authMethod == "account_key" && stringDefault(config.AccountKey, "") == "" {
		resp.Diagnostics.AddAttributeError(path.Root("account_key"), "Missing account key", "account_key is required when auth_method is account_key.")
	}
	if authMethod == "sas" && stringDefault(config.SASToken, "") == "" {
		resp.Diagnostics.AddAttributeError(path.Root("sas_token"), "Missing SAS token", "sas_token is required when auth_method is sas.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	providerConfig := &ProviderConfig{
		TenantID:              stringDefault(config.TenantID, ""),
		AuthMethod:            authMethod,
		StorageEndpointSuffix: strings.TrimPrefix(stringDefault(config.StorageEndpointSuffix, "core.windows.net"), "."),
		GraphEndpoint:         strings.TrimRight(stringDefault(config.GraphEndpoint, "https://graph.microsoft.com"), "/"),
		GraphAPIVersion:       stringDefault(config.GraphAPIVersion, "beta"),
		ARMEndpoint:           strings.TrimRight(stringDefault(config.ARMEndpoint, "https://management.azure.com"), "/"),
		AccountKey:            stringDefault(config.AccountKey, ""),
		SASToken:              stringDefault(config.SASToken, ""),
	}

	resp.ResourceData = providerConfig
	resp.DataSourceData = providerConfig
	resp.ActionData = providerConfig
}

func (p *Provider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return nil
}

func (p *Provider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewFileACLResource,
		NewAVDSessionHostCleanupMarkerResource,
	}
}

func (p *Provider) Actions(ctx context.Context) []func() action.Action {
	return []func() action.Action{
		NewAVDSessionHostCleanupAction,
	}
}

func stringDefault(value types.String, fallback string) string {
	if value.IsNull() || value.IsUnknown() {
		return fallback
	}
	return value.ValueString()
}

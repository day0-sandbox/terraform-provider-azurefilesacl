package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = (*FileACLResource)(nil)
	_ resource.ResourceWithConfigure   = (*FileACLResource)(nil)
	_ resource.ResourceWithImportState = (*FileACLResource)(nil)
)

type FileACLResource struct {
	client   fileACLClient
	resolver principalResolver
}

type FileACLResourceModel struct {
	ID                          types.String              `tfsdk:"id"`
	StorageAccountResourceID    types.String              `tfsdk:"storage_account_resource_id"`
	ShareName                   types.String              `tfsdk:"share_name"`
	Path                        types.String              `tfsdk:"path"`
	ResourceType                types.String              `tfsdk:"resource_type"`
	Mode                        types.String              `tfsdk:"mode"`
	PreserveExistingUnknownACEs types.Bool                `tfsdk:"preserve_existing_unknown_aces"`
	OwnerSID                    types.String              `tfsdk:"owner_sid"`
	GroupSID                    types.String              `tfsdk:"group_sid"`
	DACLProtected               types.Bool                `tfsdk:"dacl_protected"`
	IdentityMode                types.String              `tfsdk:"identity_mode"`
	AccessControlEntries        []AccessControlEntryModel `tfsdk:"access_control_entry"`
	GeneratedSDDL               types.String              `tfsdk:"generated_sddl"`
	CurrentSDDLHash             types.String              `tfsdk:"current_sddl_hash"`
	CurrentPermissionKey        types.String              `tfsdk:"current_permission_key"`
	MissingManagedACEs          types.List                `tfsdk:"missing_managed_aces"`
}

type AccessControlEntryModel struct {
	PrincipalID    types.String `tfsdk:"principal_id"`
	PrincipalType  types.String `tfsdk:"principal_type"`
	Type           types.String `tfsdk:"type"`
	Rights         types.String `tfsdk:"rights"`
	AdvancedRights types.List   `tfsdk:"advanced_rights"`
	AppliesTo      types.String `tfsdk:"applies_to"`
	Flags          types.String `tfsdk:"flags"`
}

type effectiveFileACLConfig struct {
	Target                      fileACLTarget
	Mode                        string
	PreserveExistingUnknownACEs bool
	OwnerSID                    string
	GroupSID                    string
	DACLProtected               bool
	IdentityMode                string
	Entries                     []aceInput
}

func NewFileACLResource() resource.Resource {
	return &FileACLResource{}
}

func (r *FileACLResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file_acl"
}

func (r *FileACLResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages Windows ACLs on an Azure Files directory or file.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"storage_account_resource_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "ARM resource ID for the storage account. The provider derives the storage account name from this ID and, when `auth_method = \"oauth\"`, can fall back to ARM `listKeys` plus shared-key Azure Files calls if direct bearer-token ACL reads or writes are unauthorized.",
			},
			"share_name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Azure Files share name.",
			},
			"path": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Directory or file path inside the share. Defaults to `/`.",
			},
			"resource_type": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Target type. Supported values: `directory` and `file`. Defaults to `directory`.",
			},
			"mode": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "ACL management mode. Supported values: `validate`, `additive`, and `authoritative`. Defaults to `additive`.",
			},
			"preserve_existing_unknown_aces": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Whether unknown existing ACEs must be preserved. Defaults to true. Authoritative mode requires this to be explicitly false.",
			},
			"owner_sid": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Owner SID or supported SDDL alias. Omit or set to `preserve` to preserve the existing owner.",
			},
			"group_sid": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Group SID or supported SDDL alias. Omit or set to `preserve` to preserve the existing group.",
			},
			"dacl_protected": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Whether generated authoritative DACLs should be protected. Defaults to true.",
			},
			"identity_mode": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Identity mode used only when a principal must be resolved through Microsoft Graph. SID-only ACLs do not require it.",
			},
			"generated_sddl": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Generated target SDDL after applying this resource's configured ACEs.",
			},
			"current_sddl_hash": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "SHA-256 hash of the current live Azure Files SDDL.",
			},
			"current_permission_key": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Current Azure Files permission key for the target object.",
			},
			"missing_managed_aces": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Configured ACEs that are missing from the live DACL.",
			},
		},
		Blocks: map[string]schema.Block{
			"access_control_entry": schema.ListNestedBlock{
				MarkdownDescription: "Managed access control entry.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"principal_id": schema.StringAttribute{
							Required: true,
						},
						"principal_type": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Principal input type. Supported values: `sid`, `user`, and `group`.",
						},
						"type": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "ACE type. Supported values: `allow` and `deny`. Defaults to `allow`.",
						},
						"rights": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "Named rights or raw SDDL rights. Mutually exclusive with `advanced_rights`.",
						},
						"advanced_rights": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
						},
						"applies_to": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "Portal-style inheritance scope. Ignored when `flags` is set.",
						},
						"flags": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "Raw SDDL ACE flags. Overrides `applies_to` when set.",
						},
					},
				},
			},
		},
	}
}

func (r *FileACLResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(*ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider configuration", fmt.Sprintf("Expected *ProviderConfig, got %T.", req.ProviderData))
		return
	}

	r.client = newAzureFilesClient(config)
	resolver, err := newGraphPrincipalResolver(config)
	if err != nil {
		resp.Diagnostics.AddError("Unable to configure Microsoft Graph resolver", err.Error())
		return
	}
	r.resolver = resolver
}

func (r *FileACLResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan FileACLResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, diags := r.apply(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, result)...)
}

func (r *FileACLResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state FileACLResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, diags := r.read(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, result)...)
}

func (r *FileACLResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan FileACLResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, diags := r.apply(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, result)...)
}

func (r *FileACLResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state FileACLResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	config, moreDiags := expandFileACLConfig(ctx, state)
	resp.Diagnostics.Append(moreDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	managedACEs, err := buildManagedACEs(ctx, config.Entries, config.IdentityMode, r.resolver)
	if err != nil {
		resp.Diagnostics.AddError("Unable to build managed ACEs", err.Error())
		return
	}

	currentSDDL, _, err := r.client.ReadSDDL(ctx, config.Target)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Azure Files ACL", err.Error())
		return
	}

	nextSDDL, removed, err := removeManagedACEsFromSDDL(currentSDDL, managedACEs)
	if err != nil {
		resp.Diagnostics.AddError("Unable to compute destroy SDDL", err.Error())
		return
	}

	if len(removed) > 0 {
		_, _, err = r.client.SetSDDL(ctx, config.Target, nextSDDL)
		if err != nil {
			resp.Diagnostics.AddError("Unable to remove managed Azure Files ACEs", err.Error())
			return
		}
	}

	resp.State.RemoveResource(ctx)
}

func (r *FileACLResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "|", 4)
	if len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Expected import ID format: {storage_account_resource_id}|{share_name}|{resource_type}|{path}.")
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("storage_account_resource_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("share_name"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("resource_type"), parts[2])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("path"), parts[3])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("mode"), "validate")...)
}

func (r *FileACLResource) apply(ctx context.Context, plan FileACLResourceModel) (FileACLResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	config, moreDiags := expandFileACLConfig(ctx, plan)
	diags.Append(moreDiags...)
	if diags.HasError() {
		return plan, diags
	}

	currentSDDL, currentPermissionKey, err := r.client.ReadSDDL(ctx, config.Target)
	if err != nil {
		diags.AddError("Unable to read Azure Files ACL", err.Error())
		return plan, diags
	}

	managedACEs, err := buildManagedACEs(ctx, config.Entries, config.IdentityMode, r.resolver)
	if err != nil {
		diags.AddError("Unable to build managed ACEs", err.Error())
		return plan, diags
	}

	nextSDDL, missing, err := computeTargetSDDL(currentSDDL, managedACEs, config)
	if err != nil {
		diags.AddError("Unable to compute target SDDL", err.Error())
		return plan, diags
	}

	if config.Mode == "validate" && len(missing) > 0 {
		diags.AddError("Azure Files ACL validation failed", fmt.Sprintf("The live ACL is missing managed ACEs: %s", strings.Join(missing, ", ")))
		plan = populateComputed(plan, config.Target, nextSDDL, currentSDDL, currentPermissionKey, missing)
		return plan, diags
	}

	finalSDDL := currentSDDL
	finalPermissionKey := currentPermissionKey
	if config.Mode != "validate" && nextSDDL != currentSDDL {
		finalSDDL, finalPermissionKey, err = r.client.SetSDDL(ctx, config.Target, nextSDDL)
		if err != nil {
			diags.AddError("Unable to set Azure Files ACL", err.Error())
			return plan, diags
		}
	}

	readMissing := missingACEs(finalSDDL, managedACEs)
	plan = populateComputed(plan, config.Target, nextSDDL, finalSDDL, finalPermissionKey, readMissing)
	return plan, diags
}

func (r *FileACLResource) read(ctx context.Context, state FileACLResourceModel) (FileACLResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	config, moreDiags := expandFileACLConfig(ctx, state)
	diags.Append(moreDiags...)
	if diags.HasError() {
		return state, diags
	}

	currentSDDL, currentPermissionKey, err := r.client.ReadSDDL(ctx, config.Target)
	if err != nil {
		diags.AddError("Unable to read Azure Files ACL", err.Error())
		return state, diags
	}

	managedACEs, err := buildManagedACEs(ctx, config.Entries, config.IdentityMode, r.resolver)
	if err != nil {
		diags.AddError("Unable to build managed ACEs", err.Error())
		return state, diags
	}

	nextSDDL, missing, err := computeTargetSDDL(currentSDDL, managedACEs, config)
	if err != nil {
		diags.AddError("Unable to compute target SDDL", err.Error())
		return state, diags
	}

	state = populateComputed(state, config.Target, nextSDDL, currentSDDL, currentPermissionKey, missing)
	return state, diags
}

func expandFileACLConfig(ctx context.Context, model FileACLResourceModel) (effectiveFileACLConfig, diag.Diagnostics) {
	var diags diag.Diagnostics
	storageAccountResourceID := model.StorageAccountResourceID.ValueString()
	storageAccountName, err := storageAccountNameFromResourceID(storageAccountResourceID)
	if err != nil {
		diags.AddAttributeError(path.Root("storage_account_resource_id"), "Invalid storage account resource ID", err.Error())
	}

	config := effectiveFileACLConfig{
		Target: fileACLTarget{
			StorageAccountName:       storageAccountName,
			StorageAccountResourceID: storageAccountResourceID,
			ShareName:                model.ShareName.ValueString(),
			Path:                     stringDefault(model.Path, "/"),
			ResourceType:             stringDefault(model.ResourceType, "directory"),
		},
		Mode:                        stringDefault(model.Mode, "additive"),
		PreserveExistingUnknownACEs: boolDefault(model.PreserveExistingUnknownACEs, true),
		OwnerSID:                    stringDefault(model.OwnerSID, "preserve"),
		GroupSID:                    stringDefault(model.GroupSID, "preserve"),
		DACLProtected:               boolDefault(model.DACLProtected, true),
		IdentityMode:                stringDefault(model.IdentityMode, ""),
		Entries:                     make([]aceInput, 0, len(model.AccessControlEntries)),
	}

	switch config.Target.ResourceType {
	case "directory", "file":
	default:
		diags.AddAttributeError(path.Root("resource_type"), "Unsupported resource type", "Supported values are directory and file.")
	}
	if config.Target.ResourceType == "file" && normalizeAzureFilePath(config.Target.Path) == "" {
		diags.AddAttributeError(path.Root("path"), "Invalid file path", "file resource_type requires a non-root path.")
	}

	switch config.Mode {
	case "validate", "additive":
		if !config.PreserveExistingUnknownACEs {
			diags.AddAttributeError(path.Root("preserve_existing_unknown_aces"), "Unsafe preservation setting", "validate and additive modes require preserve_existing_unknown_aces to be true.")
		}
	case "authoritative":
		if model.PreserveExistingUnknownACEs.IsNull() || model.PreserveExistingUnknownACEs.IsUnknown() || config.PreserveExistingUnknownACEs {
			diags.AddAttributeError(path.Root("preserve_existing_unknown_aces"), "Explicit authoritative opt-in required", "authoritative mode requires preserve_existing_unknown_aces = false explicitly.")
		}
		diags.AddWarning("Authoritative ACL mode", "This mode replaces the target DACL with only the configured managed ACEs while preserving owner, group, and SACL according to configuration.")
	default:
		diags.AddAttributeError(path.Root("mode"), "Unsupported mode", "Supported values are validate, additive, and authoritative.")
	}

	switch config.IdentityMode {
	case "", "entra_kerberos_cloud_only", "entra_kerberos_cloud_only_preview", "entra_kerberos_hybrid", "ad_ds", "entra_domain_services":
	default:
		diags.AddAttributeError(path.Root("identity_mode"), "Unsupported identity mode", "Supported values are entra_kerberos_cloud_only, entra_kerberos_cloud_only_preview, entra_kerberos_hybrid, ad_ds, and entra_domain_services.")
	}

	for _, entry := range model.AccessControlEntries {
		advancedRights := make([]string, 0)
		if !entry.AdvancedRights.IsNull() && !entry.AdvancedRights.IsUnknown() {
			diags.Append(entry.AdvancedRights.ElementsAs(ctx, &advancedRights, false)...)
		}

		config.Entries = append(config.Entries, aceInput{
			PrincipalID:    entry.PrincipalID.ValueString(),
			PrincipalType:  entry.PrincipalType.ValueString(),
			Type:           stringDefault(entry.Type, "allow"),
			Rights:         stringDefault(entry.Rights, ""),
			AdvancedRights: advancedRights,
			AppliesTo:      stringDefault(entry.AppliesTo, "this_folder_subfolders_files"),
			Flags:          stringDefault(entry.Flags, ""),
		})
	}

	return config, diags
}

func computeTargetSDDL(currentSDDL string, managedACEs []string, config effectiveFileACLConfig) (string, []string, error) {
	switch config.Mode {
	case "validate", "additive":
		return mergeAdditiveSDDL(currentSDDL, managedACEs)
	case "authoritative":
		nextSDDL, err := buildAuthoritativeSDDL(currentSDDL, managedACEs, config.OwnerSID, config.GroupSID, config.DACLProtected)
		return nextSDDL, missingACEs(currentSDDL, managedACEs), err
	default:
		return "", nil, fmt.Errorf("unsupported mode %q", config.Mode)
	}
}

func missingACEs(currentSDDL string, managedACEs []string) []string {
	currentSet := make(map[string]struct{})
	for _, ace := range sddlACEPattern.FindAllString(currentSDDL, -1) {
		currentSet[ace] = struct{}{}
	}

	missing := make([]string, 0)
	for _, ace := range managedACEs {
		if _, ok := currentSet[ace]; !ok {
			missing = append(missing, ace)
		}
	}
	return missing
}

func populateComputed(model FileACLResourceModel, target fileACLTarget, generatedSDDL, currentSDDL, permissionKey string, missing []string) FileACLResourceModel {
	model.ID = types.StringValue(fileACLID(target))
	model.GeneratedSDDL = types.StringValue(generatedSDDL)
	model.CurrentSDDLHash = types.StringValue(sddlHash(currentSDDL))
	model.CurrentPermissionKey = types.StringValue(permissionKey)
	elements := make([]types.String, 0, len(missing))
	for _, ace := range missing {
		elements = append(elements, types.StringValue(ace))
	}
	model.MissingManagedACEs, _ = types.ListValueFrom(context.Background(), types.StringType, elements)
	return model
}

func fileACLID(target fileACLTarget) string {
	targetPath := target.Path
	if strings.TrimSpace(targetPath) == "" {
		targetPath = "/"
	}
	return fmt.Sprintf("%s/%s/%s/%s", target.StorageAccountName, target.ShareName, target.ResourceType, targetPath)
}

func boolDefault(value types.Bool, fallback bool) bool {
	if value.IsNull() || value.IsUnknown() {
		return fallback
	}
	return value.ValueBool()
}

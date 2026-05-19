package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/action"
	actionschema "github.com/hashicorp/terraform-plugin-framework/action/schema"
)

var _ action.Action = (*AVDSessionHostCleanupAction)(nil)
var _ action.ActionWithConfigure = (*AVDSessionHostCleanupAction)(nil)

type AVDSessionHostCleanupAction struct {
	client avdCleanupClient
}

func NewAVDSessionHostCleanupAction() action.Action {
	return &AVDSessionHostCleanupAction{}
}

func (a *AVDSessionHostCleanupAction) Metadata(ctx context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_avd_session_host_cleanup"
}

func (a *AVDSessionHostCleanupAction) Schema(ctx context.Context, req action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = actionschema.Schema{
		MarkdownDescription: "Deletes stale Azure Virtual Desktop session-host artifacts before a replacement session-host VM is created.",
		Attributes: map[string]actionschema.Attribute{
			"host_pool_id": actionschema.StringAttribute{
				Required:            true,
				MarkdownDescription: "ARM resource ID of the Azure Virtual Desktop host pool.",
			},
			"resource_group_name": actionschema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Resource group name that contains the session-host VM.",
			},
			"session_host_name": actionschema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Session-host VM name and AVD sessionHost child-resource name.",
			},
			"current_vm_id": actionschema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Azure Compute VM instance GUID for the newly-created VM. When require_vm_absent is true, cleanup is allowed if the same-name Azure VM exists only with this VM ID.",
			},
			"allow_current_vm_present": actionschema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Allow cleanup to run when a same-name Azure VM exists. Use only when the action is triggered after the replacement VM is created and before it registers with AVD. Defaults to false.",
			},
			"cleanup_avd_session_host": actionschema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Delete the AVD broker sessionHost record and associated userSessions. Defaults to false.",
			},
			"cleanup_entra_device": actionschema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Delete matching Microsoft Entra device objects. Defaults to false.",
			},
			"cleanup_intune_managed_device": actionschema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Delete matching Microsoft Intune managedDevice objects. Defaults to false.",
			},
			"require_vm_absent": actionschema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Fail without deleting artifacts when the Azure VM still exists. Defaults to true.",
			},
			"force_user_sessions": actionschema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Delete active AVD userSessions before deleting the sessionHost record. Defaults to false.",
			},
		},
	}
}

func (a *AVDSessionHostCleanupAction) Configure(ctx context.Context, req action.ConfigureRequest, resp *action.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(*ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError("Unexpected action configuration", fmt.Sprintf("Expected *ProviderConfig, got %T.", req.ProviderData))
		return
	}

	client, err := newAVDCleanupClient(config)
	if err != nil {
		resp.Diagnostics.AddError("Unable to configure AVD cleanup client", err.Error())
		return
	}
	a.client = client
}

func (a *AVDSessionHostCleanupAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var model avdSessionHostCleanupActionModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	config, diags := expandAVDSessionHostCleanupActionConfig(model)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if a.client == nil {
		resp.Diagnostics.AddError("AVD cleanup client is not configured", "The provider must be configured before invoking azurefilesacl_avd_session_host_cleanup.")
		return
	}

	err := a.client.CleanupSessionHostArtifacts(ctx, config, func(message string) {
		if resp.SendProgress != nil {
			resp.SendProgress(action.InvokeProgressEvent{Message: message})
		}
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to clean AVD session-host artifacts", err.Error())
	}
}

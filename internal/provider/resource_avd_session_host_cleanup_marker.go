package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
)

var _ resource.Resource = (*AVDSessionHostCleanupMarkerResource)(nil)
var _ resource.ResourceWithConfigure = (*AVDSessionHostCleanupMarkerResource)(nil)

type AVDSessionHostCleanupMarkerResource struct {
	client avdCleanupClient
}

func NewAVDSessionHostCleanupMarkerResource() resource.Resource {
	return &AVDSessionHostCleanupMarkerResource{}
}

func (r *AVDSessionHostCleanupMarkerResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_avd_session_host_cleanup_marker"
}

func (r *AVDSessionHostCleanupMarkerResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Marker resource that deletes stale Azure Virtual Desktop session-host artifacts when Terraform destroys the marker.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"host_pool_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "ARM resource ID of the Azure Virtual Desktop host pool.",
			},
			"resource_group_name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Resource group name that contains the session-host VM.",
			},
			"session_host_name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Session-host VM name and AVD sessionHost child-resource name.",
			},
			"current_vm_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Azure Compute VM instance GUID that is allowed to exist during cleanup. Usually omitted for destroy markers.",
			},
			"allow_current_vm_present": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Allow cleanup to run when a same-name Azure VM exists. Usually false for destroy markers. Defaults to false.",
			},
			"cleanup_avd_session_host": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Delete the AVD broker sessionHost record and associated userSessions during marker destroy. Defaults to false.",
			},
			"cleanup_entra_device": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Delete matching Microsoft Entra device objects during marker destroy. Defaults to false.",
			},
			"cleanup_intune_managed_device": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Delete matching Microsoft Intune managedDevice objects during marker destroy. Defaults to false.",
			},
			"require_vm_absent": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Fail without deleting artifacts when the Azure VM still exists. Defaults to true.",
			},
			"force_user_sessions": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Delete active AVD userSessions before deleting the sessionHost record. Defaults to false.",
			},
		},
	}
}

func (r *AVDSessionHostCleanupMarkerResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(*ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError("Unexpected resource configuration", fmt.Sprintf("Expected *ProviderConfig, got %T.", req.ProviderData))
		return
	}

	client, err := newAVDCleanupClient(config)
	if err != nil {
		resp.Diagnostics.AddError("Unable to configure AVD cleanup client", err.Error())
		return
	}
	r.client = client
}

func (r *AVDSessionHostCleanupMarkerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan avdSessionHostCleanupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	config, diags := expandAVDSessionHostCleanupConfig(plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, setAVDSessionHostCleanupID(ctx, plan, config))...)
}

func (r *AVDSessionHostCleanupMarkerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state avdSessionHostCleanupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	config, diags := expandAVDSessionHostCleanupConfig(state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, setAVDSessionHostCleanupID(ctx, state, config))...)
}

func (r *AVDSessionHostCleanupMarkerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan avdSessionHostCleanupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	config, diags := expandAVDSessionHostCleanupConfig(plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, setAVDSessionHostCleanupID(ctx, plan, config))...)
}

func (r *AVDSessionHostCleanupMarkerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state avdSessionHostCleanupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	config, diags := expandAVDSessionHostCleanupConfig(state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if r.client == nil {
		resp.Diagnostics.AddError("AVD cleanup client is not configured", "The provider must be configured before deleting azurefilesacl_avd_session_host_cleanup_marker.")
		return
	}

	if err := r.client.CleanupSessionHostArtifacts(ctx, config, nil); err != nil {
		resp.Diagnostics.AddError("Unable to clean AVD session-host artifacts", err.Error())
		return
	}

	resp.State.RemoveResource(ctx)
}

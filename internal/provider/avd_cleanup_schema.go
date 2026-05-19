package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type avdSessionHostCleanupModel struct {
	ID                         types.String `tfsdk:"id"`
	HostPoolID                 types.String `tfsdk:"host_pool_id"`
	ResourceGroupName          types.String `tfsdk:"resource_group_name"`
	SessionHostName            types.String `tfsdk:"session_host_name"`
	CurrentVMID                types.String `tfsdk:"current_vm_id"`
	AllowCurrentVMPresent      types.Bool   `tfsdk:"allow_current_vm_present"`
	CleanupAVDSessionHost      types.Bool   `tfsdk:"cleanup_avd_session_host"`
	CleanupEntraDevice         types.Bool   `tfsdk:"cleanup_entra_device"`
	CleanupIntuneManagedDevice types.Bool   `tfsdk:"cleanup_intune_managed_device"`
	RequireVMAbsent            types.Bool   `tfsdk:"require_vm_absent"`
	ForceUserSessions          types.Bool   `tfsdk:"force_user_sessions"`
}

type avdSessionHostCleanupActionModel struct {
	HostPoolID                 types.String `tfsdk:"host_pool_id"`
	ResourceGroupName          types.String `tfsdk:"resource_group_name"`
	SessionHostName            types.String `tfsdk:"session_host_name"`
	CurrentVMID                types.String `tfsdk:"current_vm_id"`
	AllowCurrentVMPresent      types.Bool   `tfsdk:"allow_current_vm_present"`
	CleanupAVDSessionHost      types.Bool   `tfsdk:"cleanup_avd_session_host"`
	CleanupEntraDevice         types.Bool   `tfsdk:"cleanup_entra_device"`
	CleanupIntuneManagedDevice types.Bool   `tfsdk:"cleanup_intune_managed_device"`
	RequireVMAbsent            types.Bool   `tfsdk:"require_vm_absent"`
	ForceUserSessions          types.Bool   `tfsdk:"force_user_sessions"`
}

func expandAVDSessionHostCleanupConfig(model avdSessionHostCleanupModel) (avdCleanupConfig, diag.Diagnostics) {
	return expandAVDSessionHostCleanupFields(avdSessionHostCleanupActionModel{
		HostPoolID:                 model.HostPoolID,
		ResourceGroupName:          model.ResourceGroupName,
		SessionHostName:            model.SessionHostName,
		CurrentVMID:                model.CurrentVMID,
		AllowCurrentVMPresent:      model.AllowCurrentVMPresent,
		CleanupAVDSessionHost:      model.CleanupAVDSessionHost,
		CleanupEntraDevice:         model.CleanupEntraDevice,
		CleanupIntuneManagedDevice: model.CleanupIntuneManagedDevice,
		RequireVMAbsent:            model.RequireVMAbsent,
		ForceUserSessions:          model.ForceUserSessions,
	})
}

func expandAVDSessionHostCleanupActionConfig(model avdSessionHostCleanupActionModel) (avdCleanupConfig, diag.Diagnostics) {
	return expandAVDSessionHostCleanupFields(model)
}

func expandAVDSessionHostCleanupFields(model avdSessionHostCleanupActionModel) (avdCleanupConfig, diag.Diagnostics) {
	var diags diag.Diagnostics

	config := avdCleanupConfig{
		HostPoolID:                 model.HostPoolID.ValueString(),
		ResourceGroupName:          model.ResourceGroupName.ValueString(),
		SessionHostName:            model.SessionHostName.ValueString(),
		CurrentVMID:                model.CurrentVMID.ValueString(),
		AllowCurrentVMPresent:      boolDefault(model.AllowCurrentVMPresent, false),
		CleanupAVDSessionHost:      boolDefault(model.CleanupAVDSessionHost, false),
		CleanupEntraDevice:         boolDefault(model.CleanupEntraDevice, false),
		CleanupIntuneManagedDevice: boolDefault(model.CleanupIntuneManagedDevice, false),
		RequireVMAbsent:            boolDefault(model.RequireVMAbsent, true),
		ForceUserSessions:          boolDefault(model.ForceUserSessions, false),
	}

	if config.HostPoolID == "" {
		diags.AddAttributeError(path.Root("host_pool_id"), "Missing host pool ID", "host_pool_id must not be empty.")
	}
	if config.ResourceGroupName == "" {
		diags.AddAttributeError(path.Root("resource_group_name"), "Missing resource group name", "resource_group_name must not be empty.")
	}
	if config.SessionHostName == "" {
		diags.AddAttributeError(path.Root("session_host_name"), "Missing session host name", "session_host_name must not be empty.")
	}

	return config, diags
}

func avdSessionHostCleanupID(config avdCleanupConfig) string {
	return config.HostPoolID + "/sessionHosts/" + config.SessionHostName
}

func setAVDSessionHostCleanupID(ctx context.Context, model avdSessionHostCleanupModel, config avdCleanupConfig) avdSessionHostCleanupModel {
	model.ID = types.StringValue(avdSessionHostCleanupID(config))
	return model
}

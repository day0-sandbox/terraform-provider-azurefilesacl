provider "azurefilesacl" {
  tenant_id   = var.tenant_id
  auth_method = var.auth_method
  account_key = var.account_key
  sas_token   = var.sas_token
}

resource "azurefilesacl_file_acl" "profiles_root" {
  storage_account_resource_id = var.storage_account_resource_id
  share_name                  = var.share_name
  path                        = "/"
  resource_type               = "directory"

  mode                           = var.acl_mode
  preserve_existing_unknown_aces = var.preserve_existing_unknown_aces
  identity_mode                  = var.identity_mode

  access_control_entry {
    principal_id   = "SY"
    principal_type = "sid"
    rights         = "full_control"
    applies_to     = "this_folder_subfolders_files"
  }

  access_control_entry {
    principal_id   = "CO"
    principal_type = "sid"
    rights         = "modify"
    applies_to     = "subfolders_files_only"
  }

  dynamic "access_control_entry" {
    for_each = toset(var.fslogix_user_principal_ids)

    content {
      principal_id   = access_control_entry.value
      principal_type = "user"
      rights         = "modify"
      applies_to     = "this_folder_only"
    }
  }

  access_control_entry {
    principal_id   = var.fslogix_admin_group_principal_id
    principal_type = "group"
    rights         = "full_control"
    applies_to     = "this_folder_subfolders_files"
  }
}

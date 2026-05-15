variable "storage_account_resource_id" {
  description = "ARM resource ID for the storage account that hosts the FSLogix profile share."
  type        = string
}

variable "tenant_id" {
  description = "Azure tenant ID used for OAuth authentication."
  type        = string
  default     = null
}

variable "auth_method" {
  description = "Authentication method for Azure Files data-plane calls. Supported values: oauth, account_key, sas."
  type        = string
  default     = "oauth"
}

variable "account_key" {
  description = "Storage account key used when auth_method is account_key."
  type        = string
  default     = null
  sensitive   = true
}

variable "sas_token" {
  description = "Storage SAS token used when auth_method is sas."
  type        = string
  default     = null
  sensitive   = true
}

variable "share_name" {
  description = "FSLogix profile share name."
  type        = string
}

variable "acl_mode" {
  description = "ACL mode for azurefilesacl_file_acl. Defaults to additive, which adds missing managed ACEs while preserving existing ACL entries."
  type        = string
  default     = "additive"
}

variable "preserve_existing_unknown_aces" {
  description = "Whether unknown existing ACEs are preserved. Must be false explicitly for authoritative mode."
  type        = bool
  default     = true
}

variable "identity_mode" {
  description = "Identity mode used when resolving user and group principals through Microsoft Graph."
  type        = string
  default     = "entra_kerberos_hybrid"
}

variable "fslogix_user_principal_ids" {
  description = "Hybrid user UPNs or object IDs that receive FSLogix modify access on the share root."
  type        = list(string)
}

variable "fslogix_admin_group_principal_id" {
  description = "Hybrid group object ID that receives FSLogix full control on the share root."
  type        = string
}

# Changelog

## v0.2.0

- Remove the redundant `storage_account_name` argument from `azurefilesacl_file_acl`.
- Require `storage_account_resource_id` and derive the storage account name from that ARM ID while preserving OAuth direct access and ARM `listKeys` fallback behavior.
- Update examples and import documentation for the single storage-account identifier.

## v0.1.1

- Fall back from direct Azure Files OAuth ACL calls to ARM `listKeys` plus shared-key file clients when `storage_account_resource_id` is set and the operator lacks privileged Azure Files bearer-token ACL permissions.
- Add the optional `storage_account_resource_id` argument to `azurefilesacl_file_acl` so Terraform configurations can opt into that fallback path.
- Improve the FSLogix root ACL example and docs for the mixed ARM plus Azure Files permission model.

## v0.1.0

- Initial public release of the `azurefilesacl` Terraform provider.
- Adds `azurefilesacl_file_acl` for managing Windows ACLs on Azure Files directories and files.
- Supports validate, additive, and authoritative ACL modes.
- Supports SID and Microsoft Graph principal resolution for supported Azure Files identity modes.

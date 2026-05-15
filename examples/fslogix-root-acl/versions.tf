terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurefilesacl = {
      source  = "day0sh/azurefilesacl"
      version = "0.0.0"
    }
  }
}

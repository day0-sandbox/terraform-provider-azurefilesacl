package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/irisdotsh/terraform-provider-azacl/internal/provider"
)

var version = "dev"

func main() {
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/irisdotsh/azacl",
	})
	if err != nil {
		log.Fatal(err)
	}
}

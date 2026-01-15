package resources

import (
	"context"
	"encoding/base64"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-pkcs8/pkcs8/utils"
)

// ResourceFromPem returns a resource that converts PEM private keys to unencrypted PKCS8 format
func ResourceFromPem() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceFromPemCreate,
		ReadContext:   resourceFromPemRead,
		DeleteContext: resourceFromPemDelete,
		Schema: map[string]*schema.Schema{
			"private_key_pem": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				ForceNew:    true,
				Description: "PEM-encoded private key (RSA or EC)",
			},
			"private_key_pkcs8": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Base64-encoded PKCS8 private key (unencrypted)",
			},
		},
	}
}

func resourceFromPemCreate(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	keyPEM := d.Get("private_key_pem").(string)

	// Convert the private key to PKCS8 format
	keyPKCS8, err := utils.KeyPEMToPKCS8([]byte(keyPEM))
	if err != nil {
		return diag.FromErr(err)
	}

	// Generate ID from the key
	id := utils.GenerateID(keyPEM)
	d.SetId(id)

	// Set the output
	if err := d.Set("private_key_pkcs8", base64.StdEncoding.EncodeToString(keyPKCS8)); err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func resourceFromPemRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// This is a computed-only resource, nothing to read from external systems
	return nil
}

func resourceFromPemDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}

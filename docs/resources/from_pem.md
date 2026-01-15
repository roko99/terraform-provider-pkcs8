---
page_title: "PKCS8 From PEM resource"
description: |-
  Converts PEM-encoded private keys to unencrypted PKCS8 format
---

# pkcs8_from_pem Resource

Converts PEM-encoded private keys to unencrypted PKCS8 format. This is useful when you need to work with PKCS8-formatted private keys for various systems and applications. Supports RSA and EC keys.

## Example Usage

```hcl
resource "tls_private_key" "example" {
  algorithm = "RSA"
}

resource "pkcs8_from_pem" "example" {
  private_key_pem = tls_private_key.example.private_key_pem
}

# Use the converted PKCS8 private key
resource "local_file" "key" {
  filename             = "${path.module}/private_key.pkcs8"
  content_base64       = pkcs8_from_pem.example.private_key_pkcs8
  file_permission      = "0600"
}
```

## Argument Reference

* `private_key_pem` - (Required) The private key in PEM format. Supports RSA and EC key formats.

## Attribute Reference

* `private_key_pkcs8` - The private key in unencrypted PKCS#8 format, base64-encoded

## Notes

- All RSA and EC keys are standardized to PKCS#8 format in the output
- Encrypted private keys are not supported; only unencrypted keys are accepted
- The resource uses SHA256 hash of the input key to generate a unique ID
- All sensitive inputs and outputs are marked as sensitive

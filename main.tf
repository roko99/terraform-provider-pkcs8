terraform {
  required_providers {
    pkcs8 = {
      source  = "local/pkcs8"
      version = "0.1.0"
    }
  }
}

provider "pkcs8" {
  # No configuration needed
}

resource "tls_private_key" "my_private_key" {
  algorithm = "RSA"
}

resource "tls_self_signed_cert" "my_cert" {
  private_key_pem       = tls_private_key.my_private_key.private_key_pem
  validity_period_hours = 58440
  early_renewal_hours   = 5844
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
  dns_names          = ["myserver1.local", "myserver2.local"]
  is_ca_certificate  = true
  set_subject_key_id = true

  subject {
    common_name = "myserver.local"
  }
}

# Convert PEM private key to PKCS8 format
resource "pkcs8_from_pem" "my_key" {
  private_key_pem = tls_private_key.my_private_key.private_key_pem
}

# Save PKCS8 private key to file
resource "local_file" "key_pkcs8" {
  filename        = "${path.module}/private_key.pkcs8"
  content_base64  = pkcs8_from_pem.my_key.private_key_pkcs8
  file_permission = "0600"
}


output "my_key" {
  value     = pkcs8_from_pem.my_key
  sensitive = true
}

# Terraform Provider PKCS8

A Terraform provider for converting PEM-encoded private keys to unencrypted PKCS8 format.

## Features

- Convert PEM private keys (RSA, EC) to unencrypted PKCS8 format
- Standardizes all key formats to PKCS#8
- Base64-encoded output for easy file storage
- Rejects encrypted private keys

## Building the Provider

```shell
go build -o terraform-provider-pkcs8
```

## Installation

To install the provider locally:

```shell
make install
```

## Usage

Create a `.tf` file with the following configuration:

```hcl
resource "pkcs8_from_pem" "example" {
  private_key_pem = file("${path.module}/key.pem")
}

resource "local_file" "key_pkcs8" {
  filename       = "${path.module}/key.pkcs8"
  content_base64 = pkcs8_from_pem.example.private_key_pkcs8
}
```

## Testing

To test with the sample configuration:

```shell
terraform init && terraform apply
```

## Documentation

See [docs/resources/from_pem.md](docs/resources/from_pem.md) for detailed resource documentation.

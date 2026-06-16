# Keys Directory - Code Signing Certificates

This directory is reserved for code signing certificates and related files.

## Required Files

### For Production Signing

1. **code_signing.pfx** (Production)
   - EV Code Signing Certificate
   - Password protected
   - Issued by trusted CA (DigiCert, Sectigo, etc.)

### For Development Signing

2. **dev_certificate.pfx** (Development)
   - Self-signed certificate
   - For testing only
   - Not trusted by SmartScreen

## Creating a Self-Signed Certificate (Development)

```powershell
# Create self-signed certificate
$cert = New-SelfSignedCertificate `
    -DnsName "Lemonade Nexus" `
    -Type CodeSigning `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256

# Export to PFX
$password = ConvertTo-SecureString -String "YourPassword" -Force -AsPlainText
Export-PfxCertificate `
    -Cert $cert `
    -FilePath "code_signing.pfx" `
    -Password $password
```

## Using Azure Key Vault (Recommended for CI/CD)

```yaml
# GitHub Actions example
- name: Sign with Azure Key Vault
  uses: azure/azure-keyvault-sign@v1
  with:
    key-vault-name: ${{ secrets.AZURE_KEY_VAULT_NAME }}
    certificate-name: ${{ secrets.AZURE_CERT_NAME }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    client-secret: ${{ secrets.AZURE_CLIENT_SECRET }}
    files: |
      lemonade_nexus.msix
      lemonade_nexus_setup.msi
```

## Using SignPath.io

```yaml
# GitHub Actions example
- name: Sign with SignPath
  uses: signpath/github-action-sign-app@v1
  with:
    signpath-organization-id: ${{ secrets.SIGNPATH_ORG_ID }}
    signpath-project-slug: lemonade-nexus
    signpath-api-token: ${{ secrets.SIGNPATH_API_TOKEN }}
    files: |
      lemonade_nexus.msix
      lemonade_nexus_setup.msi
```

## Security Best Practices

1. **Never commit PFX files to Git**
   - Add to .gitignore
   - Store in secure secret manager

2. **Use environment variables for passwords**
   ```powershell
   $env:CERT_PASSWORD = "secure-password"
   ```

3. **Rotate certificates annually**
   - Set calendar reminder
   - Update CI/CD secrets

4. **Use separate certificates for dev and production**
   - Development: Self-signed
   - Production: EV Certificate from trusted CA

## Certificate Requirements for SmartScreen

For SmartScreen reputation:

1. **EV Code Signing Certificate** (recommended)
   - Immediate reputation
   - Hardware token or cloud signing

2. **Standard Code Signing Certificate**
   - Builds reputation over time
   - Requires multiple signed downloads

3. **Timestamp all signatures**
   - Use RFC 3161 timestamp server
   - Ensures signature validity after cert expires

## Trusted Certificate Authorities

- DigiCert
- Sectigo (formerly Comodo)
- GlobalSign
- Entrust
- Certum

## Environment Variables

Set these environment variables before building:

```bash
# Certificate file path
export CERT_FILE_PATH=/path/to/code_signing.pfx

# Certificate password
export CERT_PASSWORD=your-secure-password

# Timestamp server
export TIMESTAMP_URL=http://timestamp.digicert.com
```

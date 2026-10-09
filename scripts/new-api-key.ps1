<#
.SYNOPSIS
    Generates a new AgentShield API key and the SHA-256 hash the API is configured with.

.DESCRIPTION
    The key is 32 random bytes (base64url, 43 characters). Give the KEY to the client once, over a secure channel, and
    configure only the HASH on the server, e.g. as environment variables:

      Authentication__Clients__<client-id>__KeyHashes__0=<hash>
      Authentication__Clients__<client-id>__Permissions__0=firewall:analyze

    Nothing is written to disk. Works in Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/new-api-key.ps1
#>
$ErrorActionPreference = 'Stop'

$bytes = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$key = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')

$sha = [Security.Cryptography.SHA256]::Create()
try { $hash = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($key)) | ForEach-Object { $_.ToString('x2') }) }
finally { $sha.Dispose() }

Write-Host "API key (give to the client once; not stored anywhere): $key"
Write-Host "Key hash (configure on the server):                    $hash"

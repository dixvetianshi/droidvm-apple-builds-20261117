$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath($env:WINDOWS_OWNED_ROOT).TrimEnd('\', '/')
$taskStage = [IO.Path]::GetFullPath($env:WINDOWS_STAGE_DIR).TrimEnd('\', '/')
$taskRelease = [IO.Path]::GetFullPath($env:WINDOWS_RELEASE_DIR).TrimEnd('\', '/')
foreach ($taskChild in @($taskStage, $taskRelease)) {
    if (-not $taskChild.StartsWith("$taskRoot\", [StringComparison]::OrdinalIgnoreCase)) { throw 'Artifact path escaped the owned Windows build root' }
}
foreach ($taskBoundary in @($taskRoot, $taskStage)) {
    if (-not (Test-Path -LiteralPath $taskBoundary -PathType Container)) { throw 'Windows build directory is absent' }
    if ((Get-Item -LiteralPath $taskBoundary -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Windows build boundary is a reparse point' }
}
$taskEncryptionKey = if ($env:ARTIFACT_KEY) { $env:ARTIFACT_KEY.Trim() } else { '' }
if ($taskEncryptionKey.Length -lt 32) { throw 'A sufficiently long artifact encryption key is required' }
if (Test-Path -LiteralPath $taskRelease) { throw 'Preserve any pre-existing release output instead of overwriting it' }
New-Item -ItemType Directory -Path $taskRelease | Out-Null
$taskRecord = Get-Content -LiteralPath (Join-Path $taskStage 'build-record.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($taskRecord.format -ne 'droidvm-windows-build-record-v1' -or $taskRecord.status -ne 'complete' -or $taskRecord.evidence_mode -ne 'actual_windows_build') { throw 'Windows disk build has not completed' }
$taskMembers = @('Windows11.qcow2', 'build-record.json', 'private-credentials.json', 'windows-image-info.json')
if (Test-Path -LiteralPath (Join-Path $taskStage 'installed-drivers.json')) { $taskMembers += 'installed-drivers.json' }
foreach ($taskName in $taskMembers) {
    $taskFile = Get-Item -LiteralPath (Join-Path $taskStage $taskName) -Force
    if ($taskFile.PSIsContainer -or ($taskFile.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Tar member is not a regular owned file' }
    if ($taskName -ne 'build-record.json') {
        $taskExpected = $taskRecord.files.$taskName
        if (-not $taskExpected -or $taskFile.Length -ne $taskExpected.bytes) { throw "Recorded Windows member size differs: $taskName" }
        if ($taskName -ne 'Windows11.qcow2' -and (Get-FileHash -LiteralPath $taskFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $taskExpected.sha256) { throw "Recorded Windows metadata hash differs: $taskName" }
    }
}

$taskPrefix = 'Windows11-26H2-ARM64.source.tar.gz.enc'
$taskArchive = Join-Path $taskRoot 'Windows11-26H2-ARM64.source.tar.gz'
$taskEncrypted = Join-Path $taskRoot $taskPrefix
if ((Test-Path -LiteralPath $taskArchive) -or (Test-Path -LiteralPath $taskEncrypted)) { throw 'Preserve pre-existing intermediate archives' }
& tar.exe --format=gnutar -czf $taskArchive -C $taskStage @taskMembers
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $taskArchive -PathType Leaf)) { throw 'Regular gzip/tar creation failed' }

# OpenSSL-compatible Salted__ format, with explicit parameters for the receiver.
$taskSalt = [byte[]]::new(8)
[Security.Cryptography.RandomNumberGenerator]::Fill($taskSalt)
$taskDerivation = [Security.Cryptography.Rfc2898DeriveBytes]::new($taskEncryptionKey, $taskSalt, 200000, [Security.Cryptography.HashAlgorithmName]::SHA256)
$taskAes = [Security.Cryptography.Aes]::Create()
$taskAes.KeySize = 256
$taskAes.Mode = [Security.Cryptography.CipherMode]::CBC
$taskAes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
$taskAes.Key = $taskDerivation.GetBytes(32)
$taskAes.IV = $taskDerivation.GetBytes(16)
$taskPlain = $taskCipherFile = $taskCipher = $null
try {
    $taskPlain = [IO.File]::OpenRead($taskArchive)
    $taskCipherFile = [IO.File]::Open($taskEncrypted, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $taskHeader = [Text.Encoding]::ASCII.GetBytes('Salted__')
    $taskCipherFile.Write($taskHeader, 0, $taskHeader.Length)
    $taskCipherFile.Write($taskSalt, 0, $taskSalt.Length)
    $taskCipher = [Security.Cryptography.CryptoStream]::new($taskCipherFile, $taskAes.CreateEncryptor(), [Security.Cryptography.CryptoStreamMode]::Write, $true)
    $taskPlain.CopyTo($taskCipher, 8MB)
    $taskCipher.FlushFinalBlock()
} finally {
    if ($taskCipher) { $taskCipher.Dispose() }
    if ($taskCipherFile) { $taskCipherFile.Dispose() }
    if ($taskPlain) { $taskPlain.Dispose() }
    $taskAes.Dispose()
    $taskDerivation.Dispose()
}
$taskEncryptedBytes = (Get-Item -LiteralPath $taskEncrypted).Length
$taskCipherSha = (Get-FileHash -LiteralPath $taskEncrypted -Algorithm SHA256).Hash.ToLowerInvariant()
$taskParts = [Collections.Generic.List[object]]::new()
$taskInput = [IO.File]::OpenRead($taskEncrypted)
$taskBuffer = [byte[]]::new(8MB)
try {
    $taskIndex = 0
    while ($taskInput.Position -lt $taskInput.Length) {
        $taskName = '{0}.{1:D3}' -f $taskPrefix, $taskIndex
        $taskOutputPath = Join-Path $taskRelease $taskName
        $taskPartStream = [IO.File]::Open($taskOutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $taskRemaining = [Int64]1800MB
            while ($taskRemaining -gt 0) {
                $taskRead = $taskInput.Read($taskBuffer, 0, [int][Math]::Min($taskRemaining, $taskBuffer.Length))
                if ($taskRead -eq 0) { break }
                $taskPartStream.Write($taskBuffer, 0, $taskRead)
                $taskRemaining -= $taskRead
            }
        } finally { $taskPartStream.Dispose() }
        $taskParts.Add([pscustomobject]@{ name = $taskName; bytes = (Get-Item -LiteralPath $taskOutputPath).Length; sha256 = (Get-FileHash -LiteralPath $taskOutputPath -Algorithm SHA256).Hash.ToLowerInvariant() })
        $taskIndex++
    }
} finally { $taskInput.Dispose() }
$taskSums = @($taskParts | ForEach-Object { "$($_.sha256)  $($_.name)" }) -join "`n"
[IO.File]::WriteAllText((Join-Path $taskRelease 'SHA256SUMS'), $taskSums + "`n", [Text.UTF8Encoding]::new($false))
$taskTransport = [ordered]@{ format = 'droidvm-windows-encrypted-transport-v1'; cipher = 'aes-256-cbc'; padding = 'PKCS7'; salt_header = 'Salted__'; salt_bytes = 8; kdf = 'PBKDF2-SHA256'; iterations = 200000; compression = 'gzip'; encrypted_bytes = $taskEncryptedBytes; encrypted_sha256 = $taskCipherSha; parts = $taskParts.ToArray(); raw_windows_disk_published = $false; credentials_published = $false }
[IO.File]::WriteAllText((Join-Path $taskRelease 'encryption-record.json'), ($taskTransport | ConvertTo-Json -Depth 8) + "`n", [Text.UTF8Encoding]::new($false))

# Both intermediates are individually removed within the explicit owned root.
foreach ($taskIntermediate in @($taskArchive, $taskEncrypted)) {
    $taskChecked = [IO.Path]::GetFullPath($taskIntermediate)
    if (-not $taskChecked.StartsWith("$taskRoot\", [StringComparison]::OrdinalIgnoreCase)) { throw 'Intermediate cleanup escaped the owned root' }
    Remove-Item -LiteralPath $taskChecked -Force
}
Write-Output (([ordered]@{ operation = 'windows_source_encrypted_and_split'; parts = $taskParts.Count; encrypted_bytes = $taskEncryptedBytes; output = $taskRelease; windows_guest_boot_verified = $false } | ConvertTo-Json -Depth 3))

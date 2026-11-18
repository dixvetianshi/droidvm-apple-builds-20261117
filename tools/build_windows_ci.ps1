<# Offline Windows image construction on the GitHub-hosted Windows-2025 runner.
   Downloads, tool supply, image construction and disk validation are explicit.
   Sealing/upload and local firmware/vars attachment belong to later steps.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"

Write-Host (([ordered]@{
    github_actions=$env:GITHUB_ACTIONS
    runner_environment=$env:RUNNER_ENVIRONMENT
    runner_os=$env:RUNNER_OS
    image_os=$env:ImageOS
}) | ConvertTo-Json -Compress)
if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_OS -ne "Windows" -or
    $env:RUNNER_ENVIRONMENT -ne "github-hosted") {
    throw "This entry is only for GitHub-hosted Windows-2025; do not run it locally"
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "The hosted runner must already be elevated; this entry never opens UAC"
}
if ($PSVersionTable.PSVersion.Major -lt 7) { throw "The hosted PowerShell 7 runtime is required" }
# The fixed windows-2025 workflow can resolve to a VS image variant. ImageOS is
# diagnostic metadata, not proof of the actual operating system.
$operatingSystems = @(Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop)
if ($operatingSystems.Count -ne 1) { throw "The hosted Windows product could not be identified" }
$hostOperatingSystem = $operatingSystems[0]
$hostVersion = [Version]$hostOperatingSystem.Version
if ($hostOperatingSystem.Caption -notmatch '\bWindows Server 2025\b' -or
    $hostVersion.Major -ne 10 -or $hostVersion.Minor -ne 0 -or $hostVersion.Build -ne 26100 -or
    [int]$hostOperatingSystem.ProductType -ne 3) {
    throw "The actual hosted product must be Windows Server 2025 / 10.0.26100"
}

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$LockPath = Join-Path $ProjectRoot "profiles/windows-source-lock.json"
$ProfilePath = Join-Path $ProjectRoot "profiles/windows11-arm64.json"
$PatchPath = Join-Path $ProjectRoot "patches/windows-safe-provisioning.patch"
$Lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
$Profile = Get-Content -LiteralPath $ProfilePath -Raw | ConvertFrom-Json
if ($Lock.format -ne "droidvm-windows-source-lock-v1" -or $Lock.architecture -ne "arm64" -or
    $Lock.builder_commit -ne "cb6469058514401f16dd4b3142fde027f5b3c94a" -or
    $Lock.driver_commit -ne "9922545ee7c65927e720c3c12b39cd8ae144e90b" -or
    $Lock.iso_filename -ne "Windows11_Client_arm64_zh-cn_26300_9457.iso" -or
    [long]$Lock.iso_bytes -ne 8852006912 -or
    $Lock.publisher_sha256 -ne "cd573df724862300895d0f5d0836e663756d22cc4e964c752efdc05b4fc09e8b" -or
    [long]$Lock.driver_bytes -ne 776774 -or
    $Lock.driver_sha256 -ne "207d566ca39894eee7a811a1ff92e6e8826260a810e337c3bb88b1bec908d716" -or
    $Lock.driver_certificate_sha256 -ne "da88f450dbd881c91511c5b801295cd9cc0d3ca84ea9d3dc08eff9481eed64b3") {
    throw "The reviewed source lock differs; preserve it and update the build deliberately"
}
if ($Profile.vm.cpu_count -ne 4 -or $Profile.vm.memory_mb -ne 6144 -or
    $Profile.vm.hypervisor -ne "gunyah" -or
    $Profile.vm.protected_vm -ne "protected_without_firmware" -or $Profile.vm.swiotlb_mb -ne 256 -or
    $Profile.vm.prepare_lend_mthp -ne "chunked" -or $Profile.vm.screens.simplefb.enabled -ne $true -or
    $Profile.vm.screens.simplefb.width -ne 1280 -or $Profile.vm.screens.simplefb.height -ne 720 -or
    $Profile.vm.screens.'gpu-0'.enabled -ne $false) {
    throw "The selected VM profile differs from the reviewed 4 CPU / 6 GiB Gunyah profile"
}

function Get-Field([object]$Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}
function Emit([string]$Phase, [hashtable]$Facts = @{}) {
    $value = [ordered]@{phase=$Phase; at_utc=[DateTime]::UtcNow.ToString("o")}
    foreach ($key in $Facts.Keys) { $value[$key] = $Facts[$key] }
    Write-Host ($value | ConvertTo-Json -Depth 5 -Compress)
}
function Full-LocalPath([string]$Path) {
    if (-not $Path -or $Path -notmatch '^[A-Za-z]:[\\/]') { throw "An absolute local drive path is required" }
    return [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
}
function Assert-Child([string]$Path, [string]$Parent, [switch]$AllowParent) {
    $full = Full-LocalPath $Path
    $base = Full-LocalPath $Parent
    $same = $full.Equals($base, [StringComparison]::OrdinalIgnoreCase)
    if (($same -and -not $AllowParent) -or (-not $same -and
        -not $full.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase))) {
        throw "Path is outside the explicitly owned build parent"
    }
    $probe = $full
    while ($probe) {
        if (Test-Path -LiteralPath $probe) {
            if ((Get-Item -LiteralPath $probe -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "A reparse path cannot own this build"
            }
        }
        if ($probe.Equals($base, [StringComparison]::OrdinalIgnoreCase)) { break }
        $probe = Split-Path $probe -Parent
    }
    return $full
}
function Json-File([string]$Path, [object]$Value) {
    $path = Assert-Child $Path $script:OwnedRoot
    $temporary = $path + ".tmp"
    [IO.File]::WriteAllText($temporary, (($Value | ConvertTo-Json -Depth 20) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $path -Force
}
function Native([string]$File, [object[]]$Arguments, [int[]]$AllowedExit = @(0), [switch]$Capture) {
    $nativePreference = $PSNativeCommandUseErrorActionPreference
    try {
        $PSNativeCommandUseErrorActionPreference = $false
        if ($Capture) { $output = & $File @Arguments }
        else { & $File @Arguments | Out-Host }
        $exitCode = $LASTEXITCODE
    }
    finally { $PSNativeCommandUseErrorActionPreference = $nativePreference }
    if ($AllowedExit -notcontains $exitCode) {
        throw ("Native operation failed: " + [IO.Path]::GetFileName($File) + " (exit " + $exitCode + ")")
    }
    if ($Capture) { return ($output -join [Environment]::NewLine) }
}
function Free-Bytes([string]$Path) {
    return [long]([IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path))).AvailableFreeSpace
}
function Public-DownloadPath([uri]$Uri) {
    $builder = [UriBuilder]::new($Uri)
    $builder.UserName = ""
    $builder.Password = ""
    $builder.Query = ""
    $builder.Fragment = ""
    return $builder.Uri.AbsoluteUri
}
function Download-Verified([string]$Url, [string]$Path, [long]$Bytes, [string]$Sha, [string]$Kind) {
    $path = Assert-Child $Path $script:OwnedRoot
    if (Test-Path -LiteralPath $path) { throw "Preserve an existing download; this owned run must be new" }
    $partial = $path + ".part"
    Emit "download-start" @{kind=$Kind; expected_bytes=$Bytes}
    $oldProgress = $ProgressPreference
    try {
        $ProgressPreference = "SilentlyContinue"
        # Never echo this argument: the ISO URL contains a private ticket query.
        Invoke-WebRequest -Uri $Url -OutFile $partial -TimeoutSec 3600 -ErrorAction Stop
    }
    catch {
        $http = Get-Field (Get-Field $_.Exception "Response") "StatusCode"
        # The web exception can contain the request or redirect query; never print it.
        throw ("Download failed for " + $Kind + "; HTTP status " + [string]$http)
    }
    finally { $ProgressPreference = $oldProgress }
    $file = Get-Item -LiteralPath $partial
    if ($file.Length -ne $Bytes) {
        Emit "download-length-mismatch" @{kind=$Kind; expected_bytes=$Bytes; actual_bytes=$file.Length}
        throw "Downloaded file length differs from the source lock: $Kind"
    }
    Emit "download-hash" @{kind=$Kind; bytes=$file.Length}
    $actual = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Sha.ToLowerInvariant()) { throw "Downloaded file SHA256 differs from the source lock: $Kind" }
    Move-Item -LiteralPath $partial -Destination $path
    Emit "download-verified" @{kind=$Kind; bytes=$Bytes}
    return $actual
}
function Ensure-Qemu {
    $provided = $env:WINDOWS_QEMU_IMG
    $method = "provided-or-existing"
    $tool = $null
    if ($provided) {
        $tool = Full-LocalPath $provided
        if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "WINDOWS_QEMU_IMG is missing" }
    }
    if (-not $tool) {
        $command = Get-Command qemu-img -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command) { $tool = $command.Source }
    }
    if (-not $tool) {
        $candidate = Join-Path $env:ProgramFiles "qemu/qemu-img.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $tool = $candidate }
    }
    $packageVersion = $null
    if (-not $tool) {
        $choco = Get-Command choco -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $choco) { throw "Provide WINDOWS_QEMU_IMG; the hosted Chocolatey command is unavailable" }
        # Explicitly authorized tool supply on this disposable runner, never upstream auto-install.
        $arguments = @("install", "qemu", "--yes", "--no-progress", "--limit-output",
            "--source=https://community.chocolatey.org/api/v2/")
        if ($env:WINDOWS_QEMU_PACKAGE_VERSION) { $arguments += "--version=" + $env:WINDOWS_QEMU_PACKAGE_VERSION }
        Emit "tool-supply" @{package="qemu"; supplier="Chocolatey community"; silent=$true}
        Native $choco.Source $arguments @(0, 3010)
        $candidate = Join-Path $env:ProgramFiles "qemu/qemu-img.exe"
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "Chocolatey did not supply qemu-img at its expected path" }
        $tool = $candidate
        $method = "chocolatey-qemu"
        if ($env:ChocolateyInstall) {
            $nuspec = Join-Path $env:ChocolateyInstall "lib/qemu/qemu.nuspec"
            if (Test-Path -LiteralPath $nuspec -PathType Leaf) {
                $packageVersion = ([xml](Get-Content -LiteralPath $nuspec -Raw)).package.metadata.version
            }
        }
    }
    $version = Native $tool @("--version") -Capture
    if ($version -match 'qemu-img version ([0-9]+)\.([0-9]+)') {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
    }
    else { throw "The supplied qemu-img version is unknown" }
    if ($major -lt 5 -or ($major -eq 5 -and $minor -lt 1)) { throw "A current qemu-img with zstd QCOW2 support is required" }
    return [ordered]@{
        path=$tool; method=$method; version=$version.Trim(); package_version=[string]$packageVersion
        sha256=(Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash.ToLowerInvariant()
        install_source=if ($method -eq "chocolatey-qemu") { "https://community.chocolatey.org/api/v2/" } else { "explicit/existing local tool" }
    }
}
function Architecture([object]$Value) {
    switch (([string]$Value).ToLowerInvariant()) {
        "arm64" { return "arm64" }
        "12" { return "arm64" }
        default { return ([string]$Value).ToLowerInvariant() }
    }
}
function Select-Professional([string]$Iso) {
    $mounted = $false
    try {
        if ((Get-DiskImage -ImagePath $Iso -ErrorAction Stop).Attached) { throw "Preserve the caller's existing ISO mount" }
        $mounted = $true
        $image = Mount-DiskImage -ImagePath $Iso -PassThru -ErrorAction Stop
        $volumes = @($image | Get-Volume)
        if ($volumes.Count -ne 1 -or -not $volumes[0].DriveLetter) { throw "The ISO did not expose one mounted volume" }
        $wim = Join-Path (([string]$volumes[0].DriveLetter) + ":\") "sources/install.wim"
        if (-not (Test-Path -LiteralPath $wim -PathType Leaf)) { throw "The verified ISO lacks install.wim" }
        $selected = @()
        $enumerated = @()
        foreach ($entry in @(Get-WindowsImage -ImagePath $wim -ErrorAction Stop)) {
            $detail = Get-WindowsImage -ImagePath $wim -Index ([int]$entry.ImageIndex) -ErrorAction Stop
            $architecture = Architecture $detail.Architecture
            $facts = [ordered]@{
                image_index=[int]$detail.ImageIndex; image_name=[string]$detail.ImageName
                edition_id=[string]$detail.EditionId; architecture=$architecture
                version=[string]$detail.Version; sp_build=[int]$detail.SPBuild; sp_level=[int]$detail.SPLevel
                installation_type=[string]$detail.InstallationType; image_size_bytes=[long]$detail.ImageSize
                default_language=[string]$detail.DefaultLanguage
                languages=@($detail.Languages | ForEach-Object { [string]$_ })
            }
            $enumerated += $facts
            if ($facts.edition_id -eq "Professional" -and $architecture -eq "arm64") { $selected += $facts }
        }
        if ($selected.Count -ne 1) { throw "The ISO must contain exactly one Professional ARM64 edition" }
        if ($selected[0].image_size_bytes -le 0) { throw "DISM did not report a usable image size" }
        return [ordered]@{
            format="droidvm-windows-image-info-v1"; evidence_mode="actual_dism_image_metadata"
            observed_at_utc=[DateTime]::UtcNow.ToString("o"); windows=$selected[0]; enumerated_images=$enumerated
        }
    }
    finally {
        if ($mounted -and (Get-DiskImage -ImagePath $Iso -ErrorAction Stop).Attached) {
            Dismount-DiskImage -ImagePath $Iso -ErrorAction Stop | Out-Null
        }
    }
}
function Export-StepPath([string]$Name, [string]$Value) {
    if (-not $env:GITHUB_ENV -or $Value.Contains([Environment]::NewLine)) { throw "GitHub environment output is unavailable or malformed" }
    [IO.File]::AppendAllText($env:GITHUB_ENV, ($Name + "=" + $Value + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))
}

$TempParent = if ($env:WINDOWS_TEMP_PARENT) { Full-LocalPath $env:WINDOWS_TEMP_PARENT } else { Full-LocalPath $env:RUNNER_TEMP }
if (-not (Test-Path -LiteralPath $TempParent)) { [IO.Directory]::CreateDirectory($TempParent) | Out-Null }
$null = Assert-Child $TempParent $TempParent -AllowParent
$OwnedRoot = Assert-Child (Join-Path $TempParent ("droidvm-windows-" + [guid]::NewGuid().ToString("N"))) $TempParent
[IO.Directory]::CreateDirectory($OwnedRoot) | Out-Null
$Inputs = Join-Path $OwnedRoot "inputs"
$Stage = Join-Path $OwnedRoot "windows-stage"
$Release = Join-Path $OwnedRoot "release"
foreach ($directory in @($Inputs, $Stage)) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
# The sealer owns creation of WINDOWS_RELEASE_DIR and requires it not to exist.
if (Test-Path -LiteralPath $Release) { throw "The new release path unexpectedly exists" }
Export-StepPath "WINDOWS_STAGE_DIR" $Stage
Export-StepPath "WINDOWS_OWNED_ROOT" $OwnedRoot
Export-StepPath "WINDOWS_RELEASE_DIR" $Release

$RecordPath = Join-Path $Stage "build-record.json"
$Record = [ordered]@{
    format="droidvm-windows-build-record-v1"; status="incomplete"; evidence_mode="actual_windows_build"
    started_at_utc=[DateTime]::UtcNow.ToString("o"); files=[ordered]@{}
    source=[ordered]@{
        iso=[ordered]@{filename=$Lock.iso_filename; bytes=[long]$Lock.iso_bytes; publisher_sha256=$Lock.publisher_sha256}
        driver=[ordered]@{repository=$Lock.driver_repository; commit=$Lock.driver_commit; original_url=$Lock.driver_url
            bytes=[long]$Lock.driver_bytes; sha256=$Lock.driver_sha256; certificate_sha256=$Lock.driver_certificate_sha256}
        builder=[ordered]@{repository=$Lock.builder_repository; base_commit=$Lock.builder_commit
            patch_sha256=(Get-FileHash -LiteralPath $PatchPath -Algorithm SHA256).Hash.ToLowerInvariant()}
        source_lock_sha256=(Get-FileHash -LiteralPath $LockPath -Algorithm SHA256).Hash.ToLowerInvariant()
        profile_sha256=(Get-FileHash -LiteralPath $ProfilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    github=[ordered]@{repository=$env:GITHUB_REPOSITORY; run_id=$env:GITHUB_RUN_ID; run_attempt=$env:GITHUB_RUN_ATTEMPT
        job=$env:GITHUB_JOB; workflow=$env:GITHUB_WORKFLOW; source_commit=$env:GITHUB_SHA
        runner_environment=$env:RUNNER_ENVIRONMENT; runner_os=$env:RUNNER_OS; image_os=$env:ImageOS; image_version=$env:ImageVersion}
    host_os_observation=[ordered]@{caption=[string]$hostOperatingSystem.Caption; version=[string]$hostOperatingSystem.Version
        build_number=[string]$hostOperatingSystem.BuildNumber; product_type=[int]$hostOperatingSystem.ProductType}
    scope="Offline Windows image construction and disk checks; cloud stage has no firmware/vars or phone execution"
    phone_boot_verified=$false; android_runtime_loaded=$false; guest_first_boot_executed=$false
}
Json-File $RecordPath $Record
$Phase = "preflight"
$IsoUrl = $null
$Password = $null
try {
    $downloadFloor = [long]$Lock.iso_bytes + [long]$Lock.driver_bytes + 4GB
    $freeBefore = Free-Bytes $OwnedRoot
    $Record["capacity"] = [ordered]@{temp_parent=$TempParent; free_before_bytes=$freeBefore; download_floor_bytes=$downloadFloor}
    if ($freeBefore -lt $downloadFloor) {
        throw "The selected volume cannot hold verified inputs and tool supply; set WINDOWS_TEMP_PARENT to an explicit larger owned parent"
    }
    if (-not $env:WINDOWS_ISO_URL) { throw "WINDOWS_ISO_URL must supply the private Microsoft download ticket" }
    $IsoUrl = [uri]$env:WINDOWS_ISO_URL
    if ($IsoUrl.Scheme -ne "https") { throw "The ISO ticket must use HTTPS" }
    # Keep the ticket local before any public-source or tool-supply child process.
    $env:WINDOWS_ISO_URL = $null
    $Record.source.iso["public_download_path"] = Public-DownloadPath $IsoUrl
    $Record.source.iso["transport_credentials_and_query_removed"] = $true

    $Phase = "builder-source"
    Emit $Phase
    $Builder = Join-Path $OwnedRoot "builder"
    [IO.Directory]::CreateDirectory($Builder) | Out-Null
    # actions/checkout on this Windows runner used this existing Git application.
    # Resolve exactly one absolute tool, rather than passing a .Source array to Native.
    $gitCommands = @(Get-Command -Name "C:\Program Files\Git\bin\git.exe" -CommandType Application -ErrorAction Stop)
    if ($gitCommands.Count -ne 1) { throw "The existing checkout Git path must identify exactly one application" }
    $git = Full-LocalPath $gitCommands[0].Source
    $gitVersion = Native $git @("--version") -Capture
    $Record.source.builder["git_tool"] = [ordered]@{path=$git; version=$gitVersion.Trim()}
    Emit "git-tool" @{path=$git; version=$gitVersion.Trim()}
    Native $git @("-C", $Builder, "init", "-q")
    Native $git @("-C", $Builder, "remote", "add", "origin", $Lock.builder_repository)
    Native $git @("-C", $Builder, "fetch", "--depth", "1", "origin", $Lock.builder_commit)
    Native $git @("-C", $Builder, "checkout", "--detach", "FETCH_HEAD")
    $head = Native $git @("-C", $Builder, "rev-parse", "HEAD") -Capture
    if ($head.Trim() -ne $Lock.builder_commit) { throw "Builder source pin mismatch" }
    Native $git @("-C", $Builder, "apply", "--check", $PatchPath)
    Native $git @("-C", $Builder, "apply", $PatchPath)
    $Record.source.builder["actual_base_commit"] = $head.Trim()
    $Record.source.builder["applied_patch"] = "windows-safe-provisioning.patch"
    Json-File $RecordPath $Record
    Emit "builder-source-verified" @{actual_base_commit=$head.Trim(); patch_sha256=$Record.source.builder.patch_sha256}

    $Phase = "tool-supply"
    $Qemu = Ensure-Qemu
    $Record["qemu"] = $Qemu
    $Phase = "image-command-preflight"
    $imageCommands = @("Get-WindowsImage", "Get-WindowsDriver", "Get-DiskImage", "Mount-DiskImage", "Dismount-DiskImage", "Get-Volume")
    foreach ($imageCommand in $imageCommands) {
        $null = Get-Command -Name $imageCommand -CommandType Cmdlet,Function -ErrorAction Stop | Select-Object -First 1
    }
    Emit "image-commands-ready" @{commands=$imageCommands}

    $Iso = Join-Path $Inputs $Lock.iso_filename
    $DriverZip = Join-Path $Inputs "gunyah-arm64-drivers.zip"
    $Phase = "iso-download"
    $Record.source.iso["actual_sha256"] = Download-Verified $IsoUrl.AbsoluteUri $Iso ([long]$Lock.iso_bytes) $Lock.publisher_sha256 "windows-iso"
    # Release the local ticket after its only use.
    $IsoUrl = $null
    $Phase = "driver-download"
    $Record.source.driver["actual_sha256"] = Download-Verified $Lock.driver_url $DriverZip ([long]$Lock.driver_bytes) $Lock.driver_sha256 "arm64-drivers"

    $Phase = "image-enumeration"
    $ImageInfo = Select-Professional $Iso
    Json-File (Join-Path $Stage "windows-image-info.json") $ImageInfo
    $Record["windows"] = $ImageInfo.windows
    Emit "selected-image" @{image_index=$ImageInfo.windows.image_index; edition_id=$ImageInfo.windows.edition_id
        architecture=$ImageInfo.windows.architecture; version=$ImageInfo.windows.version; image_size_bytes=$ImageInfo.windows.image_size_bytes}
    $freeBeforeBuild = Free-Bytes $OwnedRoot
    # Both VHDX and output QCOW2 coexist. This is a conservative working estimate,
    # based on actual DISM ImageSize, not on the thin disk's 64 GiB logical maximum.
    $imageBudget = [long]$ImageInfo.windows.image_size_bytes + 4GB
    $neededAdditional = 2 * $imageBudget + 4GB
    $Record.capacity["free_before_build_bytes"] = $freeBeforeBuild
    $Record.capacity["additional_budget_bytes"] = $neededAdditional
    $Record.capacity["budget_basis"] = "two copies of actual DISM ImageSize plus 4 GiB each, plus 4 GiB margin"
    $Record.capacity["budget_is_estimate"] = $true
    Emit "capacity-plan" @{available_bytes=$freeBeforeBuild; required_additional_bytes=$neededAdditional}
    if ($freeBeforeBuild -lt $neededAdditional) {
        throw "The selected temp volume lacks the image working budget; use an explicit larger WINDOWS_TEMP_PARENT. No unrelated software is cleared"
    }
    $Phase = "credential-provisioning"
    $random = [byte[]]::new(32)
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($random) }
    finally { $generator.Dispose() }
    $Password = [Convert]::ToHexString($random)
    Write-Output ("::add-mask::" + $Password)
    Json-File (Join-Path $Stage "private-credentials.json") ([ordered]@{
        format="droidvm-windows-private-credentials-v1"; username="DroidVM"; password=$Password
        autologon=$false; ssh_provisioned=$false; rdp_provisioned=$false
        generated_at_utc=[DateTime]::UtcNow.ToString("o")
    })
    $Disk = Join-Path $Stage "Windows11.qcow2"
    $env:DVM_OWNED_ROOT = $OwnedRoot
    $env:DVM_TEMP_PARENT = $TempParent
    $env:DVM_RECORD_DIR = $Stage
    $env:SRC_ISO = $Iso
    $env:DRIVERS_DIR = $DriverZip
    $env:DRIVER_DIR = "ZIP/drivers"
    $env:DRIVER_CERT = "ZIP/DroidVM_Test.cer"
    $env:DVM_USERNAME = "DroidVM"
    $env:DVM_PASSWORD = $Password
    $env:IMAGE_INDEX = [string]$ImageInfo.windows.image_index
    $env:DISK_SIZE_MB = "65536"
    $env:OUT_QCOW = $Disk
    $env:OUT_VMPKG = $null
    $env:COMPRESS = "1"
    $env:DVM_QEMU_IMG = $Qemu.path
    $env:EMS_SAC_SOURCE = "skip"
    $Phase = "offline-windows-build"
    Emit $Phase @{image_index=$ImageInfo.windows.image_index; edition_id="Professional"; architecture="arm64"}
    & (Join-Path $Builder "windows/build.ps1")
    if (-not $?) { throw "The offline Windows builder failed" }
    $env:DVM_PASSWORD = $null
    $Password = $null

    $Phase = "disk-validation"
    $infoText = Native $Qemu.path @("info", "--output=json", $Disk) -Capture
    $diskInfo = $infoText | ConvertFrom-Json
    if ($diskInfo.format -ne "qcow2" -or [long](Get-Field $diskInfo "virtual-size") -ne 64GB -or
        (Get-Field $diskInfo "backing-filename") -or (Get-Field $diskInfo "full-backing-filename")) {
        throw "The output must be one standalone 64 GiB QCOW2 disk"
    }
    $specific = Get-Field (Get-Field $diskInfo "format-specific") "data"
    if ((Get-Field $specific "compression-type") -ne "zstd" -or
        (Get-Field $specific "data-file") -or (Get-Field $specific "encrypt")) {
        throw "The output QCOW2 lacks the selected zstd/standalone format"
    }
    $checkText = Native $Qemu.path @("check", "--output=json", $Disk) -Capture
    $diskCheck = $checkText | ConvertFrom-Json
    if ($null -eq (Get-Field $diskCheck "check-errors") -or
        [long](Get-Field $diskCheck "check-errors") -ne 0 -or
        ((Get-Field $diskCheck "corruptions") -and [long](Get-Field $diskCheck "corruptions") -ne 0) -or
        ((Get-Field $diskCheck "leaks") -and [long](Get-Field $diskCheck "leaks") -ne 0)) {
        throw "qemu-img did not report a clean complete disk check"
    }
    $Record["disk_info"] = $diskInfo
    $Record["disk_check"] = $diskCheck
    $Record["virtual_disk_bytes"] = 64GB
    $driverObservation = Get-Content -LiteralPath (Join-Path $Stage "installed-drivers.json") -Raw | ConvertFrom-Json
    $expectedDrivers = @("NetKVM", "rdmapool", "pvmpower", "vioinput", "viostor", "viosnd")
    if ($driverObservation.format -ne "droidvm-windows-installed-drivers-v1" -or
        $driverObservation.evidence_mode -ne "actual_offline_dism" -or
        @($driverObservation.drivers).Count -ne 6 -or
        @(Compare-Object $expectedDrivers @($driverObservation.drivers | ForEach-Object name)).Count -ne 0) {
        throw "Actual DISM driver observation lacks the six selected packages"
    }
    $Phase = "stage-hashes"
    foreach ($name in @("Windows11.qcow2", "private-credentials.json", "windows-image-info.json", "installed-drivers.json")) {
        $path = Assert-Child (Join-Path $Stage $name) $OwnedRoot
        $file = Get-Item -LiteralPath $path
        if ($file.PSIsContainer -or $file.Length -le 0) { throw "An actual stage file is missing: $name" }
        $Record.files[$name] = [ordered]@{path=$name; bytes=[long]$file.Length
            sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
    }
    $Record.status = "complete"
    $Record["completed_at_utc"] = [DateTime]::UtcNow.ToString("o")
    $Record.capacity["free_after_bytes"] = Free-Bytes $OwnedRoot
    Json-File $RecordPath $Record
    Emit "complete" @{stage=$Stage; file_count=$Record.files.Count; firmware_added=$false; phone_boot_verified=$false}
}
catch {
    $Record.status = "failed"
    $Record["failure_phase"] = $Phase
    $Record["failure_type"] = $_.Exception.GetType().FullName
    # Only these controlled preflight commands can expose safe command/file/line facts.
    # Never serialize exception text, invocation arguments or the command line.
    $failureFacts = @{failure_phase=$Phase; error_type=$Record.failure_type; owned_root=$OwnedRoot}
    if ($Phase -in @("builder-source", "image-command-preflight") -and
        $_.Exception -is [System.Management.Automation.CommandNotFoundException]) {
        $Record["failure_command_name"] = Get-Field $_.Exception "CommandName"
        $Record["failure_source_file"] = Get-Field $_.InvocationInfo "ScriptName"
        $Record["failure_source_line"] = Get-Field $_.InvocationInfo "ScriptLineNumber"
        $failureFacts["command_name"] = $Record.failure_command_name
        $failureFacts["source_file"] = $Record.failure_source_file
        $failureFacts["source_line"] = $Record.failure_source_line
    }
    # Retain only source locations from known owned scripts, never stack text or arguments.
    $sourceFrames = @()
    foreach ($traceLine in ([string]$_.ScriptStackTrace -split "`n")) {
        if ($traceLine.Trim() -match '^at [^,]+, ([A-Za-z]:[\\/].*\.ps1): line ([0-9]+)$') {
            $sourceFile = [IO.Path]::GetFullPath($Matches[1])
            $sourceLine = [int]$Matches[2]
            if ($sourceFile.StartsWith($OwnedRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
                $sourceFile.Equals((Join-Path $PSScriptRoot 'build_windows_ci.ps1'), [StringComparison]::OrdinalIgnoreCase)) {
                $sourceFrames += [ordered]@{file=$sourceFile; line=$sourceLine}
            }
        }
    }
    $Record["failure_source_frames"] = $sourceFrames
    $failureFacts["source_frames"] = $sourceFrames
    Json-File $RecordPath $Record
    Emit "failed" $failureFacts
    throw ("Windows image construction failed at " + $Phase + "; the owned files are preserved")
}
finally {
    $env:WINDOWS_ISO_URL = $null
    $env:DVM_PASSWORD = $null
    $IsoUrl = $null
    $Password = $null
}

param(
	[Parameter(Mandatory = $true)][string]$PayloadPath,
	[Parameter(Mandatory = $true)][string]$OutputPath
)

$ErrorActionPreference = "Stop"

function Require-Env([string]$Name) {
	$value = [Environment]::GetEnvironmentVariable($Name)
	if ([string]::IsNullOrWhiteSpace($value)) {
		throw "missing $Name"
	}
	return $value.Trim()
}

$endpoint = Require-Env "ARTIFACT_SIGNING_ENDPOINT"
$account = Require-Env "ARTIFACT_SIGNING_ACCOUNT"
$profile = Require-Env "ARTIFACT_SIGNING_CERTIFICATE_PROFILE"
$tool = Join-Path $env:COSESIGNTOOL_TOOLS_DIR "CoseSignTool.exe"
if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
	throw "CoseSignTool not found at $tool"
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("feed-head-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $work | Out-Null
try {
	$signed = Join-Path $work "head.cose"
	& $tool sign --payload $PayloadPath --SignatureFile $signed --ep --scitt false --cp azure-artifact-signing --aas-endpoint $endpoint.TrimEnd("/") --aas-account-name $account --aas-cert-profile-name $profile
	if ($LASTEXITCODE -ne 0) {
		throw "CoseSignTool failed with exit code $LASTEXITCODE"
	}
	Copy-Item -LiteralPath $signed -Destination $OutputPath -Force
}
finally {
	Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "signed $OutputPath"

param(
    [string]$RepoName = "ringeris",
    [string]$Token = ""
)

$ErrorActionPreference = "Stop"

if ($Token -ne "") {
    $env:GH_TOKEN = $Token
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Error "gh CLI not found, install it first: winget install GitHub.cli"
}

if (-not $env:GH_TOKEN) {
    gh auth status
}

git remote remove origin 2>$null

gh repo create "mel0k1/$RepoName" --public --source . --remote origin --push

Write-Host "Repository created and pushed: https://github.com/mel0k1/$RepoName"

Param(
    [switch]$WSL
)

Write-Host "Installing recon tools..." -ForegroundColor Cyan

function Try-Run($Command, $Description) {
    try {
        Write-Host "→ $Description" -ForegroundColor Yellow
        & $Command
    } catch {
        Write-Warning "$Description failed: $($_.Exception.Message)"
    }
}

function Ensure-Winget {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Warning "winget not found. Install from Microsoft Store."
        return $false
    }
    return $true
}

$hasWinget = Ensure-Winget

if ($hasWinget) {
    Try-Run { winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements --silent } "Install nmap (winget)"
    Try-Run { winget install -e --id OpenJS.NodeJS.LTS --accept-package-agreements --accept-source-agreements --silent } "Install Node.js LTS (winget)"
    Try-Run { winget install -e --id GoLang.Go --accept-package-agreements --accept-source-agreements --silent } "Install Go (winget)"
}

# Ensure Go bin in PATH for current session
$goBin = Join-Path $env:USERPROFILE 'go\bin'
if ((Test-Path $goBin) -and ($env:Path -notlike "*${goBin}*")) {
    $env:Path = "$goBin;$env:Path"
}

# Python CLIs
Try-Run { $env:PIP_DISABLE_PIP_VERSION_CHECK="1"; python -m pip install --upgrade pip } "Upgrade pip"
Try-Run { pip install theHarvester sublist3r wafw00f whatweb } "Install Python CLIs (theHarvester, sublist3r, wafw00f, whatweb)"

# Scoop for tools on Windows
if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
    Try-Run { Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force } "Set execution policy for scoop"
    Try-Run { iwr -useb get.scoop.sh | iex } "Install scoop"
}

Try-Run { scoop install git } "Install git via scoop"
Try-Run { scoop bucket add extras } "Add extras bucket"
Try-Run { scoop install nuclei httpx subfinder naabu } "Install ProjectDiscovery tools (nuclei, httpx, subfinder, naabu)"
Try-Run { scoop install gobuster ffuf feroxbuster masscan amass } "Install gobuster, ffuf, feroxbuster, masscan, amass via scoop"

# Go-based install on Windows as fallback
if (Get-Command go -ErrorAction SilentlyContinue) {
    Try-Run { go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest } "Build subfinder (Go)"
    Try-Run { go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest } "Build httpx (Go)"
    Try-Run { go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest } "Build nuclei (Go)"
    Try-Run { go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest } "Build naabu (Go)"
    Try-Run { go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest } "Build dnsx (Go)"
    Try-Run { go install -v github.com/OJ/gobuster/v3@latest } "Build gobuster (Go)"
    Try-Run { go install -v github.com/ffuf/ffuf@latest } "Build ffuf (Go)"
    Try-Run { go install -v github.com/epi052/feroxbuster@latest } "Build feroxbuster (Go)"
    Try-Run { go install -v github.com/owasp-amass/amass/v4/...@latest } "Build amass (Go)"
}

# WSL path
if ($WSL) {
    if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
        Write-Warning "WSL not detected. Enable it first (wsl --install)."
    } else {
        Try-Run { wsl bash -lc "sudo apt update && sudo apt install -y nmap masscan nikto amass golang feroxbuster gobuster ffuf" } "Install APT tools in WSL"
        Try-Run { wsl bash -lc "echo 'export PATH=\"\$HOME/go/bin:\$PATH\"' >> ~/.bashrc" } "Ensure Go bin in PATH in WSL"
        Try-Run { wsl bash -lc "source ~/.bashrc && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" } "Install subfinder via go in WSL"
        Try-Run { wsl bash -lc "source ~/.bashrc && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest" } "Install httpx via go in WSL"
        Try-Run { wsl bash -lc "source ~/.bashrc && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" } "Install nuclei via go in WSL"
        Try-Run { wsl bash -lc "source ~/.bashrc && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" } "Install naabu via go in WSL"
        Try-Run { wsl bash -lc "source ~/.bashrc && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest" } "Install dnsx via go in WSL"
    }
}

Write-Host "Done. Restart terminal for PATH changes to take effect." -ForegroundColor Green

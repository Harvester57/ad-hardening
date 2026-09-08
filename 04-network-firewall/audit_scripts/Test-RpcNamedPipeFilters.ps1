# Test-RpcNamedPipeFilters.ps1
# Description: Audits active RPC filters configuration using Netsh queries.

Write-Host "Auditing RPC filters configuration..." -ForegroundColor Cyan

# Query active RPC filters
$filters = netsh.exe rpc filter show filter

# Define expected RPC filter rules with their metadata
$expectedRules = @(
    @{ FilterKey = "d0c7640c-9355-4e52-8335-c12835559c10"; Name = "MS-SCMR Service Control Manager (Block ncacn_np)"; Pipe = "\PIPE\svcctl" }
    @{ FilterKey = "a43b9dd2-0866-4476-89dc-2e9b200762af"; Name = "MS-TSCH Task Scheduler Remoting (Block ncacn_np)"; Pipe = "\PIPE\atsvc" }
    @{ FilterKey = "13518c11-e3d8-4f62-9461-eda11beb540a"; Name = "MS-TSCH Task Scheduler Legacy AT 1 (Block All)"; Pipe = "\PIPE\atsvc" }
    @{ FilterKey = "1c079a18-e91f-4698-9868-68a121490636"; Name = "MS-TSCH Task Scheduler Legacy AT 2 (Block All)"; Pipe = "\PIPE\atsvc" }
    @{ FilterKey = "dedffabf-db89-4177-be77-1954aa2c0b95"; Name = "MS-EVEN6 EventLog v6.0 Remoting (Block ncacn_np)"; Pipe = "\PIPE\eventlog" }
    @{ FilterKey = "f7f68868-5f50-4cda-a18c-6a7a549652e7"; Name = "MS-EVEN EventLog Legacy (Block All)"; Pipe = "\PIPE\eventlog" }
    @{ FilterKey = "43873c58-e130-4ffb-8858-d259a673a917"; Name = "MS-DFSNM DFS Namespace Mgmt (Permit Domain Admins)"; Pipe = "\PIPE\netdfs" }
    @{ FilterKey = "0a239867-73db-45e6-b287-d006fe3c8b18"; Name = "MS-DFSNM DFS Namespace Mgmt (Block Others)"; Pipe = "\PIPE\netdfs" }
    @{ FilterKey = "7966512a-f2f4-4cb1-812d-d967ab83d28a"; Name = "MS-RPRN Print System Remote (Block ncacn_np)"; Pipe = "\PIPE\spoolss" }
    @{ FilterKey = "d71d00db-3eef-4935-bedf-20cf628abd9e"; Name = "MS-EFSR via lsarpc (Permit Kerberos Encrypted)"; Pipe = "\PIPE\lsarpc" }
    @{ FilterKey = "3a4cce27-a7fa-4248-b8b8-ef6439a2c0ff"; Name = "MS-EFSR via lsarpc (Block Others)"; Pipe = "\PIPE\lsarpc" }
    @{ FilterKey = "c5cf8020-c83c-4803-9241-8c7f3b10171f"; Name = "MS-EFSR via efsrpc (Permit Kerberos Encrypted)"; Pipe = "\PIPE\efsrpc" }
    @{ FilterKey = "9ad23a91-085d-4f99-ae15-85e0ad801278"; Name = "MS-EFSR via efsrpc (Block Others)"; Pipe = "\PIPE\efsrpc" }
    @{ FilterKey = "50754fe4-aa2d-42ff-8196-e90ea8fd2527"; Name = "MS-DNSP DNS Server Remote Mgmt (Block ncacn_np)"; Pipe = "\PIPE\DNSSERVER" }
    @{ FilterKey = "644291ca-9530-4066-b654-e7b838ebdc06"; Name = "MimiCom Mimikatz Remote C2 (Block All)"; Pipe = "Any" }
    @{ FilterKey = "5270da6b-67a8-4cbf-8b2c-fa5d0abcb975"; Name = "MS-FSRVP File Server Remote VSS (Block ncacn_np)"; Pipe = "\PIPE\FssagentRpc" }
)

$missingFilters = @()
$activeFiltersCount = 0

# Join netsh output into a single string for fast and case-insensitive matching
$rawFiltersOutput = ($filters -join "`n").ToLowerInvariant()

foreach ($rule in $expectedRules) {
    $targetKey = $rule.FilterKey.ToLowerInvariant()
    if ($rawFiltersOutput.Contains($targetKey)) {
        $activeFiltersCount++
        Write-Host "[+] Active: $($rule.Name) [Key: $($rule.FilterKey)]" -ForegroundColor Green
    } else {
        $missingFilters += $rule
        Write-Host "[-] Missing: $($rule.Name) [Key: $($rule.FilterKey)]" -ForegroundColor Yellow
    }
}

Write-Host "`nSummary: $activeFiltersCount of $($expectedRules.Count) expected RPC filters are active." -ForegroundColor Cyan

if ($missingFilters.Count -eq 0) {
    Write-Host "[+] All 16 RPC named pipe filters are active and enforced." -ForegroundColor Green
    Write-Host "Audit result: COMPLIANT" -ForegroundColor Green
} else {
    Write-Host "[!] NON-COMPLIANT: $($missingFilters.Count) RPC named pipe filter rule(s) are missing or inactive." -ForegroundColor Red
    Write-Host "Audit result: NON-COMPLIANT" -ForegroundColor Red
}

# Define Log function
function Log {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path "$output_dir\log.txt" -Value "$timestamp - $message"
}

# Define ErrorLog function
function ErrorLog {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path "$output_dir\error.txt" -Value "$timestamp - ERROR: $message"
}

# Function to detect OS and available tools
function DetectEnvironment {
    Log "Detecting environment..."
    $os = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption
    $envVars = Get-ChildItem Env: | Out-String
    $envVars | Out-File -FilePath "$output_dir\env_variables.txt"
    Log "Detected OS: $os"
    return $os
}

# Function to perform network traffic capture and analysis
function CaptureTraffic {
    Log "Starting network traffic capture..."
    try {
        $networkCapturePath = "$output_dir\network_traffic.etl"
        Log "Using netsh trace to capture network traffic."
        netsh trace start capture=yes tracefile=$networkCapturePath
        Start-Sleep -Seconds 140
        netsh trace stop
        Log "Network traffic capture completed with netsh trace."
        AnalyzeNetworkTraffic $networkCapturePath
    } catch {
        ErrorLog "Failed to capture network traffic: $_"
    }
}

# Function to analyze network traffic
function AnalyzeNetworkTraffic {
    param (
        [string]$networkCapturePath
    )
    Log "Analyzing network traffic..."
    try {
        $networkCaptureCsvPath = "$output_dir\network_traffic.csv"
        netsh trace convert input=$networkCapturePath output=$networkCaptureCsvPath
        $packets = Import-Csv $networkCaptureCsvPath
        
        # Calculate and store metrics, checking for the existence of FrameLength
        $totalPackets = $packets.Count
        $totalBytes = 0
        if ($packets[0].PSObject.Properties['FrameLength']) {
            $totalBytes = ($packets | Measure-Object -Property FrameLength -Sum).Sum
        } else {
            Log "FrameLength property not found in packets"
        }

        $captureDuration = 140
        $packetsPerSecond = [math]::Round($totalPackets / $captureDuration, 2)
        $bytesPerSecond = if ($totalBytes -ne 0) { [math]::Round($totalBytes / $captureDuration, 2) } else { 0 }
        $protocols = $packets | Group-Object -Property ProtocolDescription | Select-Object Name, Count
        $topTalkers = $packets | Group-Object -Property Source | Sort-Object Count -Descending | Select-Object -First 5 Name, Count
        $topConnections = $packets | Group-Object -Property Destination | Sort-Object Count -Descending | Select-Object -First 5 Name, Count
        
        # Summarize
        $networkSummary = @"
Network Traffic Summary:
- Total Packets: $totalPackets
- Total Bytes: $totalBytes
- Packets per Second: $packetsPerSecond
- Bytes per Second: $bytesPerSecond
- Protocols Used: $(($protocols | Format-Table -AutoSize | Out-String))
- Top Talkers: $(($topTalkers | Format-Table -AutoSize | Out-String))
- Top Connections: $(($topConnections | Format-Table -AutoSize | Out-String))
"@
        $networkSummary | Out-File -Append -FilePath "$output_dir\summary.txt"
        Log "Network traffic analysis completed."
    } catch {
        ErrorLog "Failed to analyze network traffic: $_"
    }
}

# Function to test network connections
function TestNetworkConnections {
    $ips = "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4" # Add more IPs as needed
    foreach ($ip in $ips) {
        try {
            $pingResult = Test-Connection -ComputerName $ip -Count 1 -ErrorAction Stop
            if ($pingResult.StatusCode -eq 0) {
                Log "Successfully pinged ${ip}"
            } else {
                ErrorLog "Failed to ping ${ip}: Response status code ${pingResult.StatusCode}"
            }
        } catch {
            ErrorLog "Failed to ping ${ip}: $($_.Exception.Message)"
        }
    }
}

# Function to collect network interfaces
function CollectNetworkInterfaces {
    Log "Collecting network interfaces..."
    try {
        $netAdapters = Get-NetAdapter
        $netAdapters | Format-List | Out-File -FilePath "$output_dir\network_interfaces.txt"
        $interfacesSummary = $netAdapters | Select-Object -Property Name, Status, MacAddress, LinkSpeed, @{Name='IPAddress';Expression={(Get-NetIPAddress -InterfaceAlias $_.Name).IPAddress}} | Out-String
        $interfacesSummary | Out-File -Append -FilePath "$output_dir\summary.txt"
        Log "Network interfaces information captured."
    } catch {
        ErrorLog "Failed to collect network interfaces: $_"
    }
}

# Function to scan open ports
function ScanOpenPorts {
    Log "Scanning open ports..."
    try {
        $tcpConnections = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" }
        $tcpConnections | Format-Table -AutoSize | Out-File -FilePath "$output_dir\tcp_connections.txt"
        $topPorts = $tcpConnections | Group-Object -Property LocalPort | Sort-Object Count -Descending | Select-Object -First 10 | Format-Table -AutoSize | Out-String
        $topPorts | Out-File -Append -FilePath "$output_dir\summary.txt"
        Log "Open ports information captured."
    } catch {
        ErrorLog "Failed to scan open ports: $_"
    }
}

# Function to collect running processes
function CollectProcesses {
    Log "Collecting running processes..."
    try {
        $processes = Get-Process
        $topCpuProcesses = $processes | Sort-Object -Property CPU -Descending | Select-Object -First 5 | Format-Table -Property Name, CPU, Id -AutoSize | Out-String
        $topMemoryProcesses = $processes | Sort-Object -Property WorkingSet -Descending | Select-Object -First 5 | Format-Table -Property Name, WorkingSet, Id -AutoSize | Out-String
        $processes | Sort-Object -Property CPU -Descending | Select-Object -First 100 | Format-Table -AutoSize | Out-File -FilePath "$output_dir\running_processes.txt"
        @"
Top 5 Processes by CPU Usage:
$topCpuProcesses

Top 5 Processes by Memory Usage:
$topMemoryProcesses
"@ | Out-File -Append -FilePath "$output_dir\summary.txt"
        Log "Running processes information captured."
    } catch {
        ErrorLog "Failed to collect running processes: $_"
    }
}

# Function to collect disk usage information
function CollectDiskUsage {
    Log "Collecting disk usage information..."
    try {
        $diskInfo = Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free, Provider, Root, @{Name='CurrentLocation';Expression={$_.CurrentLocation}}
        $diskInfo | Export-Csv -Path "$output_dir\disk_usage.csv" -NoTypeInformation
        Log "Disk usage information captured."
    } catch {
        ErrorLog "Failed to collect disk usage information: $_"
    }
}

# Function to capture system logs from the last 15 minutes
function CaptureLogs {
    Log "Capturing system logs..."
    try {
        $logs = Get-WinEvent -FilterHashtable @{LogName="System"; StartTime=(Get-Date).AddMinutes(-15)}
        $logs | Export-Csv -Path "$output_dir\system_logs.csv" -NoTypeInformation

        # Parse logs for key statistics
        $logCount = $logs.Count
        $errorCount = ($logs | Where-Object {$_.LevelDisplayName -eq "Error"}).Count
        $warningCount = ($logs | Where-Object {$_.LevelDisplayName -eq "Warning"}).Count
        $informationCount = ($logs | Where-Object {$_.LevelDisplayName -eq "Information"}).Count
        $infoLogs = $logs | Where-Object {$_.LevelDisplayName -eq "Information"} | Select-Object -Property TimeCreated, Id, Message | Out-String

        $logSummary = @"
System Log Summary:
- Total Entries: $logCount
- Errors: $errorCount
- Warnings: $warningCount
- Information: $informationCount
$infoLogs
"@
        $logSummary | Out-File -Append -FilePath "$output_dir\summary.txt"
        Log "System logs captured."
    } catch {
        ErrorLog "Failed to capture system logs: $_"
    }
}

# Function to scan for malicious files
function ScanMaliciousFiles {
    Log "Scanning for malicious files..."
    try {
        Start-MpScan -ScanType QuickScan -ErrorAction Stop
        Get-MpThreatDetection | Export-Csv -Path "$output_dir\av_scan.txt" -NoTypeInformation
        if (Test-Path "$output_dir\av_scan.txt") {
            $avResults = Get-Content "$output_dir\av_scan.txt"
            $avResults | Out-File -Append -FilePath "$output_dir\summary.txt"
            Log "Antivirus scan completed."
        } else {
            ErrorLog "Antivirus scan did not generate expected output file."
        }
    } catch {
        ErrorLog "Failed to scan for malicious files: $_"
    }
}

# Function to capture crash dump
function CaptureCrashDump {
    Log "Capturing crash dump..."
    try {
        $dumpPath = "$output_dir\crash_dump.dmp"
        procdump -ma -accepteula $PID $dumpPath
        Log "Crash dump captured at $dumpPath"
    } catch {
        ErrorLog "Failed to capture crash dump: $_"
    }
}

# Function to check for hidden users
function CheckHiddenUsers {
    Log "Checking for hidden users..."
    try {
        $hiddenUsers = Get-LocalUser | Where-Object { $_.Name -like "*$" }
        $hiddenUsersSummary = $hiddenUsers | Format-Table -Property Name, Enabled, LastLogon | Out-String
        $hiddenUsersSummary | Out-File -Append -FilePath "$output_dir\summary.txt"
        Log "Hidden users information captured."
    } catch {
        ErrorLog "Failed to check for hidden users: $_"
    }
}

# Function to summarize results
function SummarizeResults {
    Log "Summarizing results..."
    $summary_file = "$output_dir\summary.txt"
    $os = DetectEnvironment
    $envVars = Get-Content "$output_dir\env_variables.txt"
    $errors = Get-Content "$output_dir\error.txt" -ErrorAction SilentlyContinue

    $summary = @"
Security Audit Summary - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
--------------------------------------------------
Operating System: $os
--------------------------------------------------
Environment Variables:
$envVars
--------------------------------------------------
Network Interfaces:
$(Get-Content "$output_dir\network_interfaces.txt")
--------------------------------------------------
Open Ports (TCP):
$(Get-Content "$output_dir\tcp_connections.txt")
--------------------------------------------------
Running Processes:
$(Get-Content "$output_dir\running_processes.txt")
--------------------------------------------------
Disk Usage:
$(Get-Content "$output_dir\disk_usage.csv")
--------------------------------------------------
Antivirus Scan:
$(Get-Content "$output_dir\av_scan.txt")
--------------------------------------------------
System Logs Summary:
$(Get-Content "$output_dir\system_logs.csv")
--------------------------------------------------
Frequent IPs:
$(if (Test-Path "$output_dir\frequent_ips_tcpdump.txt") { Get-Content "$output_dir\frequent_ips_tcpdump.txt" } else { "No frequent IPs found." })
--------------------------------------------------
Hidden Users:
$(Get-Content "$output_dir\hidden_users.txt")
--------------------------------------------------
Errors Encountered:
$errors
"@
    $summary | Out-File -FilePath $summary_file -Force
    Log "Summary report created."
}

# Function to perform user and privilege enumeration
function UserPrivilegeEnumeration {
    Log "Starting user and privilege enumeration..."
    try {
        Get-LocalUser | Format-Table -AutoSize | Out-File -FilePath "$output_dir\users.txt"
        Get-LocalGroupMember -Group "Administrators" | Format-Table -AutoSize | Out-File -FilePath "$output_dir\admin_users.txt" -ErrorAction Stop
        $userSummary = Get-LocalUser | Select-Object -Property Name, Enabled, LastLogon | Out-String
        $adminSummary = Get-LocalGroupMember -Group "Administrators" | Select-Object -Property Name, PrincipalSource | Out-String -ErrorAction Stop
        $userSummary | Out-File -Append -FilePath "$output_dir\summary.txt"
        $adminSummary | Out-File -Append -FilePath "$output_dir\summary.txt"
        Log "User and privilege enumeration completed."
    } catch {
        ErrorLog "Failed to perform user and privilege enumeration: $_"
    }
}

# Function to perform file integrity check
function FileIntegrityCheck {
    Log "Starting file integrity check..."
    try {
        Get-FileHash -Path "C:\Windows\System32\*" -Algorithm SHA256 | Format-Table -AutoSize | Out-File -FilePath "$output_dir\file_integrity_check.txt"
        $fileHashSummary = Get-FileHash -Path "C:\Windows\System32\*" -Algorithm SHA256 | Select-Object -Property Algorithm, Hash, Path | Out-String
        $fileHashSummary | Out-File -Append -FilePath "$output_dir\summary.txt"
        Log "File integrity check completed."
    } catch {
        ErrorLog "Failed to perform file integrity check: $_"
    }
}

# Function to collect detailed system information
function CollectSystemInfo {
    Log "Collecting detailed system information..."
    try {
        Get-ComputerInfo | Out-File -FilePath "$output_dir\system_info.txt"
        $sysInfo = Get-ComputerInfo | Out-String
        $sysInfo | Out-File -Append -FilePath "$output_dir\summary.txt"
        Log "System information collected."
    } catch {
        ErrorLog "Failed to collect system information: $_"
    }
}

# Main script execution
$output_dir = "C:\Users\DenningJonathan\Desktop\security_audit"
if (-not (Test-Path $output_dir)) {
    New-Item -Path $output_dir -ItemType Directory
}

# Run all functions
DetectEnvironment
CollectSystemInfo
CaptureTraffic
CaptureLogs
CollectNetworkInterfaces
ScanOpenPorts
CollectProcesses
CollectDiskUsage
ScanMaliciousFiles
CaptureCrashDump
CheckHiddenUsers
UserPrivilegeEnumeration
FileIntegrityCheck
SummarizeResults

# Cleanup
Log "Cleaning up temporary files..."
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Log "Temporary files cleaned up."

# Completion notification
# Send-MailMessage -To "user@example.com" -From "audit@example.com" -Subject "Security Audit Completed" -Body "Security audit completed. Results are in $output_dir" -SmtpServer "your.smtp.server"

Log "Security audit completed."

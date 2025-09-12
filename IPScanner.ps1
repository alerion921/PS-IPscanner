Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "Advanced Subnet Scanner"
$form.Size = New-Object System.Drawing.Size(1100,625)
$form.StartPosition = "CenterScreen"

$label = New-Object System.Windows.Forms.Label
$label.Text = "Enter Subnet (e.g. 192.168.1)"
$label.AutoSize = $true
$label.Location = New-Object System.Drawing.Point(10,20)
$form.Controls.Add($label)

$textbox = New-Object System.Windows.Forms.TextBox
$textbox.Location = New-Object System.Drawing.Point(10,45)
$textbox.Width = 200
$textbox.Text = "192.168.1"
$form.Controls.Add($textbox)

$button = New-Object System.Windows.Forms.Button
$button.Text = "Start Scan"
$button.width = 90
$button.Location = New-Object System.Drawing.Point(220,42)
$form.Controls.Add($button)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = "Cancel Scan"
$cancelButton.width = 90
$cancelButton.Location = New-Object System.Drawing.Point(320,42)
$form.Controls.Add($cancelButton)

$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Location = New-Object System.Drawing.Point(10,80)
$progress.Size = New-Object System.Drawing.Size(1065,25)
$progress.Minimum = 0
$progress.Maximum = 254
$form.Controls.Add($progress)

$listview = New-Object System.Windows.Forms.ListView
$listview.Location = New-Object System.Drawing.Point(10,120)
$listview.Size = New-Object System.Drawing.Size(1065,420)
$listview.View = 'Details'
$listview.FullRowSelect = $false  # Change this to false to allow single cell selection
$listview.GridLines = $true
$listview.Columns.Add("IP Address",120) | Out-Null
$listview.Columns.Add("Status",80) | Out-Null
$listview.Columns.Add("Method",120) | Out-Null
$listview.Columns.Add("Hostname",160) | Out-Null
$listview.Columns.Add("MAC Address", 220) | Out-Null
$listview.Columns.Add("Web Interface",280) | Out-Null
$form.Controls.Add($listview)

# Replace the entire click handler with this improved version
$listview.Add_Click({
    param($sender, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
        $hit = $listview.HitTest($e.Location)
        if ($hit.Item -and $hit.SubItem) {
            # Clear any existing selection
            $listview.SelectedItems.Clear()
            
            # Select only the clicked item
            $hit.Item.Selected = $true
            
            $clickedText = $hit.SubItem.Text
            if (![string]::IsNullOrWhiteSpace($clickedText) -and 
                $clickedText -ne "N/A" -and 
                $clickedText -ne "Resolving..." -and 
                $clickedText -ne "Scanning...") {
                
                # Format MAC addresses if that's what was clicked
                if ($clickedText -match '([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}') {
                    $formattedText = ($clickedText -replace '-', ':').ToUpper()
                    [System.Windows.Forms.Clipboard]::SetText($formattedText)
                } else {
                    [System.Windows.Forms.Clipboard]::SetText($clickedText)
                }
            }
        }
    }
})

$saveButton = New-Object System.Windows.Forms.Button
$saveButton.Text = "Save Results"
$saveButton.Location = New-Object System.Drawing.Point(10,550)
$form.Controls.Add($saveButton)

$script:timer = $null
$script:jobs = @()
$script:completed = 0
$script:cancel = $false
$script:rsPool = $null
$script:resolveTasks = @()
$script:webTasks = @()
$script:macTasks = @()

function Test-Port {
    param($ip,$port)
    try {
        $tcp = New-Object Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($ip,$port,$null,$null)
        $success = $iar.AsyncWaitHandle.WaitOne(350)
        if ($success) {
            $tcp.EndConnect($iar) | Out-Null
            $tcp.Close()
            return $true
        }
        $tcp.Close()
        return $false
    } catch { return $false }
}

function Format-Mac {
    param([string]$hex)
    $clean = ($hex -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($clean.Length -lt 12) { return $null }
    return ($clean.ToCharArray() |
        ForEach-Object -Begin { $i = 0 } -Process {
            $i++
            $_ + (if ($i % 2 -eq 0 -and $i -lt $clean.Length) { ':' } else { '' })
        }) -join ''
}

function Get-MacAddress {
    param([string]$ip)

    # Force ARP population by sending packets
    try {
        # two ICMP pings
        Test-Connection -ComputerName $ip -Count 2 -Quiet -TimeoutSeconds 1 | Out-Null
    } catch {}

    # Extra kick: try a TCP connect to port 445 (common)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($ip, 445, $null, $null)
        $iar.AsyncWaitHandle.WaitOne(200)
        $client.Close()
    } catch {}

    # 1) Use Get-NetNeighbor if available
    if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
        try {
            $nbr = Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue |
                   Where-Object State -in 'Reachable','Stale'
            if ($nbr) {
                $fmt = Format-Mac $nbr.LinkLayerAddress
                if ($fmt) { return $fmt }
            }
        } catch {}
    }

    # 2) Fallback: arp -a
    try {
        $arpTable = arp -a
        foreach ($line in $arpTable) {
            if ($line -match "^\s*$ip\s+") {
                $parts = $line -split '\s+'
                foreach ($idx in 1..($parts.Length - 1)) {
                    if ($parts[$idx] -match '([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}') {
                        $fmt = Format-Mac $parts[$idx]
                        if ($fmt) { return $fmt }
                    }
                }
            }
        }
    } catch {}

    # 3) Fallback: netsh
    try {
        $nh = netsh interface ip show neighbors |
              Where-Object { $_ -match "\s+$ip\s+" }
        if ($nh) {
            $p = ($nh -split '\s+')[2]
            $fmt = Format-Mac $p
            if ($fmt) { return $fmt }
        }
    } catch {}

    return "fuck"
}

function Queue-MacResolve {
    param(
        [string]$ip,
        [System.Windows.Forms.ListViewItem]$item
    )

    $ps = [powershell]::Create()
    $ps.RunspacePool = $script:rsPool

    $null = $ps.AddScript({
        param($ipAddr)

        # Import SendARP API
        try {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ArpHelper {
    [DllImport("iphlpapi.dll", ExactSpelling=true)]
    public static extern int SendARP(uint destIP, uint srcIP, byte[] macAddr, ref uint macAddrLen);
}
"@ -ErrorAction SilentlyContinue
        } catch {}

        function Convert-IPToInt {
            param([string]$ipAddress)
            $bytes = [System.Net.IPAddress]::Parse($ipAddress).GetAddressBytes()
            [Array]::Reverse($bytes)
            return [System.BitConverter]::ToUInt32($bytes, 0)
        }

        function Format-MacAddress {
            param($macBytes)
            if ($macBytes -is [byte[]]) {
                return (($macBytes | ForEach-Object { $_.ToString('X2') }) -join ':')
            }
            if ($macBytes -is [string]) {
                # Clean the string and ensure consistent format
                $clean = $macBytes -replace '[^0-9A-Fa-f]', ''
                if ($clean.Length -eq 12) {
                    return (($clean -split '(..)' | Where-Object { $_ }) -join ':').ToUpper()
                }
            }
            return $null
        }

        # Try SendARP first
        try {
            $destIP = Convert-IPToInt -ipAddress $ipAddr
            $macAddr = New-Object byte[] 6
            $macAddrLen = 6
            $result = [ArpHelper]::SendARP($destIP, 0, $macAddr, [ref]$macAddrLen)
            if ($result -eq 0) {
                $mac = Format-MacAddress -macBytes $macAddr[0..5]
                if ($mac -and $mac -ne '00:00:00:00:00:00') {
                    return $mac
                }
            }
        } catch {}

        # Populate ARP cache
        try {
            Test-Connection -ComputerName $ipAddr -Count 1 -Quiet | Out-Null
            Start-Sleep -Milliseconds 100
        } catch {}

        # Try arp -a
        try {
            $arpResult = arp -a $ipAddr 2>$null
            if ($arpResult) {
                $match = [regex]::Match($arpResult, '([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}')
                if ($match.Success) {
                    return ($match.Value -replace '-', ':').ToUpper()
                }
            }
        } catch {}

        # Try Get-NetNeighbor as last resort
        try {
            $neighbor = Get-NetNeighbor -IPAddress $ipAddr -ErrorAction SilentlyContinue | 
                       Where-Object State -in 'Reachable','Permanent','Stale'
            if ($neighbor -and $neighbor.LinkLayerAddress) {
                return $neighbor.LinkLayerAddress.ToUpper()
            }
        } catch {}

        return "N/A"
    }).AddArgument($ip)

    $handle = $ps.BeginInvoke()
    if (-not $script:macTasks) { $script:macTasks = @() }
    $script:macTasks += [pscustomobject]@{ PS = $ps; Handle = $handle; Item = $item; IP = $ip }
}

function Get-MacVendor {
    param($mac)

    # Normalize: strip separators, uppercase, take first 6 chars
    $prefix = ($mac -replace '[:-]', '').Substring(0,6).ToUpper()

    switch ($prefix) {
        "000C29" { "VMware, Inc." }
        "001C23" { "Apple, Inc." }
        "F4F5E8" { "Ubiquiti Networks" }
        "D8CB8A" { "TP-Link Technologies" }
        "001A2B" { "Cisco Systems" }
        "3C5A37" { "Google LLC" }
        "B827EB" { "Raspberry Pi Foundation" }
        "FCFBFB" { "Amazon Technologies Inc." }
        default   { "Unknown Vendor" }
    }
}

function Extract-HtmlTitle {
    param($ip,$port,$isTls)
    $proto = if ($isTls) { "https" } else { "http" }
    $urlbase = "${proto}://${ip}:$port/"
    try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent","Mozilla/5.0 (compatible)")
        $html = $wc.DownloadString($urlbase)
        if ($html) {
            $m = [regex]::Match($html,"<title[^>]*>(.*?)</title>", "IgnoreCase")
            if ($m.Success) {
                $t = $m.Groups[1].Value.Trim()
                if (![string]::IsNullOrWhiteSpace($t)) { return $t }
            }
        }
    } catch {}
    return $null
}


function Queue-HostnameResolve {
    param(
        [string]$ip,
        [System.Windows.Forms.ListViewItem]$item
    )

    $ps = [powershell]::Create()
    $ps.RunspacePool = $script:rsPool

    $null = $ps.AddScript({
        param($ipAddr)

        try {
            # 1) Resolve-DnsName (if available)
            try {
                if (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue) {
                    $r = Resolve-DnsName -Name $ipAddr -ErrorAction SilentlyContinue
                    if ($r) {
                        $nh = ($r | Where-Object { $_.NameHost } | Select-Object -First 1).NameHost
                        if ($nh) { return $nh }
                    }
                }
            } catch {}

            # 2) Fallback to GetHostEntry
            try {
                $entry = [System.Net.Dns]::GetHostEntry($ipAddr)
                if ($entry -and $entry.HostName) { return $entry.HostName }
            } catch {}

            # 3) NetBIOS via nbtstat
            try {
                $nbtRaw = nbtstat -A $ipAddr 2>$null
                if ($nbtRaw) {
                    $lines = $nbtRaw -split "`r?`n"
                    foreach ($ln in $lines) {
                        if ($ln -match '^\s*([^\s]+)\s+<00>\s+UNIQUE') { return $matches[1].Trim() }
                    }
                    foreach ($ln in $lines) {
                        if ($ln -match '^\s*([^\s]+)\s+<') { return $matches[1].Trim() }
                    }
                }
            } catch {}

            # 4) MAC / Vendor lookup (best-effort)
            try {
                $mac = $null
                try { $nb = Get-NetNeighbor -IPAddress $ipAddr -ErrorAction SilentlyContinue; if ($nb) { $mac = $nb.LinkLayerAddress } } catch {}
                if (-not $mac) {
                    try {
                        $a = arp -a | Select-String $ipAddr
                        if ($a) {
                            $parts = ($a -replace '\s{2,}',' ' -split ' ')
                            $mac = $parts[-1]
                        }
                    } catch {}
                }
                if ($mac) {
                    try {
                        $vendor = Invoke-RestMethod -Uri ("https://api.macvendors.com/" + ($mac -replace '[:\-]','')) -Method Get -TimeoutSec 2 -ErrorAction SilentlyContinue
                        if ($vendor) { return $vendor }
                    } catch {}
                }
            } catch {}

        } catch {}
        return "N/A"
    }).AddArgument($ip)

    $handle = $ps.BeginInvoke()

    if (-not $script:resolveTasks) { $script:resolveTasks = @() }
    $script:resolveTasks += [pscustomobject]@{ PS = $ps; Handle = $handle; Item = $item; IP = $ip }
}

function Queue-WebCheck {
    param(
        [string]$ip,
        [System.Windows.Forms.ListViewItem]$item
    )
    $ps = [powershell]::Create()
    $ps.RunspacePool = $script:rsPool
    $null = $ps.AddScript({
        param($ipAddr)
        $probe = $null
        $ports = @(80,8080,8000,8008,443,8443,8444,8888)
        foreach ($p in $ports) {
            $isTls = $p -in 443,8443,8444
            $proto = if ($isTls) { "https" } else { "http" }
            $url = "${proto}://${ipAddr}:$p/"
            try {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            } catch {}
            try {
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add("User-Agent","Mozilla/5.0 (compatible)")
                $wc.Proxy = $null
                $wc.Encoding = [System.Text.Encoding]::UTF8
                $html = $null
                try { $html = $wc.DownloadString($url) } catch {}
                if ($html -ne $null) {
                    $probe = @{Proto=$proto.ToUpper(); Port=$p; Server=$wc.ResponseHeaders["Server"]}
                    $m = [regex]::Match($html,"<title[^>]*>(.*?)</title>", "IgnoreCase")
                    if ($m.Success) { $probe.Title = $m.Groups[1].Value.Trim() }
                    break
                }
            } catch {}
        }
        return $probe
    }).AddArgument($ip)
    $handle = $ps.BeginInvoke()
    if (-not $script:webTasks) { $script:webTasks = @() }
    $script:webTasks += [pscustomobject]@{ PS = $ps; Handle = $handle; Item = $item; IP = $ip }
}

function Get-LocalAdapterInfo {
    param($subnet)
    $localInfo = @()
    
    $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
    foreach ($adapter in $adapters) {
        $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4
        foreach ($ip in $ipConfig) {
            if ($ip.IPAddress -match "^$subnet\.") {
                $localInfo += @{
                    IP = $ip.IPAddress
                    MAC = ($adapter.MacAddress -replace '-', ':')
                    Description = $adapter.InterfaceDescription
                }
            }
        }
    }
    return $localInfo
}

$button.Add_Click({
    $listview.Items.Clear()
    $progress.Value = 0
    $subnet = $textbox.Text.Trim()
    if ($subnet -eq "") { [System.Windows.Forms.MessageBox]::Show("Please enter a subnet."); return }

    # Clean up previous runspace pool
    if ($script:rsPool) { try { $script:rsPool.Close(); $script:rsPool.Dispose() } catch {} ; $script:rsPool = $null }

    # Initialize arrays safely
    $script:jobs = @()
    $script:resolveTasks = @()
    $script:webTasks = @()
    $script:completed = 0
    $script:cancel = $false

    $script:rsPool = [runspacefactory]::CreateRunspacePool(2, 18)
    $script:rsPool.Open()

    # Add local adapter detection first
    $localDevices = Get-LocalAdapterInfo -subnet $subnet
    foreach ($device in $localDevices) {
        $item = New-Object System.Windows.Forms.ListViewItem($device.IP)
        $item.SubItems.Add("Alive") | Out-Null
        $item.SubItems.Add("Local") | Out-Null
        $item.SubItems.Add("Resolving...") | Out-Null     # Keep hostname resolution
        $item.SubItems.Add($device.MAC) | Out-Null        # Set MAC directly
        $item.SubItems.Add("Local Interface") | Out-Null  # Set interface info
        $item.ForeColor = 'DarkGreen'
        $listview.Items.Add($item) | Out-Null

        # Queue hostname resolution but skip MAC and web checks
        Queue-HostnameResolve -ip $device.IP -item $item
    }

    # Create a list of IPs to exclude (local devices)
    $excludeIPs = $localDevices | ForEach-Object { $_.IP }

    ForEach ($i in 1..254) {
        if ($script:cancel) { break }
        $ip = "$subnet.$i"
        
        # Skip if IP is in exclude list
        if ($excludeIPs -contains $ip) { continue }

        $job = [powershell]::Create().AddScript({
            param($ip)
            $alive = $false
            $method = "None"
            try { if (arp -a | Select-String ("$ip\s")) { $alive=$true; $method="ARP" } } catch {}
            if (-not $alive) {
                try { if (Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1) { $alive=$true; $method="Ping" } } catch {}
            }
            foreach ($p in 22,3389,80,443,8080,8000) {
                if (-not $alive) {
                    if (Test-Port $ip $p) {
                        $alive = $true
                        if ($method -eq "None") { $method = "TCP:$p" }
                    }
                }
            }
            return @{IP=$ip; Alive=$alive; Method=$method}
        }).AddArgument($ip)
        $handle = $job.BeginInvoke()

        # Ensure $script:jobs is an array before adding
        if (-not $script:jobs) { $script:jobs = @() }
        $script:jobs += [pscustomobject]@{ Handle = $handle; Job = $job }
    }

    if (-not $script:timer) {
        $script:timer = New-Object System.Windows.Forms.Timer
        $script:timer.Interval = 150
    }

    $script:timer.add_Tick({
        # Process discovery jobs
        foreach ($j in @($script:jobs)) {
            if ($j.Handle.IsCompleted) {
                $result = $j.Job.EndInvoke($j.Handle)
                $script:jobs = $script:jobs | Where-Object { $_ -ne $j }
                $script:completed++
                if ($script:completed -le $progress.Maximum) { $progress.Value = $script:completed }

                if ($result.Alive) {
                    $item = New-Object System.Windows.Forms.ListViewItem($result.IP)
                    $item.SubItems.Add("Alive") | Out-Null            # Status (index 1)
                    $item.SubItems.Add($result.Method) | Out-Null     # Method (index 2)
                    $item.SubItems.Add("Resolving...") | Out-Null     # Hostname (index 3)
                    $item.SubItems.Add("Resolving MAC...") | Out-Null # MAC Address placeholder (index 4)
                    $item.SubItems.Add("Scanning...") | Out-Null      # Web Interface placeholder (index 5)

                    $item.ForeColor = 'Green'
                    $listview.Items.Add($item) | Out-Null

                    Queue-HostnameResolve -ip $result.IP -item $item

                    # Ensure $script:webTasks is initialized before adding
                    if (-not $script:webTasks) { $script:webTasks = @() }
                    Queue-WebCheck -ip $result.IP -item $item

                    Queue-MacResolve -ip $result.IP -item $item
                }
                $j.Job.Dispose()
            }
        }

                # Process hostname tasks
        foreach ($t in @($script:resolveTasks)) {
            if ($t.Handle.IsCompleted) {
                try {
                    $res = $t.PS.EndInvoke($t.Handle)
                    $hostname = ($res | Select-Object -First 1)
                    if ($null -ne $hostname) { $hostname = [string]$hostname } else { $hostname = "N/A" }
                } catch {
                    $hostname = "N/A"
                }
                try { $t.PS.Dispose() } catch {}
                $t.Item.SubItems[3].Text = if (![string]::IsNullOrWhiteSpace($hostname)) { $hostname } else { "N/A" }
                $script:resolveTasks = $script:resolveTasks | Where-Object { $_ -ne $t }
            }
        }

        foreach ($m in @($script:macTasks)) {
            if ($m.Handle.IsCompleted) {
                $mac = $null
                try { $mac = $m.PS.EndInvoke($m.Handle) } catch {}
                try { $m.PS.Dispose() } catch {}

                # Only set "N/A" if $mac is explicitly $null or empty
                if ($mac -eq $null -or [string]::IsNullOrWhiteSpace($mac)) {
                    $mac = "N/A"
                }

                # Update UI (MAC should be subitem index 4)
                $m.Item.SubItems[4].Text = $mac

                # Remove task
                $script:macTasks = $script:macTasks | Where-Object { $_ -ne $m }
            }
        }

        foreach ($t in @($script:webTasks)) {
            if ($t.Handle.IsCompleted) {
                try { $probe = $t.PS.EndInvoke($t.Handle) } catch { $probe = $null }
                try { $t.PS.Dispose() } catch {}

                if ($probe -ne $null) {
                    $display = "{0} ({1})" -f $probe.Proto,$probe.Port
                    if ($probe.Title) { $display += " - $($probe.Title)" }
                    elseif ($probe.Server) { $display += " - $($probe.Server)" }
                    # Web interface should be subitem index 5
                    $t.Item.SubItems[5].Text = $display
                    $t.Item.ForeColor = 'Blue'
                } else {
                    # Only set "No" if the task finished AND returned nothing
                    $t.Item.SubItems[5].Text = "No"
                }

                # Remove completed task
                $script:webTasks = $script:webTasks | Where-Object { $_ -ne $t }
            }
        }

        if ($script:cancel -or ($script:jobs.Count -eq 0 -and $script:resolveTasks.Count -eq 0 -and $script:webTasks.Count -eq 0)) {
            if ($script:timer) { $script:timer.Stop() }
            foreach ($j in @($script:jobs)) { try { $j.Job.Dispose() } catch {} }
            foreach ($t in @($script:resolveTasks)) { try { $t.PS.Dispose() } catch {} }
            foreach ($t in @($script:webTasks)) { try { $t.PS.Dispose() } catch {} }
            $script:jobs = @()
            $script:resolveTasks = @()
            $script:webTasks = @()
            if ($script:rsPool) { try { $script:rsPool.Close(); $script:rsPool.Dispose() } catch {}; $script:rsPool = $null }
        }
    })

    $script:timer.Start()
})


$cancelButton.Add_Click({ $script:cancel = $true })

$saveButton.Add_Click({
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "Text File|*.txt"
    $saveDialog.FileName = "AliveHosts.txt"
    if ($saveDialog.ShowDialog() -eq "OK") {
        $listview.Items | ForEach-Object {
            # Include Web Interface (subitem 5) in the saved output
            "$($_.SubItems[0].Text) - $($_.SubItems[1].Text) - $($_.SubItems[2].Text) - $($_.SubItems[3].Text) - $($_.SubItems[4].Text) - $($_.SubItems[5].Text)"
        } | Out-File $saveDialog.FileName -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Saved to $($saveDialog.FileName)")
    }
})

$listview.Add_DoubleClick({
    if ($listview.SelectedItems.Count -eq 0) { return }
    $item = $listview.SelectedItems[0]
    # Web interface is in subitem index 5
    $web = $item.SubItems[5].Text
    $ip = $item.SubItems[0].Text.Trim()

    if ($web -and $web -ne "No" -and $web -ne "Scanning...") {
        # Extract protocol and port (format: PROTO (PORT) - case-insensitive match)
        if ($web -match "^(http|https)\s*\(\s*(\d+)\s*\)") {
            $proto = $matches[1].ToLower()
            $port = $matches[2].Trim()
            $url = "${proto}://${ip}:${port}/"
            try {
                Start-Process $url
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to open $url")
            }
        } else {
            # Fallback: open http://IP/
            try { Start-Process "http://$ip/" } catch {}
        }
    }
})

[void]$form.ShowDialog()

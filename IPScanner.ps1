Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "Alerion's Subnet Scanner"
$form.Size = New-Object System.Drawing.Size(1100,625)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = 'FixedSingle'    # or 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false

$ipGroup = New-Object System.Windows.Forms.GroupBox
$ipGroup.Text = "IP Scanner"
$ipGroup.Location = New-Object System.Drawing.Point(10,180)
$ipGroup.Size = New-Object System.Drawing.Size(1065,390)
$form.Controls.Add($ipGroup)

$label = New-Object System.Windows.Forms.Label
$label.Text = "Enter Subnet (Max 3 octets)"
$label.AutoSize = $true
$label.Location = New-Object System.Drawing.Point(10,20)
$ipGroup.Controls.Add($label)

$textbox = New-Object System.Windows.Forms.TextBox
$textbox.Location = New-Object System.Drawing.Point(10,45)
$textbox.Width = 200
$textbox.Text = "192.168.1"
$ipGroup.Controls.Add($textbox)

$button = New-Object System.Windows.Forms.Button
$button.Text = "Start Scan"
$button.width = 90
$button.Location = New-Object System.Drawing.Point(220,42)
$ipGroup.Controls.Add($button)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = "Cancel Scan"
$cancelButton.width = 90
$cancelButton.Location = New-Object System.Drawing.Point(320,42)
$ipGroup.Controls.Add($cancelButton)

$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Location = New-Object System.Drawing.Point(10,80)
$progress.Size = New-Object System.Drawing.Size(1045,25)
$progress.Minimum = 0
$progress.Maximum = 254
$ipGroup.Controls.Add($progress)

$listview = New-Object System.Windows.Forms.ListView
$listview.Location = New-Object System.Drawing.Point(10,120)
$listview.Size = New-Object System.Drawing.Size(1045,260)
$listview.View = 'Details'
$listview.FullRowSelect = $false
$listview.GridLines = $true
$listview.Columns.Add("IP Address",120) | Out-Null
$listview.Columns.Add("Status",80) | Out-Null
$listview.Columns.Add("Method",120) | Out-Null
$listview.Columns.Add("Hostname",160) | Out-Null
$listview.Columns.Add("MAC Address", 220) | Out-Null
$listview.Columns.Add("Web Interface",280) | Out-Null
$ipGroup.Controls.Add($listview)

$listview.Add_Click({
    param($sender, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
        $hit = $listview.HitTest($e.Location)
        if ($hit.Item -and $hit.SubItem) { 
            $listview.SelectedItems.Clear()
            
            $hit.Item.Selected = $true
            
            $clickedText = $hit.SubItem.Text
            if (![string]::IsNullOrWhiteSpace($clickedText) -and 
                $clickedText -ne "N/A" -and 
                $clickedText -ne "Resolving..." -and 
                $clickedText -ne "Scanning...") {
                
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
$saveButton.width = 90
$saveButton.Location = New-Object System.Drawing.Point(420,42)
$ipGroup.Controls.Add($saveButton)

$adapterGroup = New-Object System.Windows.Forms.GroupBox
$adapterGroup.Text = "Network Adapters"
$adapterGroup.Location = New-Object System.Drawing.Point(10,10)
$adapterGroup.Size = New-Object System.Drawing.Size(1065,160)
$form.Controls.Add($adapterGroup)

$adapterList = New-Object System.Windows.Forms.ListView
$adapterList.Location = New-Object System.Drawing.Point(10,65)
$adapterList.Size = New-Object System.Drawing.Size(1045,80)
$adapterList.View = 'Details'
$adapterList.FullRowSelect = $true
$adapterList.GridLines = $true
$adapterList.Columns.Add("Adapter",160) | Out-Null
$adapterList.Columns.Add("IPv4",110) | Out-Null
$adapterList.Columns.Add("Subnet",70) | Out-Null
$adapterList.Columns.Add("Status",80) | Out-Null
$adapterGroup.Controls.Add($adapterList)

$refreshAdapters = New-Object System.Windows.Forms.Button
$refreshAdapters.Text = "Refresh"
$refreshAdapters.Location = New-Object System.Drawing.Point(10,35)
$refreshAdapters.Size = New-Object System.Drawing.Size(90,25)
$adapterGroup.Controls.Add($refreshAdapters)

$useAdapterBtn = New-Object System.Windows.Forms.Button
$useAdapterBtn.Text = "Use Selected"
$useAdapterBtn.Location = New-Object System.Drawing.Point(110,35)
$useAdapterBtn.Size = New-Object System.Drawing.Size(100,25)
$adapterGroup.Controls.Add($useAdapterBtn)

$infoLabel = New-Object System.Windows.Forms.Label
$infoLabel.Text = "Double-click an adapter or press 'Use Selected' to populate the subnet box."
$infoLabel.AutoSize = $true
$infoLabel.Location = New-Object System.Drawing.Point(10,15)
$adapterGroup.Controls.Add($infoLabel)

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

    try {
        Test-Connection -ComputerName $ip -Count 2 -Quiet -TimeoutSeconds 1 | Out-Null
    } catch {}

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($ip, 445, $null, $null)
        $iar.AsyncWaitHandle.WaitOne(200)
        $client.Close()
    } catch {}

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

    try {
        $nh = netsh interface ip show neighbors |
              Where-Object { $_ -match "\s+$ip\s+" }
        if ($nh) {
            $p = ($nh -split '\s+')[2]
            $fmt = Format-Mac $p
            if ($fmt) { return $fmt }
        }
    } catch {}

    return "N/A"
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
                $clean = $macBytes -replace '[^0-9A-Fa-f]', ''
                if ($clean.Length -eq 12) {
                    return (($clean -split '(..)' | Where-Object { $_ }) -join ':').ToUpper()
                }
            }
            return $null
        }

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

        try {
            Test-Connection -ComputerName $ipAddr -Count 1 -Quiet | Out-Null
            Start-Sleep -Milliseconds 100
        } catch {}

        try {
            $arpResult = arp -a $ipAddr 2>$null
            if ($arpResult) {
                $match = [regex]::Match($arpResult, '([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}')
                if ($match.Success) {
                    return ($match.Value -replace '-', ':').ToUpper()
                }
            }
        } catch {}

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
            # Regex to clean up .local or .home
            $cleanupSuffix = { param($name) 
                if ($null -ne $name) { 
                    return ($name -replace '\.(local|.home)$','') 
                } 
                return $name 
            }

            # --- Prefer DNS / mDNS ---
            try {
                if (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue) {
                    $r = Resolve-DnsName -Name $ipAddr -ErrorAction SilentlyContinue
                    if ($r) {
                        $nh = ($r | Where-Object { $_.NameHost } | Select-Object -First 1).NameHost
                        if ($nh) {
                            return & $cleanupSuffix $nh
                        }
                    }
                }
            } catch {}

            # --- .NET DNS ---
            try {
                $entry = [System.Net.Dns]::GetHostEntry($ipAddr)
                if ($entry -and $entry.HostName) {
                    $h = & $cleanupSuffix $entry.HostName
                    # Avoid "localhost" false positives
                    if ($h -ne 'localhost' -and $h -ne 'localhost.localdomain') {
                        return $h
                    }
                }
            } catch {}

            # --- NetBIOS (nbtstat) ---
            try {
                $nbtRaw = nbtstat -A $ipAddr 2>$null
                if ($nbtRaw) {
                    $lines = $nbtRaw -split "`r?`n"
                    foreach ($ln in $lines) {
                        if ($ln -match '^\s*([^\s]+)\s+<00>\s+UNIQUE') {
                            return $matches[1].Trim()
                        }
                    }
                    foreach ($ln in $lines) {
                        if ($ln -match '^\s*([^\s]+)\s+<') {
                            return $matches[1].Trim()
                        }
                    }
                }
            } catch {}

            # --- MAC / Vendor lookup ---
            try {
                $mac = $null
                try {
                    $nb = Get-NetNeighbor -IPAddress $ipAddr -ErrorAction SilentlyContinue
                    if ($nb) { $mac = $nb.LinkLayerAddress }
                } catch {}
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

function Cleanup-Scan {
    $script:cancel = $true
    if ($script:timer) {
        try { $script:timer.Stop() } catch {}
        try { $script:timer.Dispose() } catch {}
        $script:timer = $null
    }
    if ($script:jobs) {
        foreach ($j in @($script:jobs)) {
            try { if ($j.Job -and $j.Job.PsBase) { $j.Job.Stop() } } catch {}
            try { if ($j.Job) { $j.Job.Dispose() } } catch {}
        }
        $script:jobs = @()
    }
    foreach ($arrName in @('resolveTasks','webTasks','macTasks')) {
        $taskArray = Get-Variable -Name $arrName -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $taskArray -and $taskArray.Count -gt 0) {
            foreach ($t in @($taskArray)) {
                try { if ($t.PS -and $t.PS.PsBase) { $t.PS.Stop() } } catch {}
                try { if ($t.PS) { $t.PS.Dispose() } } catch {}
            }
            Set-Variable -Name $arrName -Scope Script -Value @()
        }
    }
    if ($script:rsPool) {
        try { $script:rsPool.Close() } catch {}
        try { $script:rsPool.Dispose() } catch {}
        $script:rsPool = $null
    }
    $script:completed = 0
    if ($progress) { $progress.Value = 0 }
}

$form.Add_FormClosing({
    Cleanup-Scan
})

$button.Add_Click({
    $listview.Items.Clear()
    $progress.Value = 0
    $subnet = $textbox.Text.Trim()
    if ($subnet -eq "") { [System.Windows.Forms.MessageBox]::Show("Please enter a subnet."); return }

    if ($script:rsPool) { try { $script:rsPool.Close(); $script:rsPool.Dispose() } catch {} ; $script:rsPool = $null }

    $script:jobs = @()
    $script:resolveTasks = @()
    $script:webTasks = @()
    $script:completed = 0
    $script:cancel = $false

    $script:rsPool = [runspacefactory]::CreateRunspacePool(2, 18)
    $script:rsPool.Open()

    $localDevices = Get-LocalAdapterInfo -subnet $subnet
    foreach ($device in $localDevices) {
        $item = New-Object System.Windows.Forms.ListViewItem($device.IP)
        $item.SubItems.Add("Alive") | Out-Null
        $item.SubItems.Add("Local") | Out-Null
        $item.SubItems.Add("Resolving...") | Out-Null
        $item.SubItems.Add($device.MAC) | Out-Null
        $item.SubItems.Add("Local Interface") | Out-Null
        $item.ForeColor = 'DarkGreen'
        $listview.Items.Add($item) | Out-Null

        Queue-HostnameResolve -ip $device.IP -item $item
    }

    $excludeIPs = $localDevices | ForEach-Object { $_.IP }

    ForEach ($i in 1..254) {
        if ($script:cancel) { break }
        $ip = "$subnet.$i"
        
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

        if (-not $script:jobs) { $script:jobs = @() }
        $script:jobs += [pscustomobject]@{ Handle = $handle; Job = $job }
    }

    if (-not $script:timer) {
        $script:timer = New-Object System.Windows.Forms.Timer
        $script:timer.Interval = 150
    }

    $script:timer.add_Tick({
        foreach ($j in @($script:jobs)) {
            if ($j.Handle.IsCompleted) {
                $result = $j.Job.EndInvoke($j.Handle)
                $script:jobs = $script:jobs | Where-Object { $_ -ne $j }
                $script:completed++
                if ($script:completed -le $progress.Maximum) { $progress.Value = $script:completed }

                if ($result.Alive) {
                    $item = New-Object System.Windows.Forms.ListViewItem($result.IP)
                    $item.SubItems.Add("Alive") | Out-Null       
                    $item.SubItems.Add($result.Method) | Out-Null    
                    $item.SubItems.Add("Resolving...") | Out-Null   
                    $item.SubItems.Add("Resolving MAC...") | Out-Null 
                    $item.SubItems.Add("Scanning...") | Out-Null

                    $item.ForeColor = 'Green'
                    $listview.Items.Add($item) | Out-Null

                    Queue-HostnameResolve -ip $result.IP -item $item

                    if (-not $script:webTasks) { $script:webTasks = @() }
                    Queue-WebCheck -ip $result.IP -item $item

                    Queue-MacResolve -ip $result.IP -item $item
                }
                $j.Job.Dispose()
            }
        }

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

                if ($mac -eq $null -or [string]::IsNullOrWhiteSpace($mac)) {
                    $mac = "N/A"
                }

                $m.Item.SubItems[4].Text = $mac

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
                    $t.Item.SubItems[5].Text = $display
                    $t.Item.ForeColor = 'Blue'
                } else {
                    $t.Item.SubItems[5].Text = "No"
                }

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


$cancelButton.Add_Click({
    Cleanup-Scan
})

$saveButton.Add_Click({
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "Text File|*.txt"
    $saveDialog.FileName = "AliveHosts.txt"
    if ($saveDialog.ShowDialog() -eq "OK") {
        $listview.Items | ForEach-Object {
            "$($_.SubItems[0].Text) - $($_.SubItems[1].Text) - $($_.SubItems[2].Text) - $($_.SubItems[3].Text) - $($_.SubItems[4].Text) - $($_.SubItems[5].Text)"
        } | Out-File $saveDialog.FileName -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Saved to $($saveDialog.FileName)")
    }
})

function Populate-AdapterList {
    $adapterList.Items.Clear()
    try {
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Sort-Object -Property InterfaceDescription
    } catch { $adapters = @() }

    foreach ($a in $adapters) {
        $ips = @()
        try {
            $ipcfg = Get-NetIPAddress -InterfaceIndex $a.IfIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                     Where-Object { $_.IPAddress -and $_.PrefixLength }
            foreach ($ip in $ipcfg) {
                $ips += $ip
            }
        } catch {}

        if ($ips.Count -eq 0) {
            $item = New-Object System.Windows.Forms.ListViewItem($a.InterfaceAlias)
            $item.SubItems.Add("n/a") | Out-Null
            $item.SubItems.Add("-") | Out-Null
            $st = if ($a.Status -eq 'Up') { 'Up (No IP)' } else { 'Down' }
            $item.SubItems.Add($st) | Out-Null
            $item.Tag = @{IfIndex=$a.IfIndex; IP=$null; Prefix=$null}
            $adapterList.Items.Add($item) | Out-Null
        } else {
            foreach ($ipobj in $ips) {
                $prefix = $null
                try {
                    $ipParts = $ipobj.IPAddress -split '\.'
                    $base = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2])"
                    $prefix = $base
                } catch { $prefix = "n/a" }

                $item = New-Object System.Windows.Forms.ListViewItem($a.InterfaceAlias)
                $item.SubItems.Add($ipobj.IPAddress) | Out-Null
                $item.SubItems.Add($prefix) | Out-Null
                $st = if ($a.Status -eq 'Up') { 'Connected' } else { 'Disconnected' }
                $item.SubItems.Add($st) | Out-Null
                $item.Tag = @{IfIndex=$a.IfIndex; IP=$ipobj.IPAddress; Prefix=$prefix}
                $adapterList.Items.Add($item) | Out-Null
            }
        }
    }
}

Populate-AdapterList

$refreshAdapters.Add_Click({ Populate-AdapterList })

$adapterList.Add_DoubleClick({
    if ($adapterList.SelectedItems.Count -eq 0) { return }
    $it = $adapterList.SelectedItems[0]
    if ($it.Tag -and $it.Tag.Prefix) {
        $textbox.Text = $it.Tag.Prefix
    } else {
        [System.Windows.Forms.MessageBox]::Show("Selected adapter has no IPv4 address to infer a subnet.")
    }
})

$useAdapterBtn.Add_Click({
    if ($adapterList.SelectedItems.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("Please select an adapter first."); return }
    $it = $adapterList.SelectedItems[0]
    if ($it.Tag -and $it.Tag.Prefix) { $textbox.Text = $it.Tag.Prefix } else { [System.Windows.Forms.MessageBox]::Show("Selected adapter has no IPv4 address to infer a subnet.") }
})


$listview.Add_DoubleClick({
    if ($listview.SelectedItems.Count -eq 0) { return }
    $item = $listview.SelectedItems[0]
    $web = $item.SubItems[5].Text
    $ip = $item.SubItems[0].Text.Trim()

    if ($web -and $web -ne "No" -and $web -ne "Scanning...") {
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
            try { Start-Process "http://$ip/" } catch {}
        }
    }
})

[void]$form.ShowDialog()

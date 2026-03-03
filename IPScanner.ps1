#Requires -Version 5.1
<#
.SYNOPSIS
    Alerion's Subnet Scanner
.DESCRIPTION
    Fast multi-threaded PowerShell subnet scanner with a dark UI.
    Runs fully without administrator rights in standard mode.
    Enable Admin Mode when running elevated for deeper scanning
    (SendARP, Get-NetNeighbor, SMB-seeding, extended port list).
.AUTHOR
    alerion921
.VERSION
    2.0.0
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------------------------------------------------------------------------
# Scan configuration
# ---------------------------------------------------------------------------
$script:ScanConfig = @{
    StandardPorts = @(22, 80, 443, 8080, 8000, 3389)
    AdminPorts    = @(22, 80, 135, 139, 443, 445, 3389, 5985, 8080, 8000)
    WebPorts      = @(80, 8080, 8000, 8008, 443, 8443, 8444, 8888)
    MaxThreads    = 32
    PingTimeoutMs = 1000
    TcpTimeoutMs  = 350
}

$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------------------
# Theme colours
# ---------------------------------------------------------------------------
$clrBack     = [System.Drawing.ColorTranslator]::FromHtml('#1E1E2E')
$clrPanel    = [System.Drawing.ColorTranslator]::FromHtml('#252537')
$clrBtn      = [System.Drawing.ColorTranslator]::FromHtml('#3E6FBF')
$clrBtnText  = [System.Drawing.Color]::White
$clrText     = [System.Drawing.ColorTranslator]::FromHtml('#E0E0E0')
$clrGreen    = [System.Drawing.ColorTranslator]::FromHtml('#4CAF50')
$clrBlue     = [System.Drawing.ColorTranslator]::FromHtml('#64B5F6')
$clrListBack = [System.Drawing.ColorTranslator]::FromHtml('#252537')

function Set-ButtonStyle {
    param($btn)
    $btn.FlatStyle = 'Flat'
    $btn.BackColor = $clrBtn
    $btn.ForeColor = $clrBtnText
    $btn.FlatAppearance.BorderSize = 0
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
}

# ---------------------------------------------------------------------------
# Form
# ---------------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "Alerion's Subnet Scanner"
$form.Size = New-Object System.Drawing.Size(1100, 665)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.BackColor = $clrBack
$form.ForeColor = $clrText

# ---------------------------------------------------------------------------
# Network Adapters group
# ---------------------------------------------------------------------------
$adapterGroup = New-Object System.Windows.Forms.GroupBox
$adapterGroup.Text = "Network Adapters"
$adapterGroup.Location = New-Object System.Drawing.Point(10, 10)
$adapterGroup.Size = New-Object System.Drawing.Size(1065, 160)
$adapterGroup.BackColor = $clrPanel
$adapterGroup.ForeColor = $clrText
$form.Controls.Add($adapterGroup)

$infoLabel = New-Object System.Windows.Forms.Label
$infoLabel.Text = "Double-click an adapter or press 'Use Selected' to populate the subnet box."
$infoLabel.AutoSize = $true
$infoLabel.Location = New-Object System.Drawing.Point(10, 15)
$infoLabel.ForeColor = $clrText
$adapterGroup.Controls.Add($infoLabel)

$refreshAdapters = New-Object System.Windows.Forms.Button
$refreshAdapters.Text = "Refresh"
$refreshAdapters.Location = New-Object System.Drawing.Point(10, 35)
$refreshAdapters.Size = New-Object System.Drawing.Size(90, 25)
Set-ButtonStyle $refreshAdapters
$adapterGroup.Controls.Add($refreshAdapters)

$useAdapterBtn = New-Object System.Windows.Forms.Button
$useAdapterBtn.Text = "Use Selected"
$useAdapterBtn.Location = New-Object System.Drawing.Point(110, 35)
$useAdapterBtn.Size = New-Object System.Drawing.Size(100, 25)
Set-ButtonStyle $useAdapterBtn
$adapterGroup.Controls.Add($useAdapterBtn)

$adapterList = New-Object System.Windows.Forms.ListView
$adapterList.Location = New-Object System.Drawing.Point(10, 65)
$adapterList.Size = New-Object System.Drawing.Size(1045, 80)
$adapterList.View = 'Details'
$adapterList.FullRowSelect = $true
$adapterList.GridLines = $true
$adapterList.BackColor = $clrListBack
$adapterList.ForeColor = $clrText
$adapterList.Columns.Add("Adapter", 160) | Out-Null
$adapterList.Columns.Add("IPv4", 110) | Out-Null
$adapterList.Columns.Add("Subnet", 70) | Out-Null
$adapterList.Columns.Add("Status", 80) | Out-Null
$adapterGroup.Controls.Add($adapterList)

# ---------------------------------------------------------------------------
# IP Scanner group
# ---------------------------------------------------------------------------
$ipGroup = New-Object System.Windows.Forms.GroupBox
$ipGroup.Text = "IP Scanner"
$ipGroup.Location = New-Object System.Drawing.Point(10, 180)
$ipGroup.Size = New-Object System.Drawing.Size(1065, 430)
$ipGroup.BackColor = $clrPanel
$ipGroup.ForeColor = $clrText
$form.Controls.Add($ipGroup)

$label = New-Object System.Windows.Forms.Label
$label.Text = "Enter Subnet (Max 3 octets)"
$label.AutoSize = $true
$label.Location = New-Object System.Drawing.Point(10, 20)
$label.ForeColor = $clrText
$ipGroup.Controls.Add($label)

$textbox = New-Object System.Windows.Forms.TextBox
$textbox.Location = New-Object System.Drawing.Point(10, 45)
$textbox.Width = 200
$textbox.Text = "192.168.1"
$textbox.BackColor = $clrBack
$textbox.ForeColor = $clrText
$ipGroup.Controls.Add($textbox)

$button = New-Object System.Windows.Forms.Button
$button.Text = "Start Scan"
$button.Width = 90
$button.Location = New-Object System.Drawing.Point(220, 42)
Set-ButtonStyle $button
$ipGroup.Controls.Add($button)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = "Cancel Scan"
$cancelButton.Width = 90
$cancelButton.Location = New-Object System.Drawing.Point(320, 42)
Set-ButtonStyle $cancelButton
$ipGroup.Controls.Add($cancelButton)

$saveButton = New-Object System.Windows.Forms.Button
$saveButton.Text = "Save Results"
$saveButton.Width = 90
$saveButton.Location = New-Object System.Drawing.Point(420, 42)
Set-ButtonStyle $saveButton
$ipGroup.Controls.Add($saveButton)

# Admin Mode checkbox - disabled when not elevated
$adminCheck = New-Object System.Windows.Forms.CheckBox
$adminCheck.Text = "Admin Mode"
$adminCheck.AutoSize = $true
$adminCheck.Location = New-Object System.Drawing.Point(530, 46)
$adminCheck.Enabled = $script:IsAdmin
if ($script:IsAdmin) {
    $adminCheck.ForeColor = $clrText
} else {
    $adminCheck.ForeColor = [System.Drawing.Color]::Gray
    $ttAdmin = New-Object System.Windows.Forms.ToolTip
    $ttAdmin.SetToolTip($adminCheck, "Run as Administrator to enable Admin Mode")
}
$ipGroup.Controls.Add($adminCheck)

$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Location = New-Object System.Drawing.Point(10, 80)
$progress.Size = New-Object System.Drawing.Size(1045, 25)
$progress.Minimum = 0
$progress.Maximum = 254
$ipGroup.Controls.Add($progress)

$listview = New-Object System.Windows.Forms.ListView
$listview.Location = New-Object System.Drawing.Point(10, 120)
$listview.Size = New-Object System.Drawing.Size(1045, 300)
$listview.View = 'Details'
$listview.FullRowSelect = $false
$listview.GridLines = $true
$listview.BackColor = $clrListBack
$listview.ForeColor = $clrText
$listview.Columns.Add("IP Address", 120) | Out-Null
$listview.Columns.Add("Status", 80) | Out-Null
$listview.Columns.Add("Method", 120) | Out-Null
$listview.Columns.Add("Hostname", 160) | Out-Null
$listview.Columns.Add("MAC Address", 220) | Out-Null
$listview.Columns.Add("Web Interface", 280) | Out-Null
$ipGroup.Controls.Add($listview)

# Column-click sorting
$script:sortColumn    = -1
$script:sortAscending = $true
$listview.Add_ColumnClick({
    param($sender, $e)
    if ($script:sortColumn -eq $e.Column) {
        $script:sortAscending = -not $script:sortAscending
    } else {
        $script:sortColumn    = $e.Column
        $script:sortAscending = $true
    }
    $col = $e.Column
    $sorted = @($listview.Items) | Sort-Object -Property { $_.SubItems[$col].Text } -Descending:(-not $script:sortAscending)
    $listview.Items.Clear()
    foreach ($si in $sorted) { $listview.Items.Add($si) | Out-Null }
})

# Click a cell to copy its text
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
                    [System.Windows.Forms.Clipboard]::SetText(($clickedText -replace '-', ':').ToUpper())
                } else {
                    [System.Windows.Forms.Clipboard]::SetText($clickedText)
                }
            }
        }
    }
})

# ---------------------------------------------------------------------------
# Status bar
# ---------------------------------------------------------------------------
$statusStrip = New-Object System.Windows.Forms.StatusStrip
$statusStrip.BackColor = $clrPanel
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = "Idle"
$statusLabel.ForeColor = $clrText
$statusStrip.Items.Add($statusLabel) | Out-Null
$form.Controls.Add($statusStrip)

# ---------------------------------------------------------------------------
# Script state
# ---------------------------------------------------------------------------
$script:timer        = $null
$script:jobs         = @()
$script:completed    = 0
$script:cancel       = $false
$script:rsPool       = $null
$script:resolveTasks = @()
$script:webTasks     = @()
$script:macTasks     = @()

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
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

function Get-LocalAdapterInfo {
    param($subnet)
    $localInfo = @()
    try {
        $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
        foreach ($adapter in $adapters) {
            $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4
            foreach ($ip in $ipConfig) {
                if ($ip.IPAddress -match "^$subnet\.") {
                    $localInfo += @{
                        IP          = $ip.IPAddress
                        MAC         = ($adapter.MacAddress -replace '-', ':')
                        Description = $adapter.InterfaceDescription
                    }
                }
            }
        }
    } catch {
        # Fallback: parse ipconfig /all output (works without admin)
        try {
            $ipconfigOutput = ipconfig /all
            $currentAdapter = $null
            $currentMac     = $null
            foreach ($line in $ipconfigOutput) {
                if ($line -match '^\S') { $currentAdapter = $line.Trim(); $currentMac = $null }
                if ($line -match 'Physical Address.*:\s*([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})') {
                    $currentMac = ($matches[1] -replace '-', ':')
                }
                if ($line -match 'IPv4 Address.*:\s*(\d+\.\d+\.\d+\.\d+)') {
                    $detectedIP = $matches[1]
                    if ($detectedIP -match "^$subnet\.") {
                        $localInfo += @{
                            IP          = $detectedIP
                            MAC         = if ($currentMac) { $currentMac } else { 'N/A' }
                            Description = if ($currentAdapter) { $currentAdapter } else { 'Unknown' }
                        }
                    }
                }
            }
        } catch {}
    }
    return $localInfo
}

function Stop-Scan {
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
    foreach ($arrName in @('resolveTasks', 'webTasks', 'macTasks')) {
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
    if ($progress) { try { $progress.Value = 0 } catch {} }
    try { $statusLabel.Text = "Idle" } catch {}
}

# MAC resolution job - standard path uses only ARP cache + netsh.
# Admin path also uses SendARP P/Invoke, SMB port seeding, and Get-NetNeighbor.
function Start-MacResolveJob {
    param(
        [string]$ip,
        [System.Windows.Forms.ListViewItem]$item,
        [bool]$adminMode = $false
    )
    $ps = [powershell]::Create()
    $ps.RunspacePool = $script:rsPool

    $null = $ps.AddScript({
        param($ipAddr, $isAdmin)

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

        # Admin-only: SendARP P/Invoke
        if ($isAdmin) {
            try {
                Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ArpHelper {
    [DllImport("iphlpapi.dll", ExactSpelling=true)]
    public static extern int SendARP(uint destIP, uint srcIP, byte[] macAddr, ref uint macAddrLen);
}
"@ -ErrorAction SilentlyContinue
                $bytes = [System.Net.IPAddress]::Parse($ipAddr).GetAddressBytes()
                [Array]::Reverse($bytes)
                $destIP    = [System.BitConverter]::ToUInt32($bytes, 0)
                $macAddr   = New-Object byte[] 6
                $macLen    = [uint32]6
                $rc        = [ArpHelper]::SendARP($destIP, 0, $macAddr, [ref]$macLen)
                if ($rc -eq 0) {
                    $mac = Format-MacAddress -macBytes $macAddr[0..5]
                    if ($mac -and $mac -ne '00:00:00:00:00:00') { return $mac }
                }
            } catch {}

            # Admin-only: seed ARP table via SMB
            try {
                $client = New-Object System.Net.Sockets.TcpClient
                $iar = $client.BeginConnect($ipAddr, 445, $null, $null)
                $iar.AsyncWaitHandle.WaitOne(200) | Out-Null
                $client.Close()
            } catch {}
        }

        # Standard: read ARP cache via arp -a
        try {
            $arpResult = arp -a $ipAddr 2>$null
            if ($arpResult) {
                $match = [regex]::Match(($arpResult -join ' '), '([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}')
                if ($match.Success) { return ($match.Value -replace '-', ':').ToUpper() }
            }
        } catch {}

        # Admin-only: Get-NetNeighbor
        if ($isAdmin) {
            try {
                $neighbor = Get-NetNeighbor -IPAddress $ipAddr -ErrorAction SilentlyContinue |
                            Where-Object State -in 'Reachable', 'Permanent', 'Stale'
                if ($neighbor -and $neighbor.LinkLayerAddress) {
                    return $neighbor.LinkLayerAddress.ToUpper()
                }
            } catch {}
        }

        # Standard fallback: netsh neighbors
        try {
            $nh = netsh interface ip show neighbors | Where-Object { $_ -match "\s+$ipAddr\s+" }
            if ($nh) {
                $clean = ($nh -split '\s+')[2] -replace '[^0-9A-Fa-f]', ''
                if ($clean.Length -eq 12) {
                    return (($clean -split '(..)' | Where-Object { $_ }) -join ':').ToUpper()
                }
            }
        } catch {}

        return "N/A"
    }).AddArgument($ip).AddArgument($adminMode)

    $handle = $ps.BeginInvoke()
    $script:macTasks += [pscustomobject]@{ PS = $ps; Handle = $handle; Item = $item; IP = $ip }
}

# Hostname resolution job - no admin-requiring cmdlets in standard path.
function Start-HostnameResolveJob {
    param(
        [string]$ip,
        [System.Windows.Forms.ListViewItem]$item
    )
    $ps = [powershell]::Create()
    $ps.RunspacePool = $script:rsPool

    $null = $ps.AddScript({
        param($ipAddr)

        $cleanSuffix = { param($name)
            if ($null -ne $name) { return ($name -replace '\.(local|home)$', '') }
            return $name
        }

        # DNS / mDNS
        try {
            if (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue) {
                $r = Resolve-DnsName -Name $ipAddr -ErrorAction SilentlyContinue
                if ($r) {
                    $nh = ($r | Where-Object { $_.NameHost } | Select-Object -First 1).NameHost
                    if ($nh) { return & $cleanSuffix $nh }
                }
            }
        } catch {}

        # .NET DNS
        try {
            $entry = [System.Net.Dns]::GetHostEntry($ipAddr)
            if ($entry -and $entry.HostName) {
                $h = & $cleanSuffix $entry.HostName
                if ($h -ne 'localhost' -and $h -ne 'localhost.localdomain') { return $h }
            }
        } catch {}

        # NetBIOS via nbtstat (works without admin)
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

        return "N/A"
    }).AddArgument($ip)

    $handle = $ps.BeginInvoke()
    $script:resolveTasks += [pscustomobject]@{ PS = $ps; Handle = $handle; Item = $item; IP = $ip }
}

function Start-WebCheckJob {
    param(
        [string]$ip,
        [System.Windows.Forms.ListViewItem]$item
    )
    $ps = [powershell]::Create()
    $ps.RunspacePool = $script:rsPool
    $webPorts = $script:ScanConfig.WebPorts

    $null = $ps.AddScript({
        param($ipAddr, $ports)
        $probe = $null
        foreach ($p in $ports) {
            $isTls = $p -in 443, 8443, 8444
            $proto = if ($isTls) { "https" } else { "http" }
            $url   = "${proto}://${ipAddr}:$p/"
            try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}
            try {
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add("User-Agent", "Mozilla/5.0 (compatible)")
                $wc.Proxy    = $null
                $wc.Encoding = [System.Text.Encoding]::UTF8
                $html = $null
                try { $html = $wc.DownloadString($url) } catch {}
                if ($null -ne $html) {
                    $probe = @{ Proto = $proto.ToUpper(); Port = $p; Server = $wc.ResponseHeaders["Server"] }
                    $m = [regex]::Match($html, "<title[^>]*>(.*?)</title>", "IgnoreCase")
                    if ($m.Success) { $probe.Title = $m.Groups[1].Value.Trim() }
                    break
                }
            } catch {}
        }
        return $probe
    }).AddArgument($ip).AddArgument($webPorts)

    $handle = $ps.BeginInvoke()
    $script:webTasks += [pscustomobject]@{ PS = $ps; Handle = $handle; Item = $item; IP = $ip }
}

function Update-AdapterList {
    $adapterList.Items.Clear()
    try {
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Sort-Object -Property InterfaceDescription
    } catch { $adapters = @() }

    foreach ($a in $adapters) {
        $ips = @()
        try {
            $ipcfg = Get-NetIPAddress -InterfaceIndex $a.IfIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                     Where-Object { $_.IPAddress -and $_.PrefixLength }
            foreach ($ip in $ipcfg) { $ips += $ip }
        } catch {}

        if ($ips.Count -eq 0) {
            $item = New-Object System.Windows.Forms.ListViewItem($a.InterfaceAlias)
            $item.SubItems.Add("n/a") | Out-Null
            $item.SubItems.Add("-") | Out-Null
            $st = if ($a.Status -eq 'Up') { 'Up (No IP)' } else { 'Down' }
            $item.SubItems.Add($st) | Out-Null
            $item.Tag = @{ IfIndex = $a.IfIndex; IP = $null; Prefix = $null }
            $item.ForeColor = $clrText
            $adapterList.Items.Add($item) | Out-Null
        } else {
            foreach ($ipobj in $ips) {
                $prefix = $null
                try {
                    $ipParts = $ipobj.IPAddress -split '\.'
                    if ($ipParts.Length -ge 3) {
                        $prefix = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2])"
                    } else { $prefix = "n/a" }
                } catch { $prefix = "n/a" }

                $item = New-Object System.Windows.Forms.ListViewItem($a.InterfaceAlias)
                $item.SubItems.Add($ipobj.IPAddress) | Out-Null
                $item.SubItems.Add($prefix) | Out-Null
                $st = if ($a.Status -eq 'Up') { 'Connected' } else { 'Disconnected' }
                $item.SubItems.Add($st) | Out-Null
                $item.Tag = @{ IfIndex = $a.IfIndex; IP = $ipobj.IPAddress; Prefix = $prefix }
                $item.ForeColor = $clrText
                $adapterList.Items.Add($item) | Out-Null
            }
        }
    }
}

Update-AdapterList

$refreshAdapters.Add_Click({ Update-AdapterList })

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
    if ($adapterList.SelectedItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please select an adapter first.")
        return
    }
    $it = $adapterList.SelectedItems[0]
    if ($it.Tag -and $it.Tag.Prefix) {
        $textbox.Text = $it.Tag.Prefix
    } else {
        [System.Windows.Forms.MessageBox]::Show("Selected adapter has no IPv4 address to infer a subnet.")
    }
})

$form.Add_FormClosing({ Stop-Scan })

$cancelButton.Add_Click({ Stop-Scan })

# ---------------------------------------------------------------------------
# Start scan
# ---------------------------------------------------------------------------
$button.Add_Click({
    $listview.Items.Clear()
    $progress.Value = 0
    $subnet = $textbox.Text.Trim()
    if ($subnet -eq "") { [System.Windows.Forms.MessageBox]::Show("Please enter a subnet."); return }

    $isAdminMode  = $adminCheck.Checked
    $tcpPorts     = if ($isAdminMode) { $script:ScanConfig.AdminPorts } else { $script:ScanConfig.StandardPorts }
    $tcpTimeoutMs = $script:ScanConfig.TcpTimeoutMs

    if ($script:rsPool) { try { $script:rsPool.Close(); $script:rsPool.Dispose() } catch {} ; $script:rsPool = $null }

    $script:jobs         = @()
    $script:resolveTasks = @()
    $script:webTasks     = @()
    $script:macTasks     = @()
    $script:completed    = 0
    $script:cancel       = $false

    $script:rsPool = [runspacefactory]::CreateRunspacePool(2, $script:ScanConfig.MaxThreads)
    $script:rsPool.Open()

    $localDevices = Get-LocalAdapterInfo -subnet $subnet
    foreach ($device in $localDevices) {
        $item = New-Object System.Windows.Forms.ListViewItem($device.IP)
        $item.SubItems.Add("Alive") | Out-Null
        $item.SubItems.Add("Local") | Out-Null
        $item.SubItems.Add("Resolving...") | Out-Null
        $item.SubItems.Add($device.MAC) | Out-Null
        $item.SubItems.Add("Local Interface") | Out-Null
        $item.ForeColor = $clrGreen
        $listview.Items.Add($item) | Out-Null
        Start-HostnameResolveJob -ip $device.IP -item $item
    }

    $excludeIPs = $localDevices | ForEach-Object { $_.IP }

    $statusLabel.Text = "Scanning... (0/254)"

    ForEach ($i in 1..254) {
        if ($script:cancel) { break }
        $ip = "$subnet.$i"
        if ($excludeIPs -contains $ip) { continue }

        # Fix: assign runspace pool; inline TCP test (Test-Port is not available inside runspace)
        $job = [powershell]::Create()
        $job.RunspacePool = $script:rsPool
        $null = $job.AddScript({
            param($ipAddr, $ports, $timeoutMs)
            $alive  = $false
            $method = "None"

            # ARP cache check (no admin needed)
            try {
                if (arp -a | Select-String ("$ipAddr\s")) { $alive = $true; $method = "ARP" }
            } catch {}

            # ICMP ping
            if (-not $alive) {
                try {
                    if (Test-Connection -ComputerName $ipAddr -Count 1 -Quiet -TimeoutSeconds 1) {
                        $alive = $true; $method = "Ping"
                    }
                } catch {}
            }

            # TCP port probe (inlined - Test-Port is defined in outer scope, not available here)
            foreach ($p in $ports) {
                if ($alive) { break }
                try {
                    $tcp = New-Object Net.Sockets.TcpClient
                    $iar = $tcp.BeginConnect($ipAddr, $p, $null, $null)
                    $ok  = $iar.AsyncWaitHandle.WaitOne($timeoutMs)
                    try { $iar.AsyncWaitHandle.Dispose() } catch {}
                    if ($ok) {
                        try { $tcp.EndConnect($iar) } catch {}
                        $alive  = $true
                        $method = "TCP:$p"
                    }
                    $tcp.Close()
                } catch {}
            }

            return @{ IP = $ipAddr; Alive = $alive; Method = $method }
        }).AddArgument($ip).AddArgument($tcpPorts).AddArgument($tcpTimeoutMs)

        $handle = $job.BeginInvoke()
        $script:jobs += [pscustomobject]@{ Handle = $handle; Job = $job }
    }

    # Fix: create a fresh timer each scan so Add_Tick is registered exactly once
    if ($script:timer) {
        try { $script:timer.Stop() } catch {}
        try { $script:timer.Dispose() } catch {}
        $script:timer = $null
    }
    $script:timer          = New-Object System.Windows.Forms.Timer
    $script:timer.Interval = 150

    $script:timer.Add_Tick({
        foreach ($j in @($script:jobs)) {
            if ($j.Handle.IsCompleted) {
                $result = $j.Job.EndInvoke($j.Handle) | Select-Object -First 1
                $script:jobs = $script:jobs | Where-Object { $_ -ne $j }
                $script:completed++
                if ($script:completed -le $progress.Maximum) { $progress.Value = $script:completed }
                $statusLabel.Text = "Scanning... ($($script:completed)/254)"

                if ($result.Alive) {
                    $item = New-Object System.Windows.Forms.ListViewItem($result.IP)
                    $item.SubItems.Add("Alive") | Out-Null
                    $item.SubItems.Add($result.Method) | Out-Null
                    $item.SubItems.Add("Resolving...") | Out-Null
                    $item.SubItems.Add("Resolving MAC...") | Out-Null
                    $item.SubItems.Add("Scanning...") | Out-Null
                    $item.ForeColor = $clrGreen
                    $listview.Items.Add($item) | Out-Null

                    Start-HostnameResolveJob -ip $result.IP -item $item
                    Start-WebCheckJob        -ip $result.IP -item $item
                    Start-MacResolveJob      -ip $result.IP -item $item -adminMode $adminCheck.Checked
                }
                $j.Job.Dispose()
            }
        }

        foreach ($t in @($script:resolveTasks)) {
            if ($t.Handle.IsCompleted) {
                try {
                    $res      = $t.PS.EndInvoke($t.Handle)
                    $hostname = ($res | Select-Object -First 1)
                    if ($null -ne $hostname) { $hostname = [string]$hostname } else { $hostname = "N/A" }
                } catch { $hostname = "N/A" }
                try { $t.PS.Dispose() } catch {}
                $t.Item.SubItems[3].Text = if (![string]::IsNullOrWhiteSpace($hostname)) { $hostname } else { "N/A" }
                $script:resolveTasks = $script:resolveTasks | Where-Object { $_ -ne $t }
            }
        }

        foreach ($m in @($script:macTasks)) {
            if ($m.Handle.IsCompleted) {
                $mac = $null
                try { $mac = [string]($m.PS.EndInvoke($m.Handle) | Select-Object -First 1) } catch {}
                try { $m.PS.Dispose() } catch {}
                if ($null -eq $mac -or [string]::IsNullOrWhiteSpace($mac)) { $mac = "N/A" }
                $m.Item.SubItems[4].Text = $mac
                $script:macTasks = $script:macTasks | Where-Object { $_ -ne $m }
            }
        }

        foreach ($t in @($script:webTasks)) {
            if ($t.Handle.IsCompleted) {
                try { $probe = $t.PS.EndInvoke($t.Handle) | Select-Object -First 1 } catch { $probe = $null }
                try { $t.PS.Dispose() } catch {}
                if ($null -ne $probe) {
                    $display = "{0} ({1})" -f $probe.Proto, $probe.Port
                    if ($probe.Title)  { $display += " - $($probe.Title)" }
                    elseif ($probe.Server) { $display += " - $($probe.Server)" }
                    $t.Item.SubItems[5].Text = $display
                    $t.Item.ForeColor = $clrBlue
                } else {
                    $t.Item.SubItems[5].Text = "No"
                }
                $script:webTasks = $script:webTasks | Where-Object { $_ -ne $t }
            }
        }

        $allDone = ($script:jobs.Count -eq 0 -and
                    $script:resolveTasks.Count -eq 0 -and
                    $script:webTasks.Count -eq 0 -and
                    $script:macTasks.Count -eq 0)

        if ($script:cancel -or $allDone) {
            if ($script:timer) { $script:timer.Stop() }
            foreach ($j in @($script:jobs))        { try { $j.Job.Dispose() } catch {} }
            foreach ($t in @($script:resolveTasks)) { try { $t.PS.Dispose() } catch {} }
            foreach ($t in @($script:webTasks))     { try { $t.PS.Dispose() } catch {} }
            foreach ($m in @($script:macTasks))     { try { $m.PS.Dispose() } catch {} }
            $script:jobs         = @()
            $script:resolveTasks = @()
            $script:webTasks     = @()
            $script:macTasks     = @()
            if ($script:rsPool) { try { $script:rsPool.Close(); $script:rsPool.Dispose() } catch {} ; $script:rsPool = $null }

            $hostsFound = ($listview.Items | Where-Object { $_.SubItems[1].Text -eq "Alive" }).Count
            if ($script:cancel) {
                $statusLabel.Text = "Scan cancelled - $hostsFound hosts found"
            } else {
                $statusLabel.Text = "Scan complete - $hostsFound hosts found"
            }
        }
    })

    $script:timer.Start()
})

# ---------------------------------------------------------------------------
# Save / Export (TXT and CSV)
# ---------------------------------------------------------------------------
$saveButton.Add_Click({
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter   = "Text File|*.txt|CSV File|*.csv"
    $saveDialog.FileName = "AliveHosts"
    if ($saveDialog.ShowDialog() -eq "OK") {
        $ext = [System.IO.Path]::GetExtension($saveDialog.FileName).ToLower()
        if ($ext -eq ".csv") {
            $rows = @('"IP Address","Status","Method","Hostname","MAC Address","Web Interface"')
            $listview.Items | ForEach-Object {
                $row  = $_
                $cols = 0..($row.SubItems.Count - 1) | ForEach-Object { '"' + ($row.SubItems[$_].Text -replace '"', '""') + '"' }
                $rows += ($cols -join ",")
            }
            $rows | Out-File $saveDialog.FileName -Encoding UTF8
        } else {
            $listview.Items | ForEach-Object {
                "$($_.SubItems[0].Text) - $($_.SubItems[1].Text) - $($_.SubItems[2].Text) - $($_.SubItems[3].Text) - $($_.SubItems[4].Text) - $($_.SubItems[5].Text)"
            } | Out-File $saveDialog.FileName -Encoding UTF8
        }
        [System.Windows.Forms.MessageBox]::Show("Saved to $($saveDialog.FileName)")
    }
})

# ---------------------------------------------------------------------------
# Double-click a result row to open web interface
# ---------------------------------------------------------------------------
$listview.Add_DoubleClick({
    if ($listview.SelectedItems.Count -eq 0) { return }
    $item = $listview.SelectedItems[0]
    $web  = $item.SubItems[5].Text
    $ip   = $item.SubItems[0].Text.Trim()

    if ($web -and $web -ne "No" -and $web -ne "Scanning...") {
        if ($web -match "^(http|https)\s*\(\s*(\d+)\s*\)") {
            $proto = $matches[1].ToLower()
            $port  = $matches[2].Trim()
            $url   = "${proto}://${ip}:${port}/"
            try { Start-Process $url } catch { [System.Windows.Forms.MessageBox]::Show("Failed to open $url") }
        } else {
            try { Start-Process "http://$ip/" } catch {}
        }
    }
})

[void]$form.ShowDialog()

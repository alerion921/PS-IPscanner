Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "Advanced Subnet Scanner"
$form.Size = New-Object System.Drawing.Size(800,700)
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
$button.Width = 90
$button.Location = New-Object System.Drawing.Point(220,42)
$form.Controls.Add($button)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = "Cancel Scan"
$cancelButton.Width = 90
$cancelButton.Location = New-Object System.Drawing.Point(320,42)
$form.Controls.Add($cancelButton)

$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Location = New-Object System.Drawing.Point(10,80)
$progress.Size = New-Object System.Drawing.Size(760,25)
$progress.Minimum = 0
$progress.Maximum = 254
$form.Controls.Add($progress)

$listview = New-Object System.Windows.Forms.ListView
$listview.Location = New-Object System.Drawing.Point(10,120)
$listview.Size = New-Object System.Drawing.Size(760,420)
$listview.View = 'Details'
$listview.FullRowSelect = $true
$listview.GridLines = $true
$listview.Columns.Add("IP Address",120) | Out-Null
$listview.Columns.Add("Status",80) | Out-Null
$listview.Columns.Add("Method",120) | Out-Null
$listview.Columns.Add("Hostname",160) | Out-Null
$listview.Columns.Add("Web Interface",220) | Out-Null
$form.Controls.Add($listview)

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

function Test-Port {
    param($ip,$port)
    try {
        # Faster/connect-only with a small read attempt to capture simple banners
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($ip,$port,$null,$null)
        $connected = $iar.AsyncWaitHandle.WaitOne(400)
        if (-not $connected) {
            try { $tcp.Close() } catch {}
            return $false
        }
        $tcp.EndConnect($iar) | Out-Null

        # Short timeouts for banner read
        try {
            $sock = $tcp.Client
            $sock.ReceiveTimeout = 600
            $sock.SendTimeout = 600
            $stream = $tcp.GetStream()
            if ($stream.CanRead) {
                $buffer = New-Object byte[] 1024
                $read = 0
                try { $read = $stream.Read($buffer, 0, $buffer.Length) } catch {}
                if ($read -gt 0) {
                    $banner = [System.Text.Encoding]::ASCII.GetString($buffer,0,$read).Trim()
                    # normalize banner for later inspection (not stored here to keep signature)
                    $banner = ($banner -replace "[\r\n]+"," ") -replace "\s{2,}"," "
                    # small heuristic: if banner contains known protocol names, consider it useful (optional)
                }
            }
        } catch {}
        try { $tcp.Close() } catch {}
        return $true
    } catch {
        return $false
    }
}

function Test-WebInterface {
    param($ip)
    # Ports to probe (http & https variants)
    $ports = @(80,8080,8000,8008,443,8443,8444,8888)
    foreach ($p in $ports) {
        $isTls = $p -in 443,8443,8444
        $proto = if ($isTls) { "https" } else { "http" }
        $url = "${proto}://${ip}:$p/"

        # Accept any cert for discovery only
        try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}

        try {
            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Timeout = 3000
            $req.Method = "HEAD"
            $req.AllowAutoRedirect = $true
            $req.UserAgent = "Mozilla/5.0 (compatible)"
            $req.Proxy = $null

            $resp = $null
            try {
                $resp = $req.GetResponse()
            } catch [System.Net.WebException] {
                # capture response even on 401/403/etc
                $resp = $_.Exception.Response
            }

            if ($resp -ne $null) {
                $status = 0
                try { $status = [int]$resp.StatusCode } catch {}
                $serverHeader = $null
                try { $serverHeader = $resp.Headers["Server"] } catch {}
                # close the response when possible
                try { $resp.Close() } catch {}

                # If reachable or requires auth/redirect, gather richer info
                if (($status -ge 100 -and $status -lt 400) -or $status -in 401,403,302) {
                    # Try to obtain TLS cert CN when applicable
                    $certCN = $null
                    if ($isTls) {
                        try {
                            $tcp = New-Object System.Net.Sockets.TcpClient
                            $tcp.ReceiveTimeout = 1000; $tcp.SendTimeout = 1000
                            $tcp.Connect($ip,$p)
                            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, ({ $true }))
                            $ssl.AuthenticateAsClient($ip)
                            $rawCert = $ssl.RemoteCertificate
                            if ($rawCert) {
                                $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $rawCert
                                $certCN = $x.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                            }
                            $ssl.Close(); $tcp.Close()
                        } catch {}
                    }

                    # Try to extract a descriptive title (may be slow; keep short timeout in Extract-HtmlTitle)
                    $title = $null
                    try { $title = Extract-HtmlTitle -ip $ip -port $p -isTls:$isTls } catch {}

                    # Build a descriptive result, prefer title then server header then cert CN
                    $desc = $title
                    if (-not $desc) { $desc = $serverHeader }
                    if (-not $desc) { $desc = $certCN }

                    return @{ Proto = $proto.ToUpper(); Port = $p; Server = $serverHeader; Title = $title; CertCN = $certCN; Desc = $desc }
                }
            }
        } catch {
            # ignore and continue probing other ports
        }
    }
    return $null
}

function Extract-HtmlTitle {
    param($ip,$port,$isTls)
    $proto = if ($isTls) { "https" } else { "http" }
    $urlbase = "${proto}://${ip}:$port/"

    try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}

    try {
        $req = [System.Net.HttpWebRequest]::Create($urlbase)
        $req.Method = "GET"
        $req.Timeout = 4000
        $req.AllowAutoRedirect = $true
        $req.UserAgent = "Mozilla/5.0 (compatible)"
        $req.Proxy = $null

        $resp = $req.GetResponse()
        $stream = $resp.GetResponseStream()
        $encoding = [System.Text.Encoding]::UTF8
        $sr = New-Object System.IO.StreamReader($stream, $encoding)
        $html = $sr.ReadToEnd()
        $sr.Close()
        try { $resp.Close() } catch {}

        if ($html) {
            # 1) <title>
            $m = [regex]::Match($html,"<title[^>]*>(.*?)</title>", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($m.Success) {
                $t = $m.Groups[1].Value.Trim()
                if ($t) { return ([System.Net.WebUtility]::HtmlDecode($t)) }
            }

            # 2) OpenGraph title meta
            $m = [regex]::Match($html,'<meta[^>]+property=["'']og:title["''][^>]*content=["''](.*?)["'']', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($m.Success) {
                $t = $m.Groups[1].Value.Trim()
                if ($t) { return ([System.Net.WebUtility]::HtmlDecode($t)) }
            }

            # 3) meta name="title" or meta name="description"
            $m = [regex]::Match($html,'<meta[^>]+name=["'']title["''][^>]*content=["''](.*?)["'']', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($m.Success) { $t = $m.Groups[1].Value.Trim(); if ($t) { return ([System.Net.WebUtility]::HtmlDecode($t)) } }
            $m = [regex]::Match($html,'<meta[^>]+name=["'']description["''][^>]*content=["''](.*?)["'']', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($m.Success) { $t = $m.Groups[1].Value.Trim(); if ($t) { return ([System.Net.WebUtility]::HtmlDecode($t)) } }

            # 4) first H1 element
            $m = [regex]::Match($html,"<h1[^>]*>(.*?)</h1>", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($m.Success) {
                $t = $m.Groups[1].Value.Trim()
                if ($t) { return ([System.Net.WebUtility]::HtmlDecode($t)) }
            }

            # 5) look for common device signatures (printer, router, camera) in HTML body / title / headers
            $bodySnippet = ($html -replace '\s+', ' ' )
            $sig = $null
            if ($bodySnippet -match '(?i)(printer|hp|epson|canon|xerox|jetdirect|router|gateway|camera|dvr|tplink|netgear|asus)') {
                $sig = $matches[0]
                # return the matched signature to give a hint
                return $sig
            }
        }
    } catch {
        # ignore errors, return $null to indicate no title found
    }

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
        $result = "N/A"

        # --- 1) Standard DNS Reverse Lookup ---
        try {
            $task = [System.Threading.Tasks.Task[string]]::Factory.StartNew({
                try {
                    $entry = [System.Net.Dns]::GetHostEntry($ipAddr)
                    if ($entry -and $entry.HostName) { return $entry.HostName }
                } catch {}
                return $null
            })
            if ($task.Wait(2000) -and $task.Result) { return $task.Result }
        } catch {}

        # --- 2) DNS GetHostAddresses fallback ---
        try {
            $addresses = [System.Net.Dns]::GetHostAddresses($ipAddr)
            foreach ($a in $addresses) {
                try {
                    $e = [System.Net.Dns]::GetHostEntry($a)
                    if ($e -and $e.HostName) { return $e.HostName }
                } catch {}
            }
        } catch {}

        # --- 3) NetBIOS / Windows Name ---
        try {
            $nbt = nbtstat -A $ipAddr 2>$null | Select-String "Name"
            if ($nbt) {
                $candidate = ($nbt -split '\s+')[1]
                if ($candidate -and $candidate -ne "Name") { return $candidate }
            }
        } catch {}

        # --- 4) mDNS (Bonjour / _http._tcp.local) ---
        try {
            $mdns = New-Object System.Net.Sockets.UdpClient
            $mdns.Client.ReceiveTimeout = 500
            $mdns.EnableBroadcast = $true
            $mdns.Connect("224.0.0.251", 5353)

            # Simple query packet for mDNS _services._dns-sd._udp.local (generic discovery)
            $query = [byte[]] @(0,0,0,0,0,1,0,0,0,0,0,0) # Minimal placeholder, real mDNS query is complex
            $mdns.Send($query, $query.Length) | Out-Null
            try { $resp = $mdns.Receive([ref]([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0))) } catch {}
            if ($resp) {
                $result = "mDNS Device"
            }
            $mdns.Close()
        } catch {}

        # --- 5) UPnP / SSDP Discovery ---
        try {
            $ssdp = New-Object System.Net.Sockets.UdpClient
            $ssdp.Client.ReceiveTimeout = 500
            $ssdp.EnableBroadcast = $true
            $ssdp.Connect("239.255.255.250", 1900)
            $msg = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: ""ssdp:discover""`r`nMX: 1`r`nST: ssdp:all`r`n`r`n"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($msg)
            $ssdp.Send($bytes, $bytes.Length) | Out-Null
            try { $resp = $ssdp.Receive([ref]([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0))) } catch {}
            if ($resp) {
                $result = "UPnP Device"
            }
            $ssdp.Close()
        } catch {}

        return $result
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
            $url   = "${proto}://${ipAddr}:$p/"

            try {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            } catch {}

            try {
                $req = [System.Net.HttpWebRequest]::Create($url)
                $req.UserAgent = "Mozilla/5.0 (compatible; WebScanner/1.0)"
                $req.AllowAutoRedirect = $true
                $req.Timeout = 5000
                $req.Proxy = $null

                $resp = $req.GetResponse()
                $sr = New-Object IO.StreamReader($resp.GetResponseStream())
                $html = $sr.ReadToEnd()
                $sr.Close()

                if ($resp -ne $null) {
                    $probe = [ordered]@{
                        Proto  = $proto.ToUpper()
                        Port   = $p
                        Server = $resp.Headers["Server"]
                        PoweredBy = $resp.Headers["X-Powered-By"]
                        WWWAuth   = $resp.Headers["WWW-Authenticate"]
                        Cookies   = $resp.Headers["Set-Cookie"]
                        Title  = $null
                        Meta   = @{}
                        CertCN = $null
                        CertIssuer = $null
                    }

                    # Extract <title>
                    $m = [regex]::Match($html,"<title[^>]*>(.*?)</title>","IgnoreCase")
                    if ($m.Success) { $probe.Title = $m.Groups[1].Value.Trim() }

                    # Extract <meta name="...">
                    $metaRegex = '<meta\s+(?:name|http-equiv)="([^"]+)"\s+content="([^"]+)"'
                    foreach ($match in [regex]::Matches($html, $metaRegex, "IgnoreCase")) {
                        $probe.Meta[$match.Groups[1].Value] = $match.Groups[2].Value
                    }

                    # If HTTPS, pull certificate info
                    if ($isTls) {
                        try {
                            $tcp = New-Object System.Net.Sockets.TcpClient($ipAddr,$p)
                            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(),$false,({$true}))
                            $ssl.AuthenticateAsClient($ipAddr)
                            $cert = $ssl.RemoteCertificate
                            if ($cert) {
                                $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cert
                                $probe.CertCN     = $x509.GetNameInfo("SimpleName",$false)
                                $probe.CertIssuer = $x509.Issuer
                            }
                            $ssl.Dispose()
                            $tcp.Close()
                        } catch {}
                    }

                    break
                }
            } catch {}
        }

        return $probe
    }).AddArgument($ip)

    $handle = $ps.BeginInvoke()
    if (-not $script:webTasks) { $script:webTasks = @() }
    $script:webTasks += [pscustomobject]@{
        PS = $ps
        Handle = $handle
        Item = $item
        IP = $ip
    }
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

    ForEach ($i in 1..254) {
        if ($script:cancel) { break }
        $ip = "$subnet.$i"
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
                    $item.SubItems.Add("Alive") | Out-Null
                    $item.SubItems.Add($result.Method) | Out-Null
                    $item.SubItems.Add("Resolving...") | Out-Null
                    $item.SubItems.Add("Scanning...") | Out-Null
                    $item.ForeColor = 'Green'
                    $listview.Items.Add($item) | Out-Null

                    Queue-HostnameResolve -ip $result.IP -item $item

                    # Ensure $script:webTasks is initialized before adding
                    if (-not $script:webTasks) { $script:webTasks = @() }
                    Queue-WebCheck -ip $result.IP -item $item
                }
                $j.Job.Dispose()
            }
        }

        # Process hostname tasks
        foreach ($t in @($script:resolveTasks)) {
            if ($t.Handle.IsCompleted) {
                try { $hostname = $t.PS.EndInvoke($t.Handle) } catch { $hostname = "N/A" }
                try { $t.PS.Dispose() } catch {}
                $t.Item.SubItems[3].Text = if (![string]::IsNullOrWhiteSpace($hostname)) { $hostname } else { "N/A" }
                $script:resolveTasks = $script:resolveTasks | Where-Object { $_ -ne $t }
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
                    $t.Item.SubItems[4].Text = $display
                    $t.Item.ForeColor = 'Blue'
                } else {
                    # Only set "No" if the task finished AND returned nothing
                    $t.Item.SubItems[4].Text = "No"
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
            "$($_.SubItems[0].Text) - $($_.SubItems[1].Text) - $($_.SubItems[2].Text) - $($_.SubItems[3].Text) - $($_.SubItems[4].Text)"
        } | Out-File $saveDialog.FileName -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Saved to $($saveDialog.FileName)")
    }
})

$listview.Add_DoubleClick({
    if ($listview.SelectedItems.Count -eq 0) { return }
    $item = $listview.SelectedItems[0]
    $web = $item.SubItems[4].Text
    $ip = $item.SubItems[0].Text.Trim()

    if ($web -and $web -ne "No" -and $web -ne "Scanning...") {
        # Extract protocol and port (format: PROTO (PORT) - optional title/server)
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

In order to run this from the web open a powershell terminal as admin and enter this and press accept
```
Set-ExecutionPolicy Unrestricted
```

Then run this is in the same window:
```
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/alerion921/PS-IPscanner/refs/heads/main/IPScanner.ps1'))
```

If you want to run this on a tightly locked down device you can run it by copying all text (RAW) straight from the .ps1 file into Powershell ISE and it will run just fine and allow you to do the scan. 

Does not require admin privileges in order to work.

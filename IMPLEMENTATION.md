## GOAL

Support Harfanflab as a new deployment target for the OpenTide detection-as-code framework

CoreTide is our code backend and you need to extend it. 

You have a very complex task ahead of you, I expect you to 

- carefully plan ahead
- study the repository to understand code structure, patterns, oddities, technical choices
- Keep going until you finished, or hit a limit
- Perform all actions required
- Keep code additions consistent and don't overspread beyond your brief.
- Read carefully what's next, plan your work accordingly
- There is too much data in the HARFANG LAB DATA section below. Feel free to take an entire pass to study the schema generation, and generate additional files along the way. However, keep them in some kind of temporary folder easy to remove later, and only if it helps your generation
- Ensure all files pass validation
- Don't pursue meaningless technical black hole, focus on the end goal ahead of you

### Target schema

```yaml
configurations:
  harfanglab:
    #name
    #description : |
      #
    #references:
      #-
    #level : Informational, Low, Medium, High, Critical
    maturity: Stable, Testing, Experimental
    confidence: Weak, Moderate, Strong
    action: Alert, Alert & Block, Alert, Block & Quarantine    
    #tags:
      #-

    sigma:
      #status: 
      action: Alert, Alert & Block, Alert, Block & Quarantine
      confidence: 
      #tags:
        #- 
      logsource:
        category: <value list>
        product: <value list>
      
      selections:
         
        - name: FileDetection
          field: OriginalFileName
          modifiers:
            - contains
            - all 
          value:
            - string1
            - string2
        
        - name: Exclusions
          field: OriginalFileName
          modifiers:
            - contains
          value:
            - string3
            - string4
        
      condition: FileDetection and not Exclusions
        
      #false_positives:
        #-

    yara:
      meta:
        #context: process, thread, memory
        #os: Windows, MacOS
      
      strings: |
        Raw YARA Support
      
      condition: |
        Raw YARA Support
```

This allows us to statically define a JSON schema while preserving the full expression of Sigma, avoiding expressions in default sigma like fieldname|base64offset|contains. However, we must then transform our format into a Sigma YAML compliant format before deploying to the API.

#### Additional constraints

We must ensure that depending on the logsource/category, we expose the correct fields, and have full documentation in the JSON Schema. You are provided a comprehensive source of documentation below.

A user can either write a YARA OR a Sigma rule. Not both. So we must validate this correctly with the schema, 

### Components to implement

- CoreTide/Framework/Sub Schemas/HarfangLab.metaschema.yaml - our YAML schema expression, that can be transpiled to JSON Schema
- CoreTide/Configurations/systems/harfanglab.toml - contains all our technical config to setup the integration. Check other files for getting a sense of it
- CoreTide/Framework/Configurations/Harfanglab.metaschema.yaml - JSON Schema for the TOML file
- CoreTide/Engines/modules/tide - bunch of boilerplate to hook all the datamodels together. Study hard this one and be very attentive.
- CoreTide/Engines/modules/models - required dataclasses to model the entire schema. Be also very attentive to see what's expected of you. Schema and dataclass need to remain aligned to enable correct loading of values, especially for optional/required values.
- CoreTide/Engines/deployment/harfanglab.py - main deployer function. Read sentinel_one, crowdstrike, defender_for_endpoint etc. to get a sense of the structure
- CoreTide/Engines/modules/systems/harfanglab.py - backend library to wrap around the API. I prefer strong dataclass typing over guessing the JSON to send or not.


# API DOCUMENTATION

`POST /data/threat_intelligence/SigmaRule/`


Parameters
Try it out
Name	Description
data *
object
(body)
Example Value

ADDITIONAL GUIDANCE
- IGNORE LAST MODIFIER
- ORIGIN STACK/STACK ID IGNORE
- 

{
  "block_on_agent": true,
  "content": "string",
  "enabled": true,
  "global_state": "alert",
  "hl_local_testing_status": "string",
  "hl_status": "experimental",
  "last_modifier": {
    "username": "6F9kNY9f@xAAkh74H@NnWXFhT7kAvzkMEM8R@8gDpYr7+-sd4enT7ear_5O5LH-6a9Lyu753Oa93pMGrB"
  },
  "name": "string",
  "origin_stack": {
    "id": "string",
    "is_current": true,
    "is_supervisor": true,
    "is_tenant": true,
    "name": "string"
  },
  "origin_stack_id": "string",
  "overwrite": false,
  "quarantine_on_agent": true,
  "rule_confidence_override": "moderate",
  "rule_level_override": "critical",
  "source_id": "string"
}


Model
_CreateSigmaRule{
block_on_agent	Block on agentboolean
title: Block on agent
content*	Contentstring
minLength: 1
title: Content
enabled	Enabledboolean
title: Enabled
global_state	Global statestring
title: Global state
Enum:
[ alert, backend_alert, block, disabled, quarantine ]
hl_local_testing_status	Hl local testing statusstring
title: Hl local testing status
deprecated

hl_status	Hl statusstring
title: Hl status
Enum:
[ experimental, stable, testing ]
last_modifier	HlSimpleUserSerializer{
username*	Usernamestring
maxLength: 150
minLength: 1
pattern: ^[\w.@+-]+$
title: Username
Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.

}
name*	Namestring
maxLength: 100
minLength: 1
title: Name
origin_stack	OriginStack{
id*	Idstring
minLength: 1
title: Id
is_current*	Is currentboolean
title: Is current
is_supervisor*	Is supervisorboolean
title: Is supervisor
is_tenant*	Is tenantboolean
title: Is tenant
name	Name[...]
}
origin_stack_id	Origin stack idstring
maxLength: 64
minLength: 1
title: Origin stack id
overwrite	Overwriteboolean
default: false
title: Overwrite
quarantine_on_agent	Quarantine on agentboolean
title: Quarantine on agent
rule_confidence_override	Rule confidence overridestring
title: Rule confidence override
Enum:
[ moderate, strong, weak ]
rule_level_override	Rule level overridestring
title: Rule level override
Enum:
[ critical, high, informational, low, medium ]
source_id*	Source idstring
minLength: 1
title: Source id
}


``

`DELETE /data/threat_intelligence/SigmaRule/{id}/`

Parameters
Try it out
Name	Description
id *
string
(path)
A unique value identifying this sigma rule.

id


# DATA STRUCTURE FOR THE SCHEMA VALIDATION

> WARNING - you are only here to identify logsource/product & field association + how to extract and validate in the schema, including descriptions and additional documentation related to the fields. Other information is superfluous, so be cautious and manage your context to not pollute it.

Writing Sigma rules
-------------------

The EDR of HarfangLab contains a Sigma engine dedicated to behavioral detection. A Sigma rule is structured as follows:

`title: id: description: references: author: date: modified: tags: logsource:     category:     product: detection:     condition: falsepositives: level: confidence:`

A Sigma rule uses the following properties:

Property

Description

`title`

Title of the rule

`id`

Rule ID (generated by the `uuidgen` command under Linux)

`description`

Description of the rule

`references`

List of URLs ( for example, the MITRE ATT&CK reference URL...)

`author`

Rule author

`date`

Rule creation date (format YYYY-MM-DD)

`modified`

Date of rule modification (format YYYY-MM-DD)

`tags`

List of tags associated with the rule, including tactics tags (such as `attack.credential_access`) and technical (such as `attack.t1557`) from MITRE ATT&CK.

`logsource`

Includes 2 different key values: `product` and `catégorie`, respectively for the product name and log category (see below for the list of supported log categories)

`detection`

Content of the rule

`falsepositives`

List of identified situations that could lead to false positives

`level`

Criticality level (`low`, `medium`, `high`, `critical`)

`confidence`

Confidence level (`weak`, `moderate`, `strong`)

The Windows agent of the EDR of HarfangLab generates events with the **logsource.product** metadata defined on **windows**.

Example of a Sigma rule:

`title: Renamed AdFind Binary Executed id: 63b8bd32-635b-4502-9608-767c742d73d3 description: |     Detects when a renamed AdFind binary is launched.     AdFind is a legitimate tool that has been used by numerous threat actors for conducting enumeration in an Active Directory network. Sometimes, this binary is renamed to avoid detection.     It is recommended to determine if this binary is expected to be used in your environment. references:     - https://attack.mitre.org/techniques/T1482/ author: HarfangLab date: 2020/12/15 modified: 2021/03/16 tags:     - attack.discovery     - attack.t1482 logsource:     category: process_creation     product: windows detection:     selection:         OriginalFileName: 'AdFind.exe'     filter_adfind:         Image|endswith: '\AdFind.exe'     condition: selection and not 1 of filter_* falsepositives:     - Legitimate use of AdFind by an administrator or 3rd party application level: high confidence: strong`

Warning

The ID of a Sigma rule has to be unique and cannot be modified once the rule has been created.

Note

When the `level` or `confidence` fields are not defined, the rule automatically adopts the default criticality or confidence level that has been configured for the source it belongs to.

The following sections explain the list of fields available for each type of event detected by the EDR per operating system.

If an agent in an older version gets a rule using an unknown field, the rule will be ignored and an error log will be generated.

Note

You can also configure the [level of maturity for rules](../overview/#rules-maturity).

Windows events
--------------

Note

HarfangLab is trying to stay compatible with public Sigma rules relaying on Sysmon syntax. In case of an error, you can refer yourself to the event's corresponding documentation.

The Sigma engine exposes additional fields about [the related process of an event](#process-extra-fields-windows), [related to the process and event sessions](#session-information-en) as well as [fields related to the agent](#additional-fields-related-to-the-agent).

#### Process creation

Event triggered when a process is created.

`logsource:     product: windows     category: process_creation`

Field name

Description

`CommandLine`

Process command line.

`Company`

Company name from the process image.

`CurrentDirectory`

Directory under which the process image was executed.

`Description`

File description from the process image.

`GrandparentImage`

Path of the grandparent process image.

`GrandparentIntegrityLevel`

Grandparent process integrity level.

`Image`

Path of the process image.

`ImageDriveType`

Drive type of the process image (can be one of the following values: unknown, removable, fixed, remote, disk\_image, ramdisk).

`Imphash`

Imphash of the process image.

`IntegrityLevel`

Process integrity level.

`InternalName`

Internal file name from the process image.

`FileVersion`

File version from the process image.

`GrandparentCommandLine`

Grandparent process command line.

`LegalCopyright`

Legal copyright from the process image.

`LogonId`

Login ID of the user who created the new process.

`md5`

MD5 of the process image.

`OriginalFileName`

Original file name from the process image.

`ParentImage`

Path of the parent process image.

`ParentCommandLine`

Parent process command line.

`ParentIntegrityLevel`

Parent process integrity level.

`Product`

Product name from the process image.

`ProductVersion`

Product version from the process image.

`sha1`

SHA1 of the process image.

`sha256`

SHA256 of the process image.

`User`

The user that created this process.

`UserSID`

The user security identifier (SID).

`Signed`

`true` if the process loaded is signed, otherwise `false` (**This is matched as a string**)

`Signature`

Signer name of the process loaded.

`SignatureStatus`

Status of the signature of the process loaded. (`Valid` or empty string if not signed.)

`Ancestors`

The process' ancestors images joined together by a `|` (e.g `C:\parent.exe|C:\grandparent|C:\grandgrand...`)

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

`LnkLinked`

`true` if the process has been loaded from a lnk, otherwise `false` (**This is matched as a string**)

`LnkPath`

Path of the Windows LNK file that started the process.

`LnkDriveType`

Drive type of the Windows LNK file that started the process (can be one of the following values: unknown, removable, fixed, remote, disk\_image, ramdisk).

`IsFileObjectTransacted`

Boolean value holding whether the file object associated with the starting process is being the subject of an NTFS transaction.

`AuthentihashSha1`

SHA1 of the authenticode-signed data of the process image.

`AuthentihashSha256`

SHA256 of the authenticode-signed data of the process image.

Warning

The Sigma detection engine does not support expired or revoked signatures. A 'not signed' status will be displayed.

#### Network connection

##### Start

Event triggered when a network connection is created.

`logsource:     product: windows     category: network_connection`

Field name

Description

`DestinationPort`

Destination port number.

`DestinationIp`

Destination IP.

`DestinationNames`

DNS names used in order to resolve the destination IP address, if done so prior to the network connection.

`DestinationHostname`

Alias of DestinationNames

`DestinationIsIpv6`

`true` if the destination IP is an IPv6, otherwise `false` (**This is matched as a string**).

`Image`

Path of the process that initiated the network connection.

`Initiated`

Indicates if the process initiated the network connection.

`Protocol`

Protocol being used for the network connection. (`tcp` / `udp` or empty string if not known)

`ProtocolNumber`

IANA assigned protocol number being used for the network connection (tcp = 6, udp = 17, ...). See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

`SourcePort`

Source port number.

`SourceIp`

Source IP.

`SourceIsIpv6`

`true` if the source IP is an IPv6, otherwise `false` (**This is matched as a string**).

`User`

The user associated to the process that initiated the network connection.

`ConnectionGuid`

The unique identifier for the network connection

##### DPI

Event triggered when network connection protocols are identified. Only `HTTP`, `TLS`, and `SSH` are supported.

`logsource:     product: windows     category: network_dpi`

Field name

Description

`DestinationPort`

Destination port number.

`DestinationIp`

Destination IP.

`DestinationNames`

DNS names used in order to resolve the destination IP address, if done so prior to the network connection.

`DestinationHostname`

Alias of DestinationNames

`DestinationIsIpv6`

`true` if the destination IP is an IPv6, otherwise `false` (**This is matched as a string**).

`Image`

Path of the process that initiated the network connection.

`Initiated`

Indicates if the process initiated the network connection.

`Protocol`

Protocol being used for the network connection. (`tcp` / `udp` or empty string if not known)

`ProtocolNumber`

IANA assigned protocol number being used for the network connection (tcp = 6, udp = 17, ...). See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

`SourcePort`

Source port number.

`SourceIp`

Source IP.

`SourceIsIpv6`

`true` if the source IP is an IPv6, otherwise `false` (**This is matched as a string**).

`User`

The user associated to the process that initiated the network connection.

`ConnectionGuid`

The unique identifier for the network connection

`IncomingApplicationProtocol`

The name of the incoming application protocol (`HTTP`/`TLS`/`SSH`).

`OutgoingApplicationProtocol`

The name of the outgoing application protocol (`HTTP`/`TLS`/`SSH`).

`OutgoingTlsVersion`

The outgoing TLS protocol version.

`OutgoingTlsSni`

The outgoing TLS protocol Server Name Indication.

`OutgoingTlsAlpn`

The outgoing TLS protocol Application-Layer Protocol Negotiation.

`OutgoingTlsJa3`

The outgoing TLS protocol JA3 hash.

`OutgoingTlsJa3n`

The outgoing TLS protocol JA3n hash.

`OutgoingTlsJa4`

The outgoing TLS protocol JA4 hash.

`IncomingTlsVersion`

The incoming TLS protocol version.

`IncomingTlsAlpn`

The incoming TLS protocol Application-Layer Protocol Negotiation.

`IncomingTlsJa3s`

The outgoing TLS protocol JA3s hash.

`IncomingTlsCertificateThumbprintSha1`

SHA1 thumbprint of the server certificate.

`IncomingTlsCertificateThumbprintSha256`

SHA256 thumbprint of the server certificate.

`IncomingTlsCertificateDisplayName`

Signer name of the server certificate.

`IncomingTlsCertificateIssuerName`

Signer issuer name of the server certificate.

`OutgoingHttpRequestVersion`

The HTTP protocol version used for the outgoing request.

`OutgoingHttpRequestContentType`

The value of the **Content-Type** header sent with the outgoing HTTP request.

`OutgoingHttpRequestContentLength`

The size, in bytes, of the request payload (Content-Length header) for the outgoing HTTP request.

`OutgoingHttpRequestMethod`

The HTTP method (GET, POST, PUT, ...) used for the outgoing request.

`OutgoingHttpRequestPath`

The request-URI path (the part after the host) of the outgoing HTTP request.

`OutgoingHttpRequestUserAgent`

The **User-Agent** header value sent with the outgoing HTTP request.

`OutgoingHttpRequestHost`

The **Host** header value used for the outgoing HTTP request.

`OutgoingHttpRequestReferer`

The **Referer** header value, if any, sent with the outgoing HTTP request.

`OutgoingHttpRequestCookies`

The cookies (as a single string) included in the outgoing HTTP request.

`IncomingHttpResponseVersion`

The HTTP protocol version used in the incoming response.

`IncomingHttpResponseContentType`

The value of the **Content-Type** header in the incoming HTTP response.

`IncomingHttpResponseContentLength`

The size, in bytes, of the response payload (Content-Length header) of the incoming HTTP response.

`IncomingHttpResponseCode`

The HTTP status code returned by the server (e.g., 200, 404).

`IncomingHttpResponseLastModified`

The **Last-Modified** header value of the incoming HTTP response, if present.

`IncomingHttpResponseServer`

The **Server** header value identifying the software that generated the incoming HTTP response.

`OutgoingSshProtoVersion`

The SSH protocol version string advertised by the client (e.g., `SSH-2.0`).

`OutgoingSshSoftwareVersion`

The software version string of the SSH client (appears after the protocol version).

`OutgoingSshBannerComments`

Any banner comment lines sent by the SSH client during the handshake.

`IncomingSshProtoVersion`

The SSH protocol version string advertised by the server.

`IncomingSshSoftwareVersion`

The software version string of the SSH server.

`IncomingSshBannerComments`

Any banner comment lines sent by the SSH server during the handshake.

`IncomingSshServerPubkeyAndCertAlgo`

The public-key algorithm (and certificate algorithm, if any) used by the SSH server for its host key.

`IncomingSshServerFingerprint`

The fingerprint (hash) of the SSH server's host key.

##### Close

Event triggered when a network connection is closed.

`logsource:     product: windows     category: network_close`

Field name

Description

`DestinationPort`

Destination port number.

`DestinationIp`

Destination IP.

`DestinationNames`

DNS names used in order to resolve the destination IP address, if done so prior to the network connection.

`DestinationHostname`

Alias of DestinationNames

`DestinationIsIpv6`

`true` if the destination IP is an IPv6, otherwise `false` (**This is matched as a string**).

`Image`

Path of the process that initiated the network connection.

`Initiated`

Indicates if the process initiated the network connection.

`Protocol`

Protocol being used for the network connection. (`tcp` / `udp` or empty string if not known)

`ProtocolNumber`

IANA assigned protocol number being used for the network connection (tcp = 6, udp = 17, ...). See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

`SourcePort`

Source port number.

`SourceIp`

Source IP.

`SourceIsIpv6`

`true` if the source IP is an IPv6, otherwise `false` (**This is matched as a string**).

`User`

The user associated to the process that initiated the network connection.

`ConnectionGuid`

The unique identifier for the network connection

`ConnectionSuccessful`

`true` if the connection is successful, otherwise `false` (**This is matched as a string**).

`IncomingBytesCount`

The amount of incoming data in bytes.

`OutgoingBytesCount`

The amount of outgoing data in bytes.

`IncomingApplicationProtocol`

The name of the incoming application protocol (`HTTP`/`TLS`/`SSH`).

`OutgoingApplicationProtocol`

The name of the outgoing application protocol (`HTTP`/`TLS`/`SSH`).

#### Driver loaded

Event triggered when a driver is loaded by the system.

`logsource:     product: windows     category: driver_load`

Field name

Description

`ImageLoaded`

Path of the loaded driver.

`Signed`

`true` if the loaded driver is signed, otherwise `false` (**This is matched as a string**)

`Signature`

Signer name of the loaded driver.

`SignatureStatus`

Status of the signature of the loaded driver. (`Valid` or empty string if not signed.)

`DriverMd5`

MD5 hash of the loaded driver.

`DriverSha1`

SHA1 hash of the loaded driver.

`DriverSha256`

SHA256 hash of the loaded driver.

`Company`

Company name from the loaded driver.

`Description`

File description from the loaded driver.

`FileVersion`

File version from the loaded driver.

`InternalName`

Internal file name from the loaded driver.

`LegalCopyright`

Legal copyright from the loaded driver.

`OriginalFileName`

Original file name from the loaded driver.

`Product`

Product name from the loaded driver.

`ProductVersion`

Product version from the loaded driver.

`AuthentihashSha1`

SHA1 of the authenticode-signed data of the loaded driver.

`AuthentihashSha256`

SHA256 of the authenticode-signed data of the loaded driver.

#### Image loaded

Event triggered when a native or managed (_.NET_) library is loaded.

`logsource:     product: windows     category: library_event`

Field name

Description

`Company`

Company name from the image loaded.

`Description`

File description from the image loaded.

`FileVersion`

File version from the image loaded.

`InternalName`

Internal file name from the image loaded.

`Image`

Path of the process that loaded the image.

`ImageLoaded`

Path of the image loaded.

`ImageLoadedDriveType`

Drive type of the image loaded (can be one of the following values: unknown, removable, fixed, remote, disk\_image, ramdisk).

`LegalCopyright`

Legal copyright from the image loaded.

`OriginalFileName`

Original file name from the image loaded.

`Product`

Product name from the image loaded.

`ProductVersion`

Product version from the image loaded.

`Signed`

`true` if the image loaded is signed, otherwise `false` (**This is matched as a string**)

`Signature`

Signer name of the image loaded.

`SignatureStatus`

Status of the signature of the image loaded. (`Valid` or empty string if not signed.)

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

`AppDomainID`

Identifier for the application domain where the assembly is loaded.

`AssemblyFlags`

Flags that describe characteristics of the assembly.

`AssemblyFlagsStr`

Flags that describe characteristics of the assembly as `|`\-separated string values.

`FullyQualifiedAssemblyName`

Complete name of the assembly, including version, culture, and public key token.

`AssemblyName`

Name of the assembly.

`AssemblyVersion`

Version of the assembly.

`AssemblyCulture`

Culture of the assembly.

`AssemblyToken`

Public key token of the assembly.

`ModuleFlags`

Flags providing additional information about the module.

`ModuleFlagsStr`

Flags providing additional information about the module as `|`\-separated string values.

`ModuleILPath`

Path to the Intermediate Language file for the module.

`ModuleNativePath`

Path to the native image file for the module.

`ManagedPdbBuildPath`

Build path for the PDB of the managed code.

`NativePdbBuildPath`

Build path for the PDB of the native code.

`LibraryType`

Type of the library (`Native` or `Managed`), Windows only.

`AuthentihashSha1`

SHA1 of the authenticode-signed data of the loaded image.

`AuthentihashSha256`

SHA256 of the authenticode-signed data of the loaded image.

#### Remote thread creation

Event trigger when a remote thread is created.

`logsource:     product: windows     category: remote_thread`

Field name

Description

`NewThreadId`

Id of the new remote thread created in the target process.

`SourceProcessId`

Id of the source process that created the remote thread.

`SourceImage`

Path of the source process that created the remote thread.

`StartAddress`

New thread start address. (This is a 8 digit padded hexadecimal string, example: `0x0010006D`)

`StartModule`

Start module of the thread start address. (empty string if unknown)

`StartFunction`

The start function if found in the image export table. (empty string if not found)

`TargetProcessId`

Id of the target process.

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

#### Injected thread

Event triggered when an injected thread is created.

`logsource:     product: windows     category: injected_thread`

Field name

Description

`TargetProcessId`

Id of the target process.

`TargetImage`

Path of the target process.

`SourceProcessId`

ID of the source process that created the injected thread.

`SourceImage`

Path of the source process that created the injected thread.

`NewThreadId`

Id of the new injected thread created in the target process.

`StartAddress`

New thread start address. (This is a 8 digit padded hexadecimal string, example: `0x0010006D`)

`RegionBaseAddress`

New thread's region base address. (This is a 8 digit padded hexadecimal string, example: `0x0010006D`)

`RegionSize`

New thread's region size (in bytes).

`RegionStateHex`

State flags of the pages in the region in hexadecimal. (example: `0x00003000`)

`RegionState`

State flags of the pages in the region as a string. (example: `MEM_COMMIT | MEM_RESERVE`)

`RegionProtectionHex`

Protection flags of the pages in the region in hexadecimal. (example: `0x00000040`)

`RegionProtection`

Protection flags of the pages in the region as a string. (example: `PAGE_EXECUTE_READWRITE`)

`RegionTypeHex`

Type flags of the pages in the region in hexadecimal. (example: `0x00020000`)

`RegionType`

Type flags of the pages in the region as a string. (example: `MEM_PRIVATE`)

`RegionAllocationBase`

Base address of a range of pages allocated by the VirtualAlloc function. (This is a 8 digit padded hexadecimal string, example: `0x0010006D`)

`RegionAllocationProtectionHex`

Protection flags of the pages in the region in hexadecimal. (example: `0x00000040`)

`RegionAllocationProtection`

Protection flags of the pages in the region when the region was initially allocated as a string. (example: `PAGE_EXECUTE_READWRITE`)

`RegionAllocationSize`

Total size of the allocation (in bytes).

`RegionMappedFile`

DOS path of the file mapped at the allocation's address (if any)

`RegionDump`

First 128 bytes of the thread's memory region in hexadecimal. (example: `0x01234567`)

`ThreadDump`

First 128 bytes after the thread's start address in hexadecimal. (example: `0x01234567`)

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

`IsRemoteThread`

A boolean value holding whether the thread is being injected in a remote process.

#### Raw device access

Event triggered when a process makes a raw device access.

`logsource:     product: windows     category: raw_device_access`

Field name

Description

`Image`

Path of the process that performed the raw device access.

`Device`

Device targeted by the raw device access.

`DesiredAccess`

Access Mask asked by the calling process (integer).

`DesiredAccessStr`

String translation of the Access Mask.

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

#### Process access

Event triggered when a process is accessed.

`logsource:     product: windows     category: process_access`

Field name

Description

`CallTrace`

Calltrace of the source thread.

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

`GrantedAccess`

Access flags requested for the target process.

`GrantedAccessStr`

Access flags requested for the target process as a string. (example: `PROCESS_DUP_HANDLE|PROCESS_VM_READ|PROCESS_TERMINATE`)

`SourceImage`

Path of the source process that opened the target process.

`TargetImage`

Path of the target process.

`TargetProcessCommandLine`

Target process command line.

`TargetProcessCompany`

Target Process Company name.

`TargetProcessCurrentDirectory`

Target process current directory.

`TargetProcessDescription`

Target process description.

`TargetProcessFileVersion`

Target process file version from the image loaded.

`TargetProcessGrandparentCommandLine`

Target process grandparent command line.

`TargetProcessGrandparentImage`

Target process grandparent image.

`TargetProcessGrandparentIntegrityLevel`

Target process grandparent integrity level.

`TargetProcessImage`

Target process image.

`TargetProcessImphash`

Target process [import hash](https://www.mandiant.com/resources/tracking-malware-import-hashing).

`TargetProcessIntegrityLevel`

Target process integrity level.

`TargetProcessInternalName`

Target process internal name.

`TargetProcessLegalCopyright`

Target process legal copyright as indicated in the image.

`TargetProcessLogonId`

Logon id of the user who created the target process.

`TargetProcessMd5`

Target process MD5 hash.

`TargetProcessName`

Target process name.

`TargetProcessOriginalFileName`

Target process original file name.

`TargetProcessParentCommandLine`

Parent command line of the target process.

`TargetProcessParentImage`

Parent image of the target process.

`TargetProcessParentIntegrityLevel`

Parent process integrity level of the target process.

`TargetProcessPETimestamp`

PE timestamp of the target process image.

`TargetProcessProduct`

Product name of the target process image.

`TargetProcessProductVersion`

Product version of the target process image.

`TargetProcessSha1`

Target process SHA1 hash.

`TargetProcessSha256`

Target process SHA-256 hash

`TargetProcessSignature`

Signature of the target process image.

`TargetProcessSignatureStatus`

Signature status of the target process image (`Valid` or empty string if not signed).

`TargetProcessSigned`

Boolean indicating whether the target process is signed.

`TargetProcessSignatureRootDisplayName`

Root CA name of the target process image.

`TargetProcessSignatureRootIssuerName`

Root issuer name of the target process image.

`TargetProcessSignatureRootSerialNumber`

Root CA serial number of the target process image.

`TargetProcessSignatureRootThumbprint`

Root thumbprint of the target process image.

`TargetProcessSignatureSignerDisplayName`

Signer name of the target process image.

`TargetProcessSignatureSignerIssuerName`

Signer issuer name of the target process image.

`TargetProcessSignatureSignerSerialNumber`

Signer serial number of the target process image.

`TargetProcessSignatureSignerThumbprint`

Signer thumbprint of the target process image.

`TargetProcessSize`

Image size of the target process (in bytes).

`TargetProcessUser`

User who initiated the target process.

`TargetProcessUserSID`

SID of the user who initiated the target process.

#### Process handle duplicated

Event triggered when a handle targeting a process is duplicated.

`logsource:     product: windows     category: process_duplicate_handle`

Field name

Description

`CallerImage`

Path of the process calling DuplicateHandle.

`CallerProcessId`

ID of the process calling DuplicateHandle.

`SourceImage`

Path of the process with the handle to be duplicated.

`SourceProcessId`

ID of the process with the handle to be duplicated.

`DestinationImage`

Path of the process that is to receive the duplicated handle.

`DestinationProcessId`

ID of the process that is to receive the duplicated handle.

`TargetImage`

Path of the process that is the target of the handle operation.

`TargetProcessId`

ID of the process that is the target of the handle operation.

`GrantedAccess`

Access flags requested for the target process.

`GrantedAccessStr`

Access flags requested for the target process as a string. (example: `PROCESS_DUP_HANDLE|PROCESS_VM_READ|PROCESS_TERMINATE`)

`CallTrace`

Calltrace of the caller thread.

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

`CallerIsDestination`

`true` if the caller process is the destination process.

#### Process tampering

Event triggered when a process is altered.

`logsource:     product: windows     category: process_tampered`

Field name

Description

`Image`

Image of the tampered process (e.g: `C:\toto.exe`)

`Type`

The type of tampering (can be one of 3 strings: `Image is replaced`, `Image is locked for access` or `Image is deleted`)

#### API NtAllocateVirtualMemory (e.g. VirtualAlloc, VirtualAllocEx)

Event triggered when a process call `NtAllocateVirtualMemory`.

`logsource:     product: windows     category: etwti_ntallocatevirtualmemory`

Field name

Description

`ProcessId`

The ID of the process that called the NtAllocateVirtualMemory API.

`ThreadId`

The ID of the thread that called the NtAllocateVirtualMemory API.

`Image`

Path of the process that called the NtAllocateVirtualMemory API.

`TargetProcessId`

The ID of the process targeted by the NtAllocateVirtualMemory API.

`TargetImage`

Path of the process targeted by the NtAllocateVirtualMemory API.

`BaseAddress`

Base address of the memory allocation (This is a hexadecimal string, example: `0x10006D`).

`RegionSize`

Size of the allocated region (This is a hexadecimal string, example: `0x10006D`).

`AllocationType`

Type of allocation (This is a hexadecimal string, example: `0x10006D`).

`AllocationTypeStr`

Type of allocation in a string format (e.g. MEM\_COMMIT

`ProtectionMask`

Protection mask of the allocated memory region (This is a hexadecimal string, example: `0x10006D`).

`ProtectionMaskStr`

Protection mask of the allocated memory region in a string format (e.g. PAGE\_EXECUTE\_READWRITE).

`IsRemote`

A boolean value holding whether the memory allocation is being performed in a remote process (meaning a process other than the caller).

#### Registry events

##### Object created and deleted

Event triggered when a registry object is created or deleted.

`logsource:     product: windows     category: registry_event`

Field name

Description

`EventType`

`CreateKey` or `DeleteKey`

`Image`

Path of the process that generated the registry event.

`TargetObject`

Complete path of the registry key.

`PreviousDetails`

The previous value set in the registry before the operation.

`IsPreviousDetailsSet`

Boolean value indicating whether a previous value existed before the operation.

`ValueType`

The type of the registry value set (REG\_SZ, REG\_DWORD, ...)

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

##### Value set

Event triggered when a registry value is set.

`logsource:     product: windows     category: registry_event`

Field name

Description

`Details`

The value set in the registry.

`PreviousDetails`

The previous value set in the registry before the operation.

`DetailsAdded`

List of strings added in the registry value (only for REG\_MULTI\_SZ).

`DetailsRemoved`

List of strings removed in the registry value (only for REG\_MULTI\_SZ).

`IsPreviousDetailsSet`

Boolean value indicating whether a previous value existed before the operation.

`ValueType`

The type of the registry value set (REG\_SZ, REG\_DWORD, ...)

`EventType`

`SetValue`

`Image`

Path of the process that generated the registry event.

`TargetObject`

Complete path of the registry key.

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

##### Key and value renamed

Event triggered when a key or value is renamed.

`logsource:     product: windows     category: registry_event`

Field name

Description

`EventType`

`RenameKey`

`NewName`

New name of the registry key.

`Image`

Path of the process that generated the registry event.

`TargetObject`

Complete path of the registry key.

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

##### Key saved

Event triggered when a registry key is saved.

`logsource:     product: windows     category: registry_event`

Field name

Description

`EventType`

`SaveKey`

`Image`

Path of the process that generated the registry event.

`TargetObject`

Complete path of the registry key being save to disk.

`HivePath`

Path at which the hive will be saved on disk (e.g C:\\Windows\\Temp\\SavedHive.hve)

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

##### Value read

Event triggered, then, a registry value is read.

`logsource:     product: windows     category: registry_event`

Field name

Description

`EventType`

`ReadValue`

`Image`

Path of the process that generated the registry event.

`TargetObject`

Complete path of the registry value being read.

`ValueType`

The type of the registry value set (REG\_SZ, REG\_DWORD, ...)

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

#### Named pipe events

##### Pipe created

Event triggered when a named pipe is created.

`logsource:     product: windows     category: named_pipe_creation`

Field name

Description

`PipeName`

Name of the created Named Pipe (in the format: `\PIPENAME`)

`NamedPipeType`

Type of the created Named Pipe (integer, e.g: `1`)

`InboundQuota`

Inbound quota of the created Named Pipe (hex string, e.g: `0x4000`)

`OutboundQuota`

Outbound quota of the created Named Pipe (hex string, e.g: `0x4000`)

`MaximumInstances`

Maximum number of instances for the created pipe (integer, e.g: `2`)

`DesiredAccess`

Desired Access permissions for the created pipe (hex string, e.g: `0x1a019f`)

`Kind`

Identifies the named pipe operation, value: `creation`

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

##### Pipe connected

Event triggered when a process connects to a named pipe.

`logsource:     product: windows     category: named_pipe_connection`

Field name

Description

`PipeName`

Name of the created Named Pipe (in the format: `\PIPENAME`)

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

`Kind`

Identifies the named pipe operation, value: `connection`

`TargetProcessCommandLine`

`TargetProcessCompany`

`TargetProcessCurrentDirectory`

`TargetProcessDescription`

`TargetProcessFileVersion`

`TargetProcessGrandparentCommandLine`

`TargetProcessGrandparentImage`

`TargetProcessGrandparentIntegrityLevel`

`TargetProcessImage`

`TargetProcessImphash`

`TargetProcessIntegrityLevel`

`TargetProcessInternalName`

`TargetProcessLegalCopyright`

`TargetProcessLogonId`

`TargetProcessMd5`

`TargetProcessName`

`TargetProcessOriginalFileName`

`TargetProcessParentCommandLine`

`TargetProcessParentImage`

`TargetProcessParentIntegrityLevel`

`TargetProcessPETimestamp`

`TargetProcessProduct`

`TargetProcessProductVersion`

`TargetProcessSha1`

`TargetProcessSha256`

`TargetProcessSignature`

`TargetProcessSignatureStatus`

`TargetProcessSigned`

`TargetProcessSignatureRootDisplayName`

`TargetProcessSignatureRootIssuerName`

`TargetProcessSignatureRootSerialNumber`

`TargetProcessSignatureRootThumbprint`

`TargetProcessSignatureSignerDisplayName`

`TargetProcessSignatureSignerIssuerName`

`TargetProcessSignatureSignerSerialNumber`

`TargetProcessSignatureSignerThumbprint`

`TargetProcessSize`

`TargetProcessUser`

`TargetProcessUserSID`

#### Filesystem events

##### File created

Event triggered when a file is created.

`logsource:     product: windows     category: file_create`

Field name

Description

`Path`

The path of the file being created

`TargetFilename`

Alias for `Path` (for compatibility purposes)

`FileName`

Alias for `Path` (for compatibility purposes)

`FileDriveType`

Drive type of the file being created (can be one of the following values: unknown, removable, fixed, remote, disk\_image, ramdisk).

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

##### File read

Event triggered when a file is read by a process

`logsource:     product: windows     category: file_read`

Field name

Description

`Path`

The path of the file being read

`TargetFilename`

Alias for `Path` (for compatibility purposes)

`FileName`

Alias for `Path` (for compatibility purposes)

`FileDriveType`

Drive type of the file being read (can be one of the following values: unknown, removable, fixed, remote, disk\_image, ramdisk).

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

##### File written

Event triggered when a file is written by a process.

`logsource:     product: windows     category: file_write`

Field name

Description

`Path`

The path of the file being written

`TargetFilename`

Alias for `Path` (for compatibility purposes)

`FileName`

Alias for `Path` (for compatibility purposes)

`FileDriveType`

Drive type of the file being written (can be one of the following values: unknown, removable, fixed, remote, disk\_image, ramdisk).

`FirstBytes`

In the case of a file write at offset zero, the first 16 bytes written to the file (formatted as `5a4d0001020304...`)

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

##### File renamed

Event triggered when a file is renamed.

`logsource:     product: windows     category: file_rename`

Field name

Description

`Path`

The path of the file being renamed

`TargetPath`

The new path of the file

`FileDriveType`

Drive type of the file being renamed (can be one of the following values: unknown, removable, fixed, remote, disk\_image, ramdisk).

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

##### File removed

Event triggered when a file is removed.

`logsource:     product: windows     category: file_remove`

Field name

Description

`Path`

The path of the file being removed

`TargetFilename`

Alias for `Path` (for compatibility purposes)

`FileName`

Alias for `Path` (for compatibility purposes)

`FileDriveType`

Drive type of the file being removed (can be one of the following values: unknown, removable, fixed, remote, disk\_image, ramdisk).

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

##### ShadowCopy accessed

Event triggered when a process accesses (any action, read, write etc.) a file inside a Volume Shadow Copy.

`logsource:     product: windows     category: file_shadowcopy`

Field name

Description

`Path`

The path of the file being written

`TargetFilename`

Alias for `Path` (for compatibility purposes)

`FileName`

Alias for `Path` (for compatibility purposes)

`FileDriveType`

Drive type of the file targeted by the shadow copy operation (can be one of the following values: unknown, removable, fixed, remote, disk\_image, ramdisk).

`CreateOptions`

File creation options (integer), see the [Microsoft documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-iocreatefilespecifydeviceobjecthint)

`CreateOptionsStr`

Translated file creation options, see the [Microsoft documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-iocreatefilespecifydeviceobjecthint)

`CreateDisposition`

File disposition value, see the [Microsoft documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-iocreatefilespecifydeviceobjecthint)

`CreateDispositionStr`

Translated file disposition value, see the [Microsoft documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-iocreatefilespecifydeviceobjecthint)

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

`ProcessXXX` fields are also available and correspond to the process doing the action.

##### File downloaded

Event triggered when a file is downloaded by a process.

`logsource:     product: windows     category: file_download`

Field name

Description

`Path`

The path of the file being downloaded

`TargetFilename`

Alias for `Path` (for compatibility purposes)

`FileName`

Alias for `Path` (for compatibility purposes)

`FileDriveType`

Drive type of the file being downloaded (can be one of the following values: unknown, removable, fixed, remote, disk\_image, ramdisk).

`Kind`

`download`

`SourceUrl`

URL from which the file was downloaded

`SourceUrlScheme`

Scheme of the URL (`http`, `https`, etc.).

`SourceUrlHost`

Host where the file is located.

`SourceUrlPort`

Port used to access the file.

`SourceUrlPath`

Path of the file in the URL used to access the file from the targeted host.

`SourceUrlQueryParams`

Query parameters used to access the file.

`SourceUrlUsername`

Username used to access the file.

`SourceUrlPassword`

Password used to access the file.

`UrlZone`

Url Security Zone of the file being downloaded (can be `Invalid`, `LocalMachine`, `Intranet`, `Trusted`, `Internet`, `Untrusted`, `PredefinedMax`, `UserMin` or `UserMax`), see the [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms537183(v=vs.85)?redirectedfrom=MSDN)

`ZoneId`

ID of the URL Zone, see the [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms537183(v=vs.85)?redirectedfrom=MSDN)

`HostUrl`

URL from which the file was downloaded

`ReferrerUrl`

Referrer URL of the downloaded file

`HostIpAddress`

IP address from which the file was downloaded (can be null)

`SourceIpAddress`

IP address from which the file was downloaded (can be null)

`AppZoneId`

ID of the URL Zone of the downloaded Windows App (can be null)

`LastWriterPackageFamilyName`

Mark of the app container. The package family name of the last app to edit the file's contents.

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

##### Written executable

Event triggered when a file executable is written.

`logsource:     product: linux     category: filesystem_event`

Field name

Description

`Path`

The path of executable file being written to disk

`TargetFilename`

Alias for `Path` (for compatibility purposes)

`FileName`

Alias for `Path` (for compatibility purposes)

`FileDriveType`

Drive type of the executable file being written to disk (can be one of the following values: unknown, removable, fixed, remote, disk\_image, ramdisk).

`Kind`

`written_executable`

`StackTrace`

The full stacktrace leading to the event, in the following format: `C:\Windows\System32\ntdll.dll!NtCreateFile+0x200|C:\Windows\System32\kernel32.dll!CreateFile+0x100|UNKNOWN(0x0000000000000000)|...`.

`MinimalStackTrace`

The simplified stacktrace leading to the event, in the following format: `ntdll.dll|kernel32.dll|UNKNOWN|...`

`FileMd5`

MD5 hash of the executable file written to disk.

`FileSha1`

SHA1 hash of the executable file written to disk.

`FileSha256`

SHA256 hash of the executable file written to disk.

`FileSize`

Size in bytes of the executable file written to disk.

`FileSignature`

Signer name of the executable file written to disk.

`FileSignatureStatus`

Signature status of the executable file written to disk (`Valid` or empty string if not signed).

`FileSigned`

Boolean indicating whether the executable is signed.

`FileSignatureRootDisplayName`

Root CA name of the executable file written to disk.

`FileSignatureRootIssuerName`

Root issuer name of the executable file written to disk.

`FileSignatureRootSerialNumber`

Root CA serial number of the executable file written to disk.

`FileSignatureRootThumbprint`

Root thumbprint of the executable file written to disk.

`FileSignatureSignerDisplayName`

Signer name of the executable file written to disk.

`FileSignatureSignerIssuerName`

Signer issuer name of the executable file written to disk.

`FileSignatureSignerSerialNumber`

Signer serial number of the executable file written to disk.

`FileSignatureSignerThumbprint`

Signer thumbprint of the executable file written to disk.

`FileCompany`

Company name of the executable written to disk (PE metadata).

`FileDescription`

Description of the executable written to disk (PE metadata).

`FileVersion`

Version of the executable written to disk (PE metadata).

`FileImphash`

IMPHASH of the executable written to disk (PE metadata).

`FileInternalName`

Internal name of the executable written to disk (PE metadata).

`FileLegalCopyright`

Copyright of the executable written to disk (PE metadata).

`FileOriginalFileName`

Original file name of the executable written to disk (PE metadata).

`FilePETimestamp`

PE timestamp of the executable written to disk (PE metadata).

`FilePETimestampStr`

PE timestamp of the executable written to disk, in Sysmon format (PE metadata).

`FileProduct`

Product name of the executable written to disk (PE metadata).

`FileProductVersion`

Product version of the executable written to disk (PE metadata).

`FileAuthentihashSha1`

SHA1 of the authenticode-signed data of the executable written to disk.

`FileAuthentihashSha256`

SHA256 of the authenticode-signed data of the executable written to disk.

#### PowerShell

Event triggered when a PowerShell command is executed.

`logsource:     product: windows     category: powershell_event`

Field name

Description

`PowershellCommand`

Powershell command executed.

`ScriptBlockText`

Powershell command executed.

`PowershellScriptPath`

Path of the powershell script containing this command.

`Path`

Path of the powershell script containing this command.

`Signed`

`true` if the script located at `ScriptPath` is signed, otherwise `false` (**This is matched as a string**)

`Signature`

Signer name of the script located at `ScriptPath`.

`SignatureStatus`

Status of the signature of the script located at `ScriptPath`. (`Valid` or an empty string if not signed.)

`Md5`

MD5 hash of the powershell script.

`Sha1`

SHA1 hash of the powershell script.

`Sha256`

SHA256 hash of the powershell script.

`ScriptSize`

Size of the powershell script (in bytes).

`ScriptNumberOfLines`

Number of lines of the powershell script.

#### URL request

Event triggered when a process requests an URL.

`logsource:     product: windows     category: url_request`

Field name

Description

`RequestUrl`

URL to the resource requested.

`RequestUrlVerb`

Verb used to access the resource (`GET`, `POST`, etc.).

`RequestUrlScheme`

Scheme of the URL (`http`, `https`, etc.).

`RequestUrlHost`

Host where the resource is located.

`RequestUrlPort`

Port used to access the resource.

`RequestUrlPath`

Path of the resource on the targeted host.

`RequestUrlQueryParams`

Query parameters used to access the resource.

`RequestUrlUsername`

Username used to access the resource.

`RequestUrlPassword`

Password used to access the resource.

`UserAgent`

User agent used to access the resource.

#### Login

Event triggered when a user login on the machine.

`logsource:     product: windows     category: login_event`

Field name

Description

`Success`

`true` if the authentication was successful, `false` otherwise.

`TargetUsername`

Name of the user being logged into.

`TargetDomainName`

Domain name of the user being logged into.

`TargetSid`

SID of the user being logged into.

`SourceUsername`

Username of the process causing the login.

`SourceDomainName`

Domain name of the process causing the login.

`SourceSid`

SID of the user causing the login.

`AuthenticationPackageName`

Name of the authentication package that was used for the logon authentication process.

`WorkstationName`

Machine name from which the logon attempt was performed.

`IpAddress`

IP address of the machine from which logon attempt was performed.

`IpPort`

Source port that was used for the logon attempt from the remote machine.

`Status`

The reason why the logon failed.

`SubStatus`

Additional information about the logon failure.

#### Logout

Event triggered when a user disconnects on the machine.

`logsource:     product: windows     category: logout_event`

Field name

Description

`TargetUsername`

Name of the user being logged into.

`TargetDomainName`

Domain name of the user being logged into.

`TargetSid`

SID of the user being logged into.

#### DNS resolution

Event triggered when a process resolves a domain name.

`logsource:     product: windows     category: dns_query`

Field name

Description

`QueryName`

Requested domain name.

`QueryType`

The DNS query type: `A`, `AAAA`, `TXT`, ...

`QueryStatusCategory`

Status of the query: `success`, `connection_error`, `timeout`, `name_not_found`, `record_not_found` or `invalid_reply`.

`IpAddresses`

The addresses that have been returned by the resolution.  
This may be empty, for example for TXT requests.

`TextRecords`

The text records that have been returned by a TXT query.  
This is empty for all other types of requests.

`QueryStatus`

The raw return code of the resolution.  
It is recommended to use the `QueryStatusCategory` field instead, which is more readable.

`QueryResults`

The raw resolution results. The content looks like this:  
`type: 5 detectportal.prod.mozaws.net;type: 5 prod.detectportal.prod.cloudops.mozgcp.net;2600:1901:0:38d7::;::ffff:34.107.221.82;`

`Image`

Path of the process that initiated the DNS resolution.

`User`

The user associated to the process that initiated the DNS resolution.

#### User management event

Event triggered when a user is created / modified / disabled / deleted.

`logsource:     product: windows     category: user`

Field name

Description

`TargetUserName`

Username of the user targeted by the operation.

`TargetDomainName`

Domain name of the target of the operation.

`TargetUserID`

ID of the target user (can be UID, SID, etc.).

`SourceUserID`

ID of the source user (can be UID, SID, etc.).

`SourceUserName`

Username of the source user that requested the operation.

`SourceDomainName`

Domain name of the source user that requested the operation.

`SourceLogonID`

LogonID of the source user.

`SourcePrivilegelist`

List of user privileges used during the operation.

`TargetSAMName`

Logon name for account used to support clients and servers from previous versions of Windows.

`TargetDisplayName`

Name displayed in the address book.

`TargetPrincipalName`

Internet-style login name for the account, based on the Internet standard RFC 822.

`TargetHomeDirectory`

User's home directory.

`TargetHomePath`

The drive letter to which the UNC path specified by homeDirectory account's attribute should be mapped.

`TargetScriptPath`

Path of the account's logon script.

`TargetProfilePath`

Path to the account's profile.

`TargetUserWorkstations`

List of NetBIOS or DNS names of the computers from which the user can logon.

`TargetPasswordLastSet`

Last time the account's password was modified.

`TargetAccountExpires`

Date when the account expires.

`TargetPrimaryGroupId`

Relative Identifier (RID) of user's object primary group.

`TargetAllowedToDelegateTo`

List of SPNs to which this account can present delegated credentials.

`UserAccountControl`

User account properties.

`SIDHistory`

Previous SIDs used for the object if the object was moved from another domain.

`NewUserName`

New username when the operation is `rename`.

`OperationType`

Operation type (`create`, `delete`, `enable`, `disable`, `rename`, `change`, `lock_out`, `unlock`, `deleted`, `password_change`, `password_reset`).

#### Group management event

Event triggered when a group is created / modified / deleted or a user is added / removed from the group.

`logsource:     product: windows     category: group`

Field name

Description

`GroupName`

Name of the group targeted by the operation.

`DomainName`

Domain name of the target of the operation.

`GroupID`

ID of the target group (can be GID, SID, etc..)

`SourceUserID`

ID of the source user (can be UID, SID, etc.).

`SourceUserName`

Username of the source user that requested the operation.

`SourceDomainName`

Domain name of the source user that requested the operation.

`SourceLogonID`

LogonID of the source user.

`SourcePrivilegelist`

List of user privileges used during the operation.

`TargetSAMName`

Name for the group used to support clients and servers from previous versions of Windows.

`SIDHistory`

Previous SIDs used for the object if the object was moved from another domain.

`OldGroupType`

Old group type in a 'type\_change' operation.

`NewGroupType`

New group type in a 'type\_change' operation.

`TargetMemberName`

Name of the user added/removed to/from the group.

`TargetMemberID`

ID of the user added/removed to/from the group.

`OperationType`

Operation type (create, delete, change, member\_add, member\_remove, type\_change).

#### AMSI scan

Event triggered when a process asks for an AMSI scan.

`logsource:     product: windows     category: amsi_scan`

Field name

Description

`AppName`

Name, version or GUID string of the application name (e.g. `VBScript`, `PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.19041.1`).

`ContentName`

The filename, URL, unique script ID or similar of the content.

`TextPayload`

The textual content of the payload of the scan, potentially truncated.

#### Windows service

Event triggered when a service operation occurs: create / change / start or receive control command (stop / suspend / resume).

`logsource:     product: windows     category: service`

Field name

Description

`ServiceName`

Name of the service.

`IsRemote`

Defined if the operation has been triggered remotely.

`Image`

Path of the process that requested the operation.

`ServiceStartType`

Start type of the service.

`ServiceStartTypeStr`

Star type of the service as a string. (example: `SYSTEM_START`)

`ServiceCommandLine`

Service command\_line.

`ServiceType`

Type of the service.

`ServiceTypeStr`

Type of the service as a string. (example: `KERNEL_DRIVER`)

`ServiceAccount`

Account of the service.

`ControlCode`

Control code received by the service.

`ControlCodeStr`

Control code received by the service as a string. (example: `SERVICE_CONTROL_STOP`)

`SourceUserID`

ID of the source user.

`SourceUserName`

Username of the source user that requested the operation.

`SourceDomainName`

Domain name of the source user that requested the operation.

`OperationType`

Operation type (`create`, `change`, `start`, `control_received`).

#### Scheduled tasks

Event triggered when a scheduled task operation occurs: create / delete / enable / disable / update / or task process creation (when a scheduled task runs and spawns a process).

`logsource:     product: windows     category: scheduled_task`

Field name

Description

`TaskName`

Name of the scheduled task.

`TaskPath`

Path to the task on disk

`Image`

Path of the process that created/modified the task or was spawned by a task.

`SourceUserName`

Username that triggered the operation.

`SourceUserId`

User ID that triggered the operation.

`SourceDomainName`

Domain name of the user that triggered the operation.

`IsRemote`

Indicates if the operation was performed from a remote machine.

`TaskContent`

Raw XML content of the task definition.

`SourceLogonId`

Logon ID of the source user.

`ClientProcessId`

Process ID of the client that made the request.

`RpcCallLocality`

RPC call locality information.

`SpawnedProcessPid`

Process ID of the process spawned by the task.

`ProcessPriority`

Priority of the spawned process.

`OperationType`

Operation type (task\_modification, task\_process\_created).

`FirstActionCommandLine`

Command-line of the first executable action in the task.

`NumberOfTriggers`

Number of triggers configured for this task.

`NumberOfActions`

Number of actions configured for this task.

`TaskCommands`

Concatenation of all command-lines present in the task actions separated by a '

`PrincipalUserId`

User ID under which the task runs.

`LogonType`

Logon type for task execution.

`RunLevel`

Run level of the task (least\_privilege, highest\_available, etc.).

`PrincipalGroupId`

Group ID associated with the task principal.

`TaskEnabled`

Whether the task is enabled.

`TaskHidden`

Whether the task is hidden from the task scheduler UI.

`ExecutionTimeLimit`

Maximum time the task is allowed to run.

`TaskPriority`

Priority level of the task execution.

#### Windows event logs

The Sigma engine exposes a generic syntax to access Windows EventLogs in addition of a specific `logsource` for common logs.

Note

If they are not exposed directly, it is possible to get access to fields located in `EventData` and the `UserData` sections using `event_data.` et `user_data.` prefixes in all logs.

The table below lists the Windows Event logs that are available through detection:

Channel

Provider

Included

Excluded

Application

Application Error

All

Application

Application Hang

All

Application

MSSQLSERVER

15457

Application

Microsoft-Windows-User Profiles Service

All

Application

Microsoft-Windows-WMI

All

Application

Microsoft-Windows-Winlogon

All

Application

MsiInstaller

All

Application

SecurityCenter

All

Application

Windows Error Reporting

All

Application

Wow64 Emulation Layer

All

MSExchange Management

MSExchange CmdletLogs

1

Microsoft-IIS-Logging/Logs

Microsoft-Windows-IIS-Logging

6200

Microsoft-Windows-CodeIntegrity/Operational

Microsoft-Windows-CodeIntegrity

All

Microsoft-Windows-Crypto-DPAPI/Operational

Microsoft-Windows-Crypto-DPAPI

16385

Microsoft-Windows-DFSN-Server/Admin

Microsoft-Windows-DFSN-Server

514, 515

Microsoft-Windows-NTLM/Operational

Microsoft-Windows-NTLM

All

Microsoft-Windows-PowerShell/Operational

Microsoft-Windows-PowerShell

4103, 4104

Microsoft-Windows-TerminalServices-LocalSessionManager/Operational

Microsoft-Windows-TerminalServices-LocalSessionManager

All

Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational

Microsoft-Windows-TerminalServices-RemoteConnectionManager

All

Microsoft-Windows-Windows Defender/Operational

Microsoft-Windows-Windows Defender

All

Security

Microsoft-Windows-Eventlog

All

Security

Microsoft-Windows-Security-Auditing

4608, 4609, 4610, 4611, 4612, 4614, 4615, 4616, 4618, 4621, 4622, 4624, 4625, 4634, 4647, 4648, 4649, 4662, 4672, 4697, 4698, 4699, 4700, 4701, 4702, 4703, 4704, 4705, 4706, 4707, 4713, 4716, 4717, 4718, 4719, 4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4738, 4739, 4740, 4741, 4742, 4743, 4744, 4745, 4746, 4747, 4748, 4749, 4750, 4751, 4752, 4753, 4754, 4755, 4756, 4757, 4758, 4759, 4760, 4761, 4762, 4764, 4765, 4766, 4767, 4768, 4769, 4770, 4771, 4772, 4773, 4774, 4776, 4777, 4778, 4779, 4780, 4781, 4793, 4797, 4798, 4799, 4800, 4801, 4802, 4803, 4820, 4821, 4822, 4823, 4824, 4825, 4826, 4865, 4866, 4867, 4870, 4886, 4887, 4888, 4893, 4898, 4902, 4904, 4905, 4907, 4931, 4932, 4933, 4946, 4948, 4956, 4964, 5024, 5025, 5029, 5030, 5033, 5034, 5035, 5037, 5059, 5136, 5137, 5138, 5139, 5140, 5145, 5381, 5382, 5712, 6144, 6145, 6272, 6273, 6278, 6416, 6423, 6424

System

Microsoft Antimalware

All

System

Microsoft-Windows-Bits-Client

All

System

Microsoft-Windows-Directory-Services-SAM

All

System

Microsoft-Windows-DistributedCOM

All

System

Microsoft-Windows-Eventlog

All

System

Microsoft-Windows-GroupPolicy

All

System

Microsoft-Windows-Kernel-General

All

System

Microsoft-Windows-Kernel-Power

All

System

Microsoft-Windows-TaskScheduler

All

System

Microsoft-Windows-WER-SystemErrorReporting

All

System

Microsoft-Windows-WindowsUpdateClient

All

System

Microsoft-Windows-Wininit

All

System

Microsoft-Windows-Winlogon

All

System

Service Control Manager

All

System

User32

All

Windows Powershell

PowerShell

All

##### Generic syntax

`logsource:     product: windows     category: eventlog`

The channel can then be specified using the `LogName` field and the event fields located in `EventData` and `UserData` sections can be accessed using `event_data.` et `user_data.` prefixes.

##### Application

`logsource:     product: windows     service: application`

Fields available in the event log can be used.

##### Security

`logsource:     product: windows     service: security`

Fields available in the event log can be used.

##### System

`logsource:     product: windows     service: system`

Fields available in the event log can be used.

##### Powershell

`logsource:     product: windows     service: powershell-classic`

Fields available in the event log can be used.

##### Microsoft-Windows-PowerShell/Operational

`logsource:     product: windows     service: powershell`

Fields available in the event log can be used.

##### Microsoft-Windows-Windows Defender/Operational

`logsource:     product: windows     service: defender`

Fields available in the event log can be used.

##### Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational

`logsource:     product: windows     service: terminalservices-remoteconnectionmanager`

Fields available in the event log can be used.

##### Microsoft-Windows-TerminalServices-LocalSessionManager/Operational

`logsource:     product: windows     service: terminalservices-localsessionmanager`

Fields available in the event log can be used.

#### Windows API

##### Win32k - GetAsyncKeyState

Triggered when a process use the GetAsyncKeyState API.

`logsource:     product: windows     category: win32k_getasynckeystate`

Field name

Description

`ProcessId`

The ID of the process that called the GetAsyncKeyState API.

`Image`

Path of the process that called the GetAsyncKeyState API.

`MsSinceLastKeyEvent`

This parameter indicates the elapsed time in milliseconds between the last GetAsyncKeyState event.

`BackgroundCallCount`

This parameter indicates the number of all GetAsyncKeyState API calls, including unsuccessful calls, between the last successful GetAsyncKeyState call.

##### Win32k - RegisterRawInputDevices

Triggered when a process use the RegisterRawInputDevices API.

`logsource:     product: windows     category: win32k_registerrawinputdevices`

Field name

Description

`ProcessId`

The ID of the process that called the RegisterRawInputDevices API.

`Image`

Path of the process that called the RegisterRawInputDevices API.

`UsagePage`

This parameter indicates the top-level collection (Usage Page) of the device. This is the first member of the RAWINPUTDEVICE structure.

`UsagePageStr`

String representation of the UsagePage field.

`ReturnValue`

Return value of RegisterRawInputDevices.

`UsageId`

This parameter indicates the specific device (Usage) within the Usage Page. This is the second member of the RAWINPUTDEVICE structure.

`UsageIdStr`

String representation of the UsageId field.

`WindowsCount`

Number of windows owned by the caller thread.

`VisibleWindowsCount`

Number of visible windows owned by the caller thread.

`StartModuleName`

Name of the module associated with the starting address of a thread.

`Flags`

Mode flag that specifies how to interpret the information provided by UsagePage and UsageId. This is the third member of the RAWINPUTDEVICE structure.

`FlagsStr`

String representation of the Flags field.

`ThreadInfoFlags`

Thread information flags.

`StartAddressProtection`

Memory protection attributes associated with the starting address of the caller thread.

##### Win32k - SetWindowsHookEx

Triggered when a process use the SetWindowsHookEx API.

`logsource:     product: windows     category: win32k_setwindowshookex`

Field name

Description

`ProcessId`

The ID of the process that called the SetWindowsHookEx API.

`Image`

Path of the process that called the SetWindowsHookEx API.

`HookLibrary`

DLL containing the hook procedure.

`HookFunction`

Summary of the hook procedure.

`ReturnValue`

Return value of SetWindowsHookEx.

`FilterType`

Type of hook procedure to be installed as uint32.

`FilterTypeStr`

Type of hook procedure to be installed as string.

#### Extra process fields

Those fields are available on all events except for driver load.

Field name

Description

`ProcessCommandLine`

`ProcessCompany`

`ProcessCurrentDirectory`

`ProcessDescription`

`ProcessFileVersion`

`ProcessGrandparentCommandLine`

`ProcessGrandparentImage`

`ProcessGrandparentImageDriveType`

`ProcessGrandparentIntegrityLevel`

`ProcessImage`

`ProcessImageDriveType`

`ProcessImphash`

`ProcessIntegrityLevel`

`ProcessInternalName`

`ProcessLegalCopyright`

`ProcessLogonId`

`ProcessMd5`

`ProcessProcessName`

`ProcessOriginalFileName`

`ProcessParentCommandLine`

`ProcessParentImage`

`ProcessParentImageDriveType`

`ProcessParentIntegrityLevel`

`ProcessPETimestamp`

`ProcessProduct`

`ProcessProductVersion`

`ProcessSession`

`ProcessSha1`

`ProcessSha256`

`ProcessSignature`

`ProcessSignatureStatus`

`ProcessSigned`

`ProcessSignatureRootDisplayName`

`ProcessSignatureRootIssuerName`

`ProcessSignatureRootSerialNumber`

`ProcessSignatureRootThumbprint`

`ProcessSignatureSignerDisplayName`

`ProcessSignatureSignerIssuerName`

`ProcessSignatureSignerSerialNumber`

`ProcessSignatureSignerThumbprint`

`ProcessIsFileObjectTransacted`

`ProcessSize`

`ProcessUser`

`ProcessUserSID`

`ProcessAncestors`

`ProcessStackTrace`

`ProcessMinimalStackTrace`

Equivalent fields using the `ProcessParent` and `ProcessGrandparent` prefixes are also available, respectively referencing the parent and grandparent processes.

#### Sessions information

Two prefixes allow to create detection, based on information of the user's session:

*   `Session`: information about the user session related to the event, can be specific to a thread or any session specified by the event, for instance, for Windows event logs. This session might differ from the process one, for example, when the thread is impersonating another user's access token.
*   `ProcessSession`: the session related to the process, available every time an event has a process.

For both prefixes, the following fields are available.

Field name

Description

`SourceHostname`

Hostname of the session's source.

`SourceIp`

IP address of the session's source.

`SourcePort`

Port number of the session's source.

`TargetUsername`

Username of the session.

`TargetDomain`

Domain name of the session.

`LogonType`

Type of the session (Windows enum from 0 - System to 13 - CachedUnlock)

`AuthenticationPackage`

Name of the authentication package that was used for the logon authentication process.

Linux events
------------

Note

The Sigma engine exposes [additional fields about the related process of an event](#process-extra-fields-linux) as well as [fields related to the agent](#additional-fields-related-to-the-agent).

#### Process events

##### Process creation

Event triggered when a new process is executed, which happens when the `execve` system call is executed.

`logsource:     product: linux     category: process_creation`

Field name

Description

`Image`

Path of the process image.

`CommandLine`

Process command line.

`CurrentDirectory`

Directory under which the process image was executed.

`md5`

MD5 of the process image.

`sha1`

SHA1 of the process image.

`sha256`

SHA256 of the process image.

`User`

Alias of `RealUsername`.

`RealUsername`

Name of the real user (`uid`) of the newly created process.

`EffectiveUsername`

Name of the effective user (`euid`) of the newly created process.

`SavedUsername`

Name of the saved user (`suid`) of the newly created process.

`RealGroup`

Name of the real group (`gid`) that created this process.

`EffectiveGroup`

Name of the effective user (`egid`) that created the process.

`SavedGroup`

Name of the saved user (`sgid`) that created the process.

`ParentImage`

Path of the parent process image.

`ParentCommandLine`

Parent process command line.

`GrandparentImage`

Path of the grandparent process image.

`GrandparentCommandLine`

Grandparent process command line.

`Ancestors`

The process' ancestors images joined together by a `|` (e.g `/usr/bin/parent|/usr/bin/grandparent|/usr/bin/grandgrand...`)

`MemfdName`

Name of the memfd used to execute the process filelessly.

##### Process ptrace

Event triggered when a process uses `ptrace`.

`logsource:     product: linux     category: process_ptrace`

Field name

Description

`SourceImage`

Path of the process calling ptrace.

`SourceProcessId`

PID of the process calling ptrace.

`TargetImage`

Path of the process that is the target of the ptrace operation.

`TargetProcessId`

PID of the process that is the target of the ptrace operation.

`PtraceRequest`

Operation to be performed on the target process.

`PtraceRequestStr`

Operation to be performed on the target process, as a string (example: `PTRACE_POKETEXT`).

`PtraceOptions`

Optional flags, only for SEIZE and SETOPTIONS operations.

`PtraceOptionsStr`

Optional flags, only for SEIZE and SETOPTIONS operations, as a string (example: `PTRACE_O_EXITKILL|PTRACE_O_TRACEFORK`).

`TargetIsChild`

`true` if the target process is the direct child of the source process (calling ptrace).

##### cBPF load

Event triggered when a process loads and attaches a "classic" BPF filter to a socket with `SO_ATTACH_FILTER`.

`logsource:     product: linux     category: bpf_event     kind: cbpf_load`

Field name

Description

`Image`

Path of the process that loaded the cBPF program.

`Kind`

Kind of the operation. Set to 'cbpf\_load' for classic BPF program load.

`InstructionCount`

Number of cBPF instructions loaded.

`BpfDump`

First 128 bytes of the cBPF program loaded. (example: `0x01234567`)

##### eBPF load

Event triggered when a process loads an eBPF program (when the program goes through the verifier)

`logsource:     product: linux     category: bpf_event     kind: ebpf_load`

Field name

Description

`Image`

Path of the process that loaded the eBPF program.

`Kind`

Kind of the operation. Set to 'ebpf\_load' for extended BPF program load.

`InstructionCount`

Number of eBPF instructions loaded.

`BpfDump`

First 128 bytes of the eBPF program loaded. (example: `0x01234567`)

`ProgramLoaded`

Name of the eBPF program. It is a 16 character string.

`ProgramType`

Type of the eBPF program loaded.

`ProgramTypeStr`

String representation of the field `ProgramType` (example: `BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_TRACEPOINT`, etc.)

`ProgramFlags`

Flags for all sorts of purposes.

`ProgramFlagsStr`

String representation of the field `ProgramFlags` (example: `BPF_F_STRICT_ALIGNMENT`, `BPF_F_TEST_STATE_FREQ`, etc.)

`ExpectedAttachType`

Attach type the user expects to use when attaching the program.

`ExpectedAttachTypeStr`

String representation of the field `ExpectedAttachType` (example: `BPF_LSM_CGROUP`, `BPF_TCX_EGRESS`, etc.)

##### eBPF attach

Event triggered when a process attaches an eBPF program to a tracepoint or kprobe perf event.

`logsource:     product: linux     category: bpf_event     kind: ebpf_attach`

Field name

Description

`Image`

Path of the process that attached the eBPF program.

`Kind`

Kind of the operation. Set to 'ebpf\_attach' for extended BPF program attach.

`InstructionCount`

Number of eBPF instructions loaded.

`BpfDump`

First 128 bytes of the attached eBPF program. (example: `0x01234567`)

`ProgramLoaded`

Name of the eBPF program. It is a 16 character string.

`ProgramType`

Type of the eBPF program attached.

`ProgramTypeStr`

String representation of the field `ProgramType` (example: `BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_TRACEPOINT`, etc.)

`FunctionHooked`

Function hooked by the eBPF program. It can be a KPROBE (ex: `do_unlinkat`) or a TRACEPOINT (ex: `syscalls:sys_enter_openat`) depending of the program type.

#### Image loaded

Event triggered when a library (_so_) is loaded.

`logsource:     product: linux     category: library_event`

Field name

Description

`Image`

Path of the process that loaded the image.

`ImageLoaded`

Path of the image loaded.

`ImageSize`

Size of the memory allocated to map the library.

`Hashes`

Hashes of the library file.

#### Filesystem events

##### File read/written/removed

File read/write event triggered when a file is opened with the read or write permissions.

File remove event triggered when a file is deleted from the filesystem through the `unlink` or `rmdir` system calls.

Note that this event requires eBPF support.

`logsource:     product: linux     category: filesystem_event`

Field name

Description

`Kind`

Kind of the operation. One of `read`, `write`, `remove`.

`Path`

Path to the file being created, read, written or removed.

##### File renamed

Event triggered when a file is renamed through the `rename` system call.

Note that this event requires eBPF support.

`logsource:     product: linux     category: filesystem_event`

Field name

Description

`Kind`

Kind of the operation. `rename`.

`Path`

Old path of the file being renamed.

`TargetPath`

New path of the file being renamed.

##### File permission changed

Event triggered when a file permission change happens through the `chmod` system call.

Note that this event requires eBPF support.

`logsource:     product: linux     category: filesystem_event`

Field name

Description

`Kind`

Kind of the operation. `chmod`.

`Path`

Path to the file whose permissions are changed.

`Mode`

The new mode of the file, in octal form (e.g. `0601`).

`PrettyMode`

The new mode of the file, in rwx form (e.g. for mode 0601: `rw------x`).

`OldMode`

The old mode of the file, in octal form (e.g. `0601`).

`PrettyOldMode`

The old mode of the file, in rwx form (e.g. for mode 0601: `rw------x`).

##### File owner changed

Event triggered when a file ownership change happens through the `chown` system call.

Note that this event requires eBPF support.

`logsource:     product: linux     category: filesystem_event`

Field name

Description

`Kind`

Kind of the operation. `chown`.

`Path`

Path to the file whose owner is being changed.

`Uid`

ID of the user owning the file after the operation.

`Gid`

ID of the group owning the file after the operation.

##### Link/symlink created

Event triggered when a `link` or `symlink` system call is executed.

Note that this event requires eBPF support.

`logsource:     product: linux     category: filesystem_event`

Field name

Description

`Kind`

Kind of the operation. One of `symlink` or `hardlink`.

`Path`

Path to the new symlink file.

`TargetPath`

Target of the symlink.

##### Written executable

Event triggered when a file executable is written.

`logsource:     product: linux     category: filesystem_event`

Field name

Description

`Kind`

Kind of the operation. `written_executable`.

`Path`

Path to the executable file written to disk.

`FileMd5`

MD5 hash of the executable file written to disk.

`FileSha1`

SHA1 hash of the executable file written to disk.

`FileSha256`

SHA256 hash of the executable file written to disk.

`FileSize`

Size in bytes of the executable file written to disk.

#### Network events

##### Network connection

Event triggered when a network connection is created. This can either be an incoming connection (in case of a server listening on a port) or an outgoing connection.

`logsource:     product: linux     category: network_connection`

Field name

Description

`DestinationIp`

Destination IP.

`DestinationNames`

DNS names used in order to resolve the destination IP address, if done so prior to the network connection.

`DestinationHostname`

Alias of DestinationNames

`DestinationIsIpv6`

`true` if the destination IP is an IPv6, otherwise `false` (**This is matched as a string**).

`DestinationPort`

Destination port number.

`Protocol`

Protocol being used for the network connection. (`tcp`/`udp` or empty string if not known)

`ProtocolNumber`

IANA assigned protocol number being used for the network connection (tcp = 6, udp = 17, ...). See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

`Initiated`

Indicates if the process initiated the network connection.

`SourceIp`

Source IP.

`SourceIsIpv6`

`true` if the source IP is an IPv6, otherwise `false` (**This is matched as a string**).

`SourcePort`

Source port number.

##### Network listen

Event triggered when a `listen` system call is executed.

Note that this event requires eBPF support.

`logsource:     product: linux     category: network_listen`

Field name

Description

`Address`

IP address the network server is bound to.

`Port`

Port of the network server.

##### Raw socket

Event triggered when a raw socket is created through the `socket` system call. A raw socket is defined as either:

*   A socket with `AF_INET` family and socket type `SOCK_RAW` or `SOCK_PACKET`
*   A socket with `AF_PACKET` family with socket type `SOCK_RAW` or `SOCK_DGRAM`

Note that this event requires eBPF support.

`logsource:     product: linux     category: network_rawsocket`

Field name

Description

`SocketFamily`

Integer value of the socket family. See [the kernel source](https://elixir.bootlin.com/linux/v6.4.8/source/include/linux/socket.h#L187) for possible values.

`SocketType`

Integer value for the type of the socket. See [the kernel source](https://elixir.bootlin.com/linux/v6.4.8/source/include/linux/net.h#L63) for possible values.

`SocketProtocol`

Integer value of the protocol of the socket.

#### Login

Event triggered when a user authenticates on the machine. This is detected by monitoring calls to PAM, which allows seeing local user logins, remote connections and local user elevation through tools such as `sudo`.

Note that this event requires eBPF support.

`logsource:     product: linux     category: login_event`

Field name

Description

`Success`

`true` if the authentication was successful, `false` otherwise.

`Kind`

Identifies how the authentication occurred. Can be one of `authenticate` or `session_open`.

`TargetUid`

UID of the user being logged into.

`TargetUsername`

Name of the user being logged into.

`TargetGid`

Group ID (`gid`) of the user being logged into.

`TargetGroup`

Group name of the user being logged into.

`SourceUsername`

Username of the process causing the login. When using sudo, this will be the name of the user invoking sudo. In case of remote authentication through ssh, this will be the username of the sshd service.

`SourceHost`

IP of the user logging in, in case of remote logins, such as through ssh.

`Tty`

Path to the terminal device that initiated the authentication (for instance, `/dev/tty1`)

#### Logout

Event triggered when a user disconnects on the machine. This is detected by monitoring calls to PAM.

Note that this event requires eBPF support.

`logsource:     product: linux     category: logout_event`

Field name

Description

`TargetUid`

UID of the user logging out.

`TargetUsername`

Name of the user logging out.

`TargetGid`

Group ID (`gid`) of the user logging out.

`TargetGroup`

Group name of the user logging out.

`SourceUsername`

Username of the process that had caused the authentication.

`SourceHost`

IP the user logging out, in case of remote logins, such as through ssh.

`Tty`

Path to the terminal device that initiated the authentication (for instance, `/dev/tty1`)

#### Url request

Event triggered when a process requests an URL.

`logsource:     product: linux     category: url_request`

Field name

Description

`RequestUrl`

URL to the resource requested.

`RequestUrlScheme`

Scheme of the URL.

`RequestUrlHost`

Host where the resource is located.

`RequestUrlPort`

Port used to access the resource.

`RequestUrlPath`

Path of the resource on the targeted host.

`RequestUrlQueryParams`

Query parameters used to access the resource.

`RequestUrlUsername`

Username used to access the resource.

`RequestUrlPassword`

Password used to access the resource.

#### DNS resolution

Event triggered when a process resolves a domain name.

Note that this event requires eBPF support.

`logsource:     product: linux     category: dns_query`

Field name

Description

`QueryName`

Requested domain name.

`QueryType`

The DNS query type: `A`, `AAAA`, `TXT`, ...

`QueryStatusCategory`

Status of the query: `success`, `connection_error`, `timeout`, `name_not_found`, `record_not_found` or `invalid_reply`.

`IpAddresses`

The addresses that have been returned by the resolution.  
This may be empty, for example for TXT requests.

`TextRecords`

The text records that have been returned by a TXT query.  
This is empty for all other types of requests.

`Image`

Path of the process that initiated the DNS resolution.

`User`

The user associated to the process that initiated the DNS resolution.

#### Extra process fields

Those fields are available on all events.

Field name

Description

`ProcessName`

Name of the process that caused the event.

`ProcessImage`

Path to the image of the process that caused the event.

`ProcessCommandLine`

Commandline of the process that caused the event.

`ProcessCurrentDirectory`

Current directory under which the process that caused the event was started.

`ProcessMd5`

MD5 of the image of the process that caused the event.

`ProcessSha1`

SHA1 of the image of the process that caused the event.

`ProcessSha256`

SHA256 of the image of the process that caused the event.

`ProcessSize`

Size of the image of the process that caused the event (in bytes).

`ProcessAncestors`

The ancestors of the process that caused the event, joined together by a `|` (e.g `/usr/bin/parent|/usr/bin/grandparent|/usr/bin/grandgrand...`)

`ProcessUser`

Alias of `ProcessRealUsername`

`ProcessRealUsername`

Name of the real user (`uid`) of the newly created process.

`ProcessEffectiveUsername`

Name of the effective user (`euid`) of the newly created process.

`ProcessSavedUsername`

Name of the saved user (`suid`) of the newly created process.

`ProcessRealGroup`

Name of the real group (`gid`) that created this process.

`ProcessEffectiveGroup`

Name of the effective user (`egid`) that created the process.

`ProcessSavedGroup`

Name of the saved user (`sgid`) that created the process.

`ProcessMemfdName`

Name of the memfd used to execute the process filelessly.

Equivalent fields using the `ProcessParent` and `ProcessGrandparent` prefixes are also available, respectively referencing the parent and grandparent processes.

MacOS events
------------

Note

The Sigma engine exposes [additional fields about the related process of an event](#process-extra-fields-macos) as well as [fields related to the agent](#additional-fields-related-to-the-agent).

#### Process creation

Event triggered when a new process is executed, which happens when the `execve` system call is executed.

`logsource:     product: macos     category: process_creation`

Field name

Description

`Image`

Path of the process image.

`CommandLine`

Process command line.

`CurrentDirectory`

Directory under which the process image was executed.

`User`

Alias of `RealUsername`.

`ParentImage`

Path of the parent process image.

`ParentCommandLine`

Parent process command line.

`GrandparentImage`

Path of the grandparent process image.

`GrandparentCommandLine`

Grandparent process command line.

`md5`

MD5 of the process image.

`sha1`

SHA1 of the process image.

`sha256`

SHA256 of the process image.

`Ancestors`

The process' ancestors images joined together by a `|` (e.g `/usr/bin/parent|/usr/bin/grandparent|/usr/bin/grandgrand...`)

`RealUsername`

Name of the real user (`uid`) of the newly created process.

`EffectiveUsername`

Name of the effective user (`euid`) of the newly created process.

`RealGroup`

Name of the real group (`gid`) that created this process.

`EffectiveGroup`

Name of the effective user (`egid`) that created the process.

`CdHash`

CDHash of the process.

`Signed`

`true` if the process loaded is signed, otherwise `false` (**This is matched as a string**)

`SignatureTeamId`

TeamID responsible for signing the binary.

`SignatureSigningId`

Signing identifier of the binary (e.g `com.apple.MRT`).

`CodesigningFlags`

Code signature flags as an integer.

`CodesigningFlagsStr`

Code signature flags as a string. (example: `CS_VALID|CS_SIGNED`)

`IsPlatformBinary`

`true` if the process is part of the operating system, otherwise `false` (**This is matched as a string**)

#### Image loaded

Event triggered when a library (_Dylib_) is loaded.

`logsource:     product: macos     category: library_event`

Field name

Description

`Image`

Path of the process that loaded the image.

`ImageLoaded`

Path of the image loaded.

#### Filesystem events

##### File created/read/written/removed

File create event triggered when a file is created.

File read/write event triggered when a file is opened with the read or write permissions.

File remove event triggered when a file is deleted from the filesystem through the `unlink` or `rmdir` system calls.

`logsource:     product: macos     category: filesystem_event`

Field name

Description

`Kind`

Kind of the operation. One of `create`, `read`, `write`, `remove`.

`Path`

Path to the file being created, read, written or removed.

##### File renamed

Event triggered when a file is renamed through the `rename` system call.

`logsource:     product: macos     category: filesystem_event`

Field name

Description

`Kind`

Kind of the operation. `rename`.

`Path`

Old path of the file being renamed.

`TargetPath`

New path of the file being renamed.

##### File permission changed

Event triggered when a file permission change happens through the `chmod` system call.

`logsource:     product: macos     category: filesystem_event`

Field name

Description

`Kind`

Kind of the operation. `chmod`.

`Path`

Path to the file whose permissions are changed.

`Mode`

The new mode of the file, in octal form (e.g. `0601`).

`PrettyMode`

The new mode of the file, in rwx form (e.g. for mode 0601: `rw------x`).

`OldMode`

The old mode of the file, in octal form (e.g. `0601`).

`PrettyOldMode`

The old mode of the file, in rwx form (e.g. for mode 0601: `rw------x`).

##### File owner changed

Event triggered when a file ownership change happens through the `chown` system call.

`logsource:     product: macos     category: filesystem_event`

Field name

Description

`Kind`

Kind of the operation. `chmod`.

`Path`

Path to the file whose owner is being changed.

`Uid`

ID of the user owning the file after the operation.

`Gid`

ID of the group owning the file after the operation.

##### Link/symlink created

Event triggered when a `link` or `symlink` system call is executed.

`logsource:     product: macos     category: filesystem_event`

Field name

Description

`Kind`

Kind of the operation. One of `symlink` or `hardlink`.

`Path`

Path to the new symlink file.

`TargetPath`

Target of the symlink.

##### Written executable

Event triggered when a file executable is written.

`logsource:     product: linux     category: filesystem_event`

Field name

Description

`Kind`

Kind of the operation. `written_executable`.

`Path`

Path to the executable file written to disk.

`FileMd5`

MD5 hash of the executable file written to disk.

`FileSha1`

SHA1 hash of the executable file written to disk.

`FileSha256`

SHA256 hash of the executable file written to disk.

`FileSize`

Size in bytes of the executable file written to disk.

#### Network events

##### Network connection

Event triggered when a network connection is created.

`logsource:     product: macos     category: network_connection`

Field name

Description

`DestinationPort`

Destination port number.

`DestinationIp`

Destination IP.

`DestinationNames`

DNS names used in order to resolve the destination IP address, if done so prior to the network connection.

`DestinationHostname`

Alias of DestinationNames

`DestinationIsIpv6`

`true` if the destination IP is an IPv6, otherwise `false` (**This is matched as a string**).

`Image`

Path of the process that initiated the network connection.

`Initiated`

Indicates if the process initiated the network connection.

`Protocol`

Protocol being used for the network connection. (`tcp` / `udp` or empty string if not known)

`ProtocolNumber`

IANA assigned protocol number being used for the network connection (tcp = 6, udp = 17, ...). See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

`SourcePort`

Source port number.

`SourceIp`

Source IP.

`SourceIsIpv6`

`true` if the source IP is an IPv6, otherwise `false` (**This is matched as a string**).

`User`

The user associated to the process that initiated the network connection.

#### Login

Event triggered when a user login on the machine.

`logsource:     product: macos     category: login_event`

Field name

Description

`Success`

`true` if the authentication was successful, `false` otherwise.

`LoginMethod`

Identifies the method of authentication. Can be one of `open_directory`, `touch_id`, `token`, `auto_unlock`, `session_login`, `session_unlock`, `screensharing_attach`, `openssh_login` or `login_login`.

`TargetUsername`

Name of the user being logged into.

`SourceAddress`

IP address of the machine from which the logon attempt was performed.

#### Logout

Event triggered when a user logout on the machine.

`logsource:     product: macos     category: logout_event`

Field name

Description

`TargetUsername`

Name of the user logging out.

`LogoutMethod`

Identifies the method of logout. Can be one of `session_logout`, `session_lock`, `openssh_logout`, `login_logout` or `screensharing_detach`.

`SourceAddress`

IP address of the machine from which the logout attempt was performed.

#### Extra process fields

Those fields are available on all events.

Field name

Description

`ProcessImage`

Path of the process image.

`ProcessCommandLine`

Process command line.

`ProcessCurrentDirectory`

Directory under which the process image was executed.

`ProcessUser`

Alias of `RealUsername`.

`ProcessParentImage`

Path of the parent process image.

`ProcessParentCommandLine`

Parent process command line.

`ProcessGrandparentImage`

Path of the grandparent process image.

`ProcessGrandparentCommandLine`

Grandparent process command line.

`ProcessMd5`

MD5 of the process image.

`ProcessSha1`

SHA1 of the process image.

`ProcessSha256`

SHA256 of the process image.

`ProcessAncestors`

The process' ancestors images joined together by a `|` (e.g `/usr/bin/parent|/usr/bin/grandparent|/usr/bin/grandgrand...`)

`ProcessRealUsername`

Name of the real user (`uid`) of the newly created process.

`ProcessEffectiveUsername`

Name of the effective user (`euid`) of the newly created process.

`ProcessRealGroup`

Name of the real group (`gid`) that created this process.

`ProcessEffectiveGroup`

Name of the effective user (`egid`) that created the process.

`ProcessCdHash`

CDHash of the process.

`ProcessSigned`

`true` if the process loaded is signed, otherwise `false` (**This is matched as a string**)

`ProcessSignatureTeamId`

TeamID responsible for signing the binary.

`ProcessSignatureSigningId`

Signing identifier of the binary (e.g `com.apple.MRT`).

`ProcessCodesigningFlags`

Code signature flags as an integer.

`ProcessCodesigningFlagsStr`

Code signature flags as a string. (example: `CS_VALID|CS_SIGNED`)

`ProcessIsPlatformBinary`

`true` if the process is part of the operating system, otherwise `false` (**This is matched as a string**)

Equivalent fields using the `ProcessParent` and `ProcessGrandparent` prefixes are also available, respectively referencing the parent and grandparent processes.

Additional fields related to the agent
--------------------------------------

These fields are available on all events and give information about each agent.

Field name

Description

`AgentId`

The agent ID.

`AgentVersion`

The agent version.

`AgentOsType`

The agent operating system type, one of \[`windows`, `linux`, `macos`\].

Field name

Description

`AgentAdditionalInfo1`

The additional info 1 set in the agent config.

`AgentAdditionalInfo2`

The additional info 2 set in the agent config.

`AgentAdditionalInfo3`

The additional info 3 set in the agent config.

`AgentAdditionalInfo4`

The additional info 4 set in the agent config.

`AgentDomain`

The agent netbios domain name (Windows only).

`AgentDomainName`

The agent netbios domain name (Windows only).

`AgentDnsDomainName`

The agent DNS domain name.

`AgentHostname`

The agent hostname.

`AgentOsProductType`

The Windows product type, one of \[`workstation`, `server`, `server_dc`, `unknown`\] (Windows only).

`AgentOsVersion`

The Windows version in the following format `major.minor.build` (Windows only).

`AgentDistroid`

The linux distro name (Linux only).

Field name

Description

`AgentIpAddress`

The IP used by the agent to connect to the manager.

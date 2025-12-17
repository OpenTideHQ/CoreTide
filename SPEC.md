# HarfangLab Sigma Logsource Specification

This document defines the authoritative logsource and field specifications for HarfangLab Sigma rules,
extracted from IMPLEMENTATION.md.

## Windows Events (product: windows)

### Category: process_creation
Event triggered when a process is created.

**Fields:** CommandLine, Company, CurrentDirectory, Description, GrandparentImage, GrandparentIntegrityLevel, GrandparentCommandLine, Image, ImageDriveType, Imphash, IntegrityLevel, InternalName, FileVersion, LegalCopyright, LogonId, md5, OriginalFileName, ParentImage, ParentCommandLine, ParentIntegrityLevel, Product, ProductVersion, sha1, sha256, User, UserSID, Signed, Signature, SignatureStatus, Ancestors, StackTrace, MinimalStackTrace, LnkLinked, LnkPath, LnkDriveType, IsFileObjectTransacted, AuthentihashSha1, AuthentihashSha256

### Category: network_connection
Event triggered when a network connection is created.

**Fields:** DestinationPort, DestinationIp, DestinationNames, DestinationHostname, DestinationIsIpv6, Image, Initiated, Protocol, ProtocolNumber, SourcePort, SourceIp, SourceIsIpv6, User, ConnectionGuid

### Category: network_dpi
Event triggered when network connection protocols are identified (HTTP, TLS, SSH).

**Fields:** DestinationPort, DestinationIp, DestinationNames, DestinationHostname, DestinationIsIpv6, Image, Initiated, Protocol, ProtocolNumber, SourcePort, SourceIp, SourceIsIpv6, User, ConnectionGuid, IncomingApplicationProtocol, OutgoingApplicationProtocol, OutgoingTlsVersion, OutgoingTlsSni, OutgoingTlsAlpn, OutgoingTlsJa3, OutgoingTlsJa3n, OutgoingTlsJa4, IncomingTlsVersion, IncomingTlsAlpn, IncomingTlsJa3s, IncomingTlsCertificateThumbprintSha1, IncomingTlsCertificateThumbprintSha256, IncomingTlsCertificateDisplayName, IncomingTlsCertificateIssuerName, OutgoingHttpRequestVersion, OutgoingHttpRequestContentType, OutgoingHttpRequestContentLength, OutgoingHttpRequestMethod, OutgoingHttpRequestPath, OutgoingHttpRequestUserAgent, OutgoingHttpRequestHost, OutgoingHttpRequestReferer, OutgoingHttpRequestCookies, IncomingHttpResponseVersion, IncomingHttpResponseContentType, IncomingHttpResponseContentLength, IncomingHttpResponseCode, IncomingHttpResponseLastModified, IncomingHttpResponseServer, OutgoingSshProtoVersion, OutgoingSshSoftwareVersion, OutgoingSshBannerComments, IncomingSshProtoVersion, IncomingSshSoftwareVersion, IncomingSshBannerComments, IncomingSshServerPubkeyAndCertAlgo, IncomingSshServerFingerprint

### Category: network_close
Event triggered when a network connection is closed.

**Fields:** DestinationPort, DestinationIp, DestinationNames, DestinationHostname, DestinationIsIpv6, Image, Initiated, Protocol, ProtocolNumber, SourcePort, SourceIp, SourceIsIpv6, User, ConnectionGuid, ConnectionSuccessful, IncomingBytesCount, OutgoingBytesCount, IncomingApplicationProtocol, OutgoingApplicationProtocol

### Category: driver_load
Event triggered when a driver is loaded by the system.

**Fields:** ImageLoaded, Signed, Signature, SignatureStatus, DriverMd5, DriverSha1, DriverSha256, Company, Description, FileVersion, InternalName, LegalCopyright, OriginalFileName, Product, ProductVersion, AuthentihashSha1, AuthentihashSha256

### Category: library_event
Event triggered when a native or managed (.NET) library is loaded.

**Fields:** Company, Description, FileVersion, InternalName, Image, ImageLoaded, ImageLoadedDriveType, LegalCopyright, OriginalFileName, Product, ProductVersion, Signed, Signature, SignatureStatus, StackTrace, MinimalStackTrace, AppDomainID, AssemblyFlags, AssemblyFlagsStr, FullyQualifiedAssemblyName, AssemblyName, AssemblyVersion, AssemblyCulture, AssemblyToken, ModuleFlags, ModuleFlagsStr, ModuleILPath, ModuleNativePath, ManagedPdbBuildPath, NativePdbBuildPath, LibraryType, AuthentihashSha1, AuthentihashSha256

### Category: remote_thread
Event triggered when a remote thread is created.

**Fields:** NewThreadId, SourceProcessId, SourceImage, StartAddress, StartModule, StartFunction, TargetProcessId, StackTrace, MinimalStackTrace

### Category: injected_thread
Event triggered when an injected thread is created.

**Fields:** TargetProcessId, TargetImage, SourceProcessId, SourceImage, NewThreadId, StartAddress, RegionBaseAddress, RegionSize, RegionStateHex, RegionState, RegionProtectionHex, RegionProtection, RegionTypeHex, RegionType, RegionAllocationBase, RegionAllocationProtectionHex, RegionAllocationProtection, RegionAllocationSize, RegionMappedFile, RegionDump, ThreadDump, StackTrace, MinimalStackTrace, IsRemoteThread

### Category: raw_device_access
Event triggered when a process makes a raw device access.

**Fields:** Image, Device, DesiredAccess, DesiredAccessStr, StackTrace, MinimalStackTrace

### Category: process_access
Event triggered when a process is accessed.

**Fields:** CallTrace, StackTrace, MinimalStackTrace, GrantedAccess, GrantedAccessStr, SourceImage, TargetImage, TargetProcessCommandLine, TargetProcessCompany, TargetProcessCurrentDirectory, TargetProcessDescription, TargetProcessFileVersion, TargetProcessGrandparentCommandLine, TargetProcessGrandparentImage, TargetProcessGrandparentIntegrityLevel, TargetProcessImage, TargetProcessImphash, TargetProcessIntegrityLevel, TargetProcessInternalName, TargetProcessLegalCopyright, TargetProcessLogonId, TargetProcessMd5, TargetProcessName, TargetProcessOriginalFileName, TargetProcessParentCommandLine, TargetProcessParentImage, TargetProcessParentIntegrityLevel, TargetProcessPETimestamp, TargetProcessProduct, TargetProcessProductVersion, TargetProcessSha1, TargetProcessSha256, TargetProcessSignature, TargetProcessSignatureStatus, TargetProcessSigned, TargetProcessSignatureRootDisplayName, TargetProcessSignatureRootIssuerName, TargetProcessSignatureRootSerialNumber, TargetProcessSignatureRootThumbprint, TargetProcessSignatureSignerDisplayName, TargetProcessSignatureSignerIssuerName, TargetProcessSignatureSignerSerialNumber, TargetProcessSignatureSignerThumbprint, TargetProcessSize, TargetProcessUser, TargetProcessUserSID

### Category: process_duplicate_handle
Event triggered when a handle targeting a process is duplicated.

**Fields:** CallerImage, CallerProcessId, SourceImage, SourceProcessId, DestinationImage, DestinationProcessId, TargetImage, TargetProcessId, GrantedAccess, GrantedAccessStr, CallTrace, StackTrace, MinimalStackTrace, CallerIsDestination

### Category: process_tampered
Event triggered when a process is altered.

**Fields:** Image, Type

### Category: etwti_ntallocatevirtualmemory
Event triggered when a process calls NtAllocateVirtualMemory.

**Fields:** ProcessId, ThreadId, Image, TargetProcessId, TargetImage, BaseAddress, RegionSize, AllocationType, AllocationTypeStr, ProtectionMask, ProtectionMaskStr, IsRemote

### Category: registry_event
Event triggered for registry operations.

**Fields:** EventType, Image, TargetObject, Details, PreviousDetails, DetailsAdded, DetailsRemoved, IsPreviousDetailsSet, ValueType, NewName, HivePath, StackTrace, MinimalStackTrace

### Category: named_pipe_creation
Event triggered when a named pipe is created.

**Fields:** PipeName, NamedPipeType, InboundQuota, OutboundQuota, MaximumInstances, DesiredAccess, Kind, StackTrace, MinimalStackTrace

### Category: named_pipe_connection
Event triggered when a process connects to a named pipe.

**Fields:** PipeName, Kind, StackTrace, MinimalStackTrace, TargetProcessCommandLine, TargetProcessCompany, TargetProcessCurrentDirectory, TargetProcessDescription, TargetProcessFileVersion, TargetProcessGrandparentCommandLine, TargetProcessGrandparentImage, TargetProcessGrandparentIntegrityLevel, TargetProcessImage, TargetProcessImphash, TargetProcessIntegrityLevel, TargetProcessInternalName, TargetProcessLegalCopyright, TargetProcessLogonId, TargetProcessMd5, TargetProcessName, TargetProcessOriginalFileName, TargetProcessParentCommandLine, TargetProcessParentImage, TargetProcessParentIntegrityLevel, TargetProcessPETimestamp, TargetProcessProduct, TargetProcessProductVersion, TargetProcessSha1, TargetProcessSha256, TargetProcessSignature, TargetProcessSignatureStatus, TargetProcessSigned, TargetProcessSignatureRootDisplayName, TargetProcessSignatureRootIssuerName, TargetProcessSignatureRootSerialNumber, TargetProcessSignatureRootThumbprint, TargetProcessSignatureSignerDisplayName, TargetProcessSignatureSignerIssuerName, TargetProcessSignatureSignerSerialNumber, TargetProcessSignatureSignerThumbprint, TargetProcessSize, TargetProcessUser, TargetProcessUserSID

### Category: file_create
Event triggered when a file is created.

**Fields:** Path, TargetFilename, FileName, FileDriveType, StackTrace, MinimalStackTrace

### Category: file_read
Event triggered when a file is read.

**Fields:** Path, TargetFilename, FileName, FileDriveType, StackTrace, MinimalStackTrace

### Category: file_write
Event triggered when a file is written.

**Fields:** Path, TargetFilename, FileName, FileDriveType, FirstBytes, StackTrace, MinimalStackTrace

### Category: file_rename
Event triggered when a file is renamed.

**Fields:** Path, TargetPath, FileDriveType, StackTrace, MinimalStackTrace

### Category: file_remove
Event triggered when a file is removed.

**Fields:** Path, TargetFilename, FileName, FileDriveType, StackTrace, MinimalStackTrace

### Category: file_shadowcopy
Event triggered when a process accesses a file inside a Volume Shadow Copy.

**Fields:** Path, TargetFilename, FileName, FileDriveType, CreateOptions, CreateOptionsStr, CreateDisposition, CreateDispositionStr, StackTrace, MinimalStackTrace

### Category: file_download
Event triggered when a file is downloaded.

**Fields:** Path, TargetFilename, FileName, FileDriveType, Kind, SourceUrl, SourceUrlScheme, SourceUrlHost, SourceUrlPort, SourceUrlPath, SourceUrlQueryParams, SourceUrlUsername, SourceUrlPassword, UrlZone, ZoneId, HostUrl, ReferrerUrl, HostIpAddress, SourceIpAddress, AppZoneId, LastWriterPackageFamilyName, StackTrace, MinimalStackTrace

### Category: powershell_event
Event triggered when a PowerShell command is executed.

**Fields:** PowershellCommand, ScriptBlockText, PowershellScriptPath, Path, Signed, Signature, SignatureStatus, Md5, Sha1, Sha256, ScriptSize, ScriptNumberOfLines

### Category: url_request
Event triggered when a process requests a URL.

**Fields:** RequestUrl, RequestUrlVerb, RequestUrlScheme, RequestUrlHost, RequestUrlPort, RequestUrlPath, RequestUrlQueryParams, RequestUrlUsername, RequestUrlPassword, UserAgent

### Category: login_event
Event triggered when a user logs in (Windows).

**Fields:** Success, TargetUsername, TargetDomainName, TargetSid, SourceUsername, SourceDomainName, SourceSid, AuthenticationPackageName, WorkstationName, IpAddress, IpPort, Status, SubStatus

### Category: logout_event
Event triggered when a user disconnects (Windows).

**Fields:** TargetUsername, TargetDomainName, TargetSid

### Category: dns_query
Event triggered when a process resolves a domain name.

**Fields:** QueryName, QueryType, QueryStatusCategory, IpAddresses, TextRecords, QueryStatus, QueryResults, Image, User

### Category: user
Event triggered when a user is created/modified/disabled/deleted.

**Fields:** TargetUserName, TargetDomainName, TargetUserID, SourceUserID, SourceUserName, SourceDomainName, SourceLogonID, SourcePrivilegelist, TargetSAMName, TargetDisplayName, TargetPrincipalName, TargetHomeDirectory, TargetHomePath, TargetScriptPath, TargetProfilePath, TargetUserWorkstations, TargetPasswordLastSet, TargetAccountExpires, TargetPrimaryGroupId, TargetAllowedToDelegateTo, UserAccountControl, SIDHistory, NewUserName, OperationType

### Category: group
Event triggered for group management operations.

**Fields:** GroupName, DomainName, GroupID, SourceUserID, SourceUserName, SourceDomainName, SourceLogonID, SourcePrivilegelist, TargetSAMName, SIDHistory, OldGroupType, NewGroupType, TargetMemberName, TargetMemberID, OperationType

### Category: amsi_scan
Event triggered when a process asks for an AMSI scan.

**Fields:** AppName, ContentName, TextPayload

### Category: service
Event triggered for Windows service operations.

**Fields:** ServiceName, IsRemote, Image, ServiceStartType, ServiceStartTypeStr, ServiceCommandLine, ServiceType, ServiceTypeStr, ServiceAccount, ControlCode, ControlCodeStr, SourceUserID, SourceUserName, SourceDomainName, OperationType

### Category: scheduled_task
Event triggered for scheduled task operations.

**Fields:** TaskName, TaskPath, Image, SourceUserName, SourceUserId, SourceDomainName, IsRemote, TaskContent, SourceLogonId, ClientProcessId, RpcCallLocality, SpawnedProcessPid, ProcessPriority, OperationType, FirstActionCommandLine, NumberOfTriggers, NumberOfActions, TaskCommands, PrincipalUserId, LogonType, RunLevel, PrincipalGroupId, TaskEnabled, TaskHidden, ExecutionTimeLimit, TaskPriority

### Category: eventlog
Generic syntax to access Windows EventLogs.

**Fields:** LogName, EventID, Provider, Message, Computer, Level, Task, Opcode, Keywords

### Category: win32k_getasynckeystate
Triggered when a process uses the GetAsyncKeyState API.

**Fields:** ProcessId, Image, MsSinceLastKeyEvent, BackgroundCallCount

### Category: win32k_registerrawinputdevices
Triggered when a process uses the RegisterRawInputDevices API.

**Fields:** ProcessId, Image, UsagePage, UsagePageStr, ReturnValue, UsageId, UsageIdStr, WindowsCount, VisibleWindowsCount, StartModuleName, Flags, FlagsStr, ThreadInfoFlags, StartAddressProtection

### Category: win32k_setwindowshookex
Triggered when a process uses the SetWindowsHookEx API.

**Fields:** ProcessId, Image, HookLibrary, HookFunction, ReturnValue, FilterType, FilterTypeStr

## Linux Events (product: linux)

### Category: process_creation
**Fields:** Image, CommandLine, CurrentDirectory, md5, sha1, sha256, User, RealUsername, EffectiveUsername, SavedUsername, RealGroup, EffectiveGroup, SavedGroup, ParentImage, ParentCommandLine, GrandparentImage, GrandparentCommandLine, Ancestors, MemfdName

### Category: process_ptrace
**Fields:** SourceImage, SourceProcessId, TargetImage, TargetProcessId, PtraceRequest, PtraceRequestStr, PtraceOptions, PtraceOptionsStr, TargetIsChild

### Category: bpf_event
**Fields:** Image, Kind, InstructionCount, BpfDump, ProgramLoaded, ProgramType, ProgramTypeStr, ProgramFlags, ProgramFlagsStr, ExpectedAttachType, ExpectedAttachTypeStr, FunctionHooked

### Category: library_event
**Fields:** Image, ImageLoaded, ImageSize, Hashes

### Category: filesystem_event
**Fields:** Kind, Path, TargetPath, Mode, PrettyMode, OldMode, PrettyOldMode, Uid, Gid, FileMd5, FileSha1, FileSha256, FileSize

### Category: network_connection
**Fields:** DestinationIp, DestinationNames, DestinationHostname, DestinationIsIpv6, DestinationPort, Protocol, ProtocolNumber, Initiated, SourceIp, SourceIsIpv6, SourcePort

### Category: network_listen
**Fields:** Address, Port

### Category: network_rawsocket
**Fields:** SocketFamily, SocketType, SocketProtocol

### Category: login_event
**Fields:** Success, Kind, TargetUid, TargetUsername, TargetGid, TargetGroup, SourceUsername, SourceHost, Tty

### Category: logout_event
**Fields:** TargetUid, TargetUsername, TargetGid, TargetGroup, SourceUsername, SourceHost, Tty

### Category: url_request
**Fields:** RequestUrl, RequestUrlScheme, RequestUrlHost, RequestUrlPort, RequestUrlPath, RequestUrlQueryParams, RequestUrlUsername, RequestUrlPassword

### Category: dns_query
**Fields:** QueryName, QueryType, QueryStatusCategory, IpAddresses, TextRecords, Image, User

## macOS Events (product: macos)

### Category: process_creation
**Fields:** Image, CommandLine, CurrentDirectory, User, ParentImage, ParentCommandLine, GrandparentImage, GrandparentCommandLine, md5, sha1, sha256, Ancestors, RealUsername, EffectiveUsername, RealGroup, EffectiveGroup, CdHash, Signed, SignatureTeamId, SignatureSigningId, CodesigningFlags, CodesigningFlagsStr, IsPlatformBinary

### Category: library_event
**Fields:** Image, ImageLoaded

### Category: filesystem_event
**Fields:** Kind, Path, TargetPath, Mode, PrettyMode, OldMode, PrettyOldMode, Uid, Gid, FileMd5, FileSha1, FileSha256, FileSize

### Category: network_connection
**Fields:** DestinationPort, DestinationIp, DestinationNames, DestinationHostname, DestinationIsIpv6, Image, Initiated, Protocol, ProtocolNumber, SourcePort, SourceIp, SourceIsIpv6, User

### Category: login_event
**Fields:** Success, LoginMethod, TargetUsername, SourceAddress

### Category: logout_event
**Fields:** TargetUsername, LogoutMethod, SourceAddress

## Summary of Categories by Product

### Windows Categories
- process_creation
- network_connection
- network_dpi
- network_close
- driver_load
- library_event
- remote_thread
- injected_thread
- raw_device_access
- process_access
- process_duplicate_handle
- process_tampered
- etwti_ntallocatevirtualmemory
- registry_event
- named_pipe_creation
- named_pipe_connection
- file_create
- file_read
- file_write
- file_rename
- file_remove
- file_shadowcopy
- file_download
- powershell_event
- url_request
- login_event
- logout_event
- dns_query
- user
- group
- amsi_scan
- service
- scheduled_task
- eventlog
- win32k_getasynckeystate
- win32k_registerrawinputdevices
- win32k_setwindowshookex

### Linux Categories
- process_creation
- process_ptrace
- bpf_event
- library_event
- filesystem_event
- network_connection
- network_listen
- network_rawsocket
- login_event
- logout_event
- url_request
- dns_query

### macOS Categories
- process_creation
- library_event
- filesystem_event
- network_connection
- login_event
- logout_event

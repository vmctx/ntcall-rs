#![no_std]

//! A library containg NT System Call definitions.
//!
//! All System Call ID's are dumped at compile-time.
//! To get started just import the function you would like to use and call it
//! just like with winapi/ntapi.
//!
//! # Example
//! Add the following to your code to shutdown your system:
//! ```rust
//! use ntcall::NtShutdownSystem;
//!
//! const ShutdownPowerOff: u32 = 2;
//!
//! unsafe { NtShutdownSystem(ShutdownPowerOff); }
//! ```

use core::arch::global_asm;
use ntapi::ntapi_base::{PCLIENT_ID, PRTL_ATOM, RTL_ATOM};
use ntapi::ntdbg::DEBUGOBJECTINFOCLASS;
use ntapi::ntexapi::{
    ATOM_INFORMATION_CLASS, EVENT_INFORMATION_CLASS, FILTER_BOOT_OPTION_OPERATION,
    MUTANT_INFORMATION_CLASS, PBOOT_ENTRY, PBOOT_OPTIONS, PCWNF_TYPE_ID, PEFI_DRIVER_ENTRY,
    PT2_CANCEL_PARAMETERS, PT2_SET_PARAMETERS, PTIMER_APC_ROUTINE, PWNF_CHANGE_STAMP,
    PWNF_DELIVERY_DESCRIPTOR, SEMAPHORE_INFORMATION_CLASS, SHUTDOWN_ACTION, SYSDBG_COMMAND,
    SYSTEM_INFORMATION_CLASS, TIMER_INFORMATION_CLASS, TIMER_SET_INFORMATION_CLASS,
    WNF_CHANGE_STAMP, WNF_DATA_SCOPE, WNF_STATE_NAME_INFORMATION, WNF_STATE_NAME_LIFETIME,
    WORKERFACTORYINFOCLASS,
};
use ntapi::ntioapi::{
    FILE_INFORMATION_CLASS, FILE_IO_COMPLETION_INFORMATION, FS_INFORMATION_CLASS,
    IO_COMPLETION_INFORMATION_CLASS, IO_SESSION_EVENT, IO_SESSION_STATE, PFILE_BASIC_INFORMATION,
    PFILE_IO_COMPLETION_INFORMATION, PFILE_NETWORK_OPEN_INFORMATION, PIO_APC_ROUTINE,
    PIO_STATUS_BLOCK,
};
use ntapi::ntkeapi::KPROFILE_SOURCE;
use ntapi::ntlpcapi::{
    ALPC_HANDLE, ALPC_MESSAGE_INFORMATION_CLASS, ALPC_PORT_INFORMATION_CLASS, PALPC_CONTEXT_ATTR,
    PALPC_DATA_VIEW_ATTR, PALPC_HANDLE, PALPC_MESSAGE_ATTRIBUTES, PALPC_PORT_ATTRIBUTES,
    PALPC_SECURITY_ATTR, PORT_INFORMATION_CLASS, PPORT_MESSAGE, PPORT_VIEW, PREMOTE_PORT_VIEW,
};
use ntapi::ntmisc::VDMSERVICECLASS;
use ntapi::ntmmapi::{
    MEMORY_INFORMATION_CLASS, MEMORY_PARTITION_INFORMATION_CLASS, PMEMORY_RANGE_ENTRY,
    SECTION_INFORMATION_CLASS, SECTION_INHERIT, VIRTUAL_MEMORY_INFORMATION_CLASS,
};
use ntapi::ntobapi::OBJECT_INFORMATION_CLASS;
use ntapi::ntpnpapi::PLUGPLAY_CONTROL_CLASS;
use ntapi::ntpsapi::{
    MEMORY_RESERVE_TYPE, PINITIAL_TEB, PPS_APC_ROUTINE, PPS_ATTRIBUTE_LIST, PPS_CREATE_INFO,
    PROCESSINFOCLASS, THREADINFOCLASS,
};
use ntapi::ntregapi::{
    KEY_INFORMATION_CLASS, KEY_SET_INFORMATION_CLASS, KEY_VALUE_INFORMATION_CLASS, PKEY_VALUE_ENTRY,
};
use ntapi::ntseapi::PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;
use ntapi::winapi_local::um::winnt::PMEM_EXTENDED_PARAMETER;
use winapi::shared::basetsd::{
    KAFFINITY, PSIZE_T, PULONG64, PULONG_PTR, SIZE_T, ULONG64, ULONG_PTR,
};

use winapi::shared::ntdef::{
    BOOLEAN, EVENT_TYPE, HANDLE, LANGID, LCID, LOGICAL, LONG, NTSTATUS, OBJECT_ATTRIBUTES,
    PBOOLEAN, PCHAR, PCWNF_STATE_NAME, PGROUP_AFFINITY, PHANDLE, PLARGE_INTEGER, PLCID, PLONG,
    PLUID, PNTSTATUS, POBJECT_ATTRIBUTES, PUCHAR, PULARGE_INTEGER, PULONG, PULONGLONG,
    PUNICODE_STRING, PUSHORT, PVOID, PWNF_STATE_NAME, PWSTR, TIMER_TYPE, ULONG, USHORT, VOID,
    WAIT_TYPE,
};

use ntapi::ntexapi::PFILE_PATH;
use winapi::shared::guiddef::LPGUID;
use winapi::shared::ktmtypes::{NOTIFICATION_MASK, PCRM_PROTOCOL_ID, PTRANSACTION_NOTIFICATION};
use winapi::um::winnt::{
    ACCESS_MASK, AUDIT_EVENT_TYPE, ENLISTMENT_INFORMATION_CLASS, EXECUTION_STATE,
    JOBOBJECTINFOCLASS, KTMOBJECT_TYPE, PACCESS_MASK, PCONTEXT, PDEVICE_POWER_STATE,
    PEXCEPTION_RECORD, PEXECUTION_STATE, PFILE_SEGMENT_ELEMENT, PGENERIC_MAPPING, PJOB_SET_ARRAY,
    PKTMOBJECT_CURSOR, POBJECT_TYPE_LIST, POWER_ACTION, POWER_INFORMATION_LEVEL, PPRIVILEGE_SET,
    PSECURITY_DESCRIPTOR, PSECURITY_QUALITY_OF_SERVICE, PSE_SIGNING_LEVEL, PSID,
    PSID_AND_ATTRIBUTES, PTOKEN_DEFAULT_DACL, PTOKEN_GROUPS, PTOKEN_MANDATORY_POLICY, PTOKEN_OWNER,
    PTOKEN_PRIMARY_GROUP, PTOKEN_PRIVILEGES, PTOKEN_SOURCE, PTOKEN_USER,
    RESOURCEMANAGER_INFORMATION_CLASS, SECURITY_INFORMATION, SE_SIGNING_LEVEL, SYSTEM_POWER_STATE,
    TOKEN_INFORMATION_CLASS, TOKEN_TYPE, TRANSACTIONMANAGER_INFORMATION_CLASS,
    TRANSACTION_INFORMATION_CLASS,
};

// https://j00ru.vexillium.org/syscalls/nt/64/
#[allow(non_snake_case)]
extern "C" {
    pub fn NtAcceptConnectPort(
        PortHandle: PHANDLE,
        PortContext: PVOID,
        ConnectionRequest: PPORT_MESSAGE,
        AcceptConnection: BOOLEAN,
        ServerView: PPORT_VIEW,
        ClientView: PREMOTE_PORT_VIEW,
    ) -> NTSTATUS;
    pub fn NtAccessCheck(
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
        ClientToken: HANDLE,
        DesiredAccess: ACCESS_MASK,
        GenericMapping: PGENERIC_MAPPING,
        PrivilegeSet: PPRIVILEGE_SET,
        PrivilegeSetLength: PULONG,
        GrantedAccess: PACCESS_MASK,
        AccessStatus: PNTSTATUS,
    ) -> NTSTATUS;
    pub fn NtAccessCheckAndAuditAlarm(
        SubsystemName: PUNICODE_STRING,
        HandleId: PVOID,
        ObjectTypeName: PUNICODE_STRING,
        ObjectName: PUNICODE_STRING,
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
        DesiredAccess: ACCESS_MASK,
        GenericMapping: PGENERIC_MAPPING,
        ObjectCreation: BOOLEAN,
        GrantedAccess: PACCESS_MASK,
        AccessStatus: PNTSTATUS,
        GenerateOnClose: PBOOLEAN,
    ) -> NTSTATUS;
    pub fn NtAccessCheckByType(
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
        PrincipalSelfSid: PSID,
        ClientToken: HANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectTypeList: POBJECT_TYPE_LIST,
        ObjectTypeListLength: ULONG,
        GenericMapping: PGENERIC_MAPPING,
        PrivilegeSet: PPRIVILEGE_SET,
        PrivilegeSetLength: PULONG,
        GrantedAccess: PACCESS_MASK,
        AccessStatus: PNTSTATUS,
    ) -> NTSTATUS;
    pub fn NtAccessCheckByTypeAndAuditAlarm(
        SubsystemName: PUNICODE_STRING,
        HandleId: PVOID,
        ObjectTypeName: PUNICODE_STRING,
        ObjectName: PUNICODE_STRING,
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
        PrincipalSelfSid: PSID,
        DesiredAccess: ACCESS_MASK,
        AuditType: AUDIT_EVENT_TYPE,
        Flags: ULONG,
        ObjectTypeList: POBJECT_TYPE_LIST,
        ObjectTypeListLength: ULONG,
        GenericMapping: PGENERIC_MAPPING,
        ObjectCreation: BOOLEAN,
        GrantedAccess: PACCESS_MASK,
        AccessStatus: PNTSTATUS,
        GenerateOnClose: PBOOLEAN,
    ) -> NTSTATUS;
    pub fn NtAccessCheckByTypeResultList(
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
        PrincipalSelfSid: PSID,
        ClientToken: HANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectTypeList: POBJECT_TYPE_LIST,
        ObjectTypeListLength: ULONG,
        GenericMapping: PGENERIC_MAPPING,
        PrivilegeSet: PPRIVILEGE_SET,
        PrivilegeSetLength: PULONG,
        GrantedAccess: PACCESS_MASK,
        AccessStatus: PNTSTATUS,
    ) -> NTSTATUS;
    pub fn NtAccessCheckByTypeResultListAndAuditAlarm(
        SubsystemName: PUNICODE_STRING,
        HandleId: PVOID,
        ObjectTypeName: PUNICODE_STRING,
        ObjectName: PUNICODE_STRING,
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
        PrincipalSelfSid: PSID,
        DesiredAccess: ACCESS_MASK,
        AuditType: AUDIT_EVENT_TYPE,
        Flags: ULONG,
        ObjectTypeList: POBJECT_TYPE_LIST,
        ObjectTypeListLength: ULONG,
        GenericMapping: PGENERIC_MAPPING,
        ObjectCreation: BOOLEAN,
        GrantedAccess: PACCESS_MASK,
        AccessStatus: PNTSTATUS,
        GenerateOnClose: PBOOLEAN,
    ) -> NTSTATUS;
    pub fn NtAccessCheckByTypeResultListAndAuditAlarmByHandle(
        SubsystemName: PUNICODE_STRING,
        HandleId: PVOID,
        ClientToken: HANDLE,
        ObjectTypeName: PUNICODE_STRING,
        ObjectName: PUNICODE_STRING,
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
        PrincipalSelfSid: PSID,
        DesiredAccess: ACCESS_MASK,
        AuditType: AUDIT_EVENT_TYPE,
        Flags: ULONG,
        ObjectTypeList: POBJECT_TYPE_LIST,
        ObjectTypeListLength: ULONG,
        GenericMapping: PGENERIC_MAPPING,
        ObjectCreation: BOOLEAN,
        GrantedAccess: PACCESS_MASK,
        AccessStatus: PNTSTATUS,
        GenerateOnClose: PBOOLEAN,
    ) -> NTSTATUS;
    pub fn NtAcquireCrossVmMutant(
        _Unknown: ULONG,
        __Unknown: ULONG,
        EventHandle: HANDLE,
        __Unknown: PULONGLONG,
    );
    pub fn NtAcquireProcessActivityReference(pHandle: PHANDLE, hProcess: HANDLE, Unknown: ULONG);
    pub fn NtAddAtom(AtomName: PWSTR, Length: ULONG, Atom: PRTL_ATOM) -> NTSTATUS;
    pub fn NtAddAtomEx(AtomName: PWSTR, Length: ULONG, Atom: PRTL_ATOM, Flags: ULONG) -> NTSTATUS;
    pub fn NtAddBootEntry(BootEntry: PBOOT_ENTRY, Id: PULONG) -> NTSTATUS;
    pub fn NtAddDriverEntry(DriverEntry: PEFI_DRIVER_ENTRY, Id: PULONG) -> NTSTATUS;
    pub fn NtAdjustGroupsToken(
        TokenHandle: HANDLE,
        ResetToDefault: BOOLEAN,
        NewState: PTOKEN_GROUPS,
        BufferLength: ULONG,
        PreviousState: PTOKEN_GROUPS,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtAdjustPrivilegesToken(
        TokenHandle: HANDLE,
        DisableAllPrivileges: BOOLEAN,
        NewState: PTOKEN_PRIVILEGES,
        BufferLength: ULONG,
        PreviousState: PTOKEN_PRIVILEGES,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtAdjustTokenClaimsAndDeviceGroups(
        TokenHandle: HANDLE,
        UserResetToDefault: BOOLEAN,
        DeviceResetToDefault: BOOLEAN,
        DeviceGroupsResetToDefault: BOOLEAN,
        NewUserState: PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
        NewDeviceState: PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
        NewDeviceGroupsState: PTOKEN_GROUPS,
        UserBufferLength: ULONG,
        PreviousUserState: PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
        DeviceBufferLength: ULONG,
        PreviousDeviceState: PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
        DeviceGroupsBufferLength: ULONG,
        PreviousDeviceGroups: PTOKEN_GROUPS,
        UserReturnLength: PULONG,
        DeviceReturnLength: PULONG,
        DeviceGroupsReturnBufferLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtAlertResumeThread(ThreadHandle: HANDLE, PreviousSuspendCount: PULONG) -> NTSTATUS;
    pub fn NtAlertThread(ThreadHandle: HANDLE) -> NTSTATUS;
    pub fn NtAlertThreadByThreadId(ThreadId: HANDLE) -> NTSTATUS;
    pub fn NtAllocateLocallyUniqueId(Luid: PLUID) -> NTSTATUS;
    pub fn NtAllocateReserveObject(
        MemoryReserveHandle: PHANDLE,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        Type: MEMORY_RESERVE_TYPE,
    ) -> NTSTATUS;
    pub fn NtAllocateUserPhysicalPages(
        ProcessHandle: HANDLE,
        NumberOfPages: PULONG_PTR,
        UserPfnArray: PULONG_PTR,
    ) -> NTSTATUS;
    // TODO NtAllocateUserPhysicalPagesEx

    pub fn NtAllocateUuids(
        Time: PULARGE_INTEGER,
        Range: PULONG,
        Sequence: PULONG,
        Seed: PCHAR,
    ) -> NTSTATUS;
    pub fn NtAllocateVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        ZeroBits: ULONG_PTR,
        RegionSize: PSIZE_T,
        AllocationType: ULONG,
        Protect: ULONG,
    ) -> NTSTATUS;
    // TODO NtAllocateVirtualMemoryEx

    pub fn NtAlpcAcceptConnectPort(
        PortHandle: PHANDLE,
        ConnectionPortHandle: HANDLE,
        Flags: ULONG,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        PortAttributes: PALPC_PORT_ATTRIBUTES,
        PortContext: PVOID,
        ConnectionRequest: PPORT_MESSAGE,
        ConnectionMessageAttributes: PALPC_MESSAGE_ATTRIBUTES,
        AcceptConnection: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtAlpcCancelMessage(
        PortHandle: HANDLE,
        Flags: ULONG,
        MessageContext: PALPC_CONTEXT_ATTR,
    ) -> NTSTATUS;
    pub fn NtAlpcConnectPort(
        PortHandle: PHANDLE,
        PortName: PUNICODE_STRING,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        PortAttributes: PALPC_PORT_ATTRIBUTES,
        Flags: ULONG,
        RequiredServerSid: PSID,
        ConnectionMessage: PPORT_MESSAGE,
        BufferLength: PULONG,
        OutMessageAttributes: PALPC_MESSAGE_ATTRIBUTES,
        InMessageAttributes: PALPC_MESSAGE_ATTRIBUTES,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtAlpcConnectPortEx(
        PortHandle: PHANDLE,
        ConnectionPortObjectAttributes: POBJECT_ATTRIBUTES,
        ClientPortObjectAttributes: POBJECT_ATTRIBUTES,
        PortAttributes: PALPC_PORT_ATTRIBUTES,
        Flags: ULONG,
        ServerSecurityRequirements: PSECURITY_DESCRIPTOR,
        ConnectionMessage: PPORT_MESSAGE,
        BufferLength: PSIZE_T,
        OutMessageAttributes: PALPC_MESSAGE_ATTRIBUTES,
        InMessageAttributes: PALPC_MESSAGE_ATTRIBUTES,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtAlpcCreatePort(
        PortHandle: PHANDLE,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        PortAttributes: PALPC_PORT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtAlpcCreatePortSection(
        PortHandle: HANDLE,
        Flags: ULONG,
        SectionHandle: HANDLE,
        SectionSize: SIZE_T,
        AlpcSectionHandle: PALPC_HANDLE,
        ActualSectionSize: PSIZE_T,
    ) -> NTSTATUS;
    pub fn NtAlpcCreateResourceReserve(
        PortHandle: HANDLE,
        Flags: ULONG,
        MessageSize: SIZE_T,
        ResourceId: PALPC_HANDLE,
    ) -> NTSTATUS;
    pub fn NtAlpcCreateSectionView(
        PortHandle: HANDLE,
        Flags: ULONG,
        ViewAttributes: PALPC_DATA_VIEW_ATTR,
    ) -> NTSTATUS;
    pub fn NtAlpcCreateSecurityContext(
        PortHandle: HANDLE,
        Flags: ULONG,
        SecurityAttribute: PALPC_SECURITY_ATTR,
    ) -> NTSTATUS;
    pub fn NtAlpcDeletePortSection(
        PortHandle: HANDLE,
        Flags: ULONG,
        SectionHandle: ALPC_HANDLE,
    ) -> NTSTATUS;
    pub fn NtAlpcDeleteResourceReserve(
        PortHandle: HANDLE,
        Flags: ULONG,
        ResourceId: ALPC_HANDLE,
    ) -> NTSTATUS;
    pub fn NtAlpcDeleteSectionView(PortHandle: HANDLE, Flags: ULONG, ViewBase: PVOID) -> NTSTATUS;
    pub fn NtAlpcDeleteSecurityContext(
        PortHandle: HANDLE,
        Flags: ULONG,
        ContextHandle: ALPC_HANDLE,
    ) -> NTSTATUS;
    pub fn NtAlpcDisconnectPort(PortHandle: HANDLE, Flags: ULONG) -> NTSTATUS;
    pub fn NtAlpcImpersonateClientContainerOfPort(
        PortHandle: HANDLE,
        Message: PPORT_MESSAGE,
        Flags: ULONG,
    ) -> NTSTATUS;
    pub fn NtAlpcImpersonateClientOfPort(
        PortHandle: HANDLE,
        Message: PPORT_MESSAGE,
        Flags: PVOID,
    ) -> NTSTATUS;
    pub fn NtAlpcOpenSenderProcess(
        ProcessHandle: PHANDLE,
        PortHandle: HANDLE,
        PortMessage: PPORT_MESSAGE,
        Flags: ULONG,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtAlpcOpenSenderThread(
        ThreadHandle: PHANDLE,
        PortHandle: HANDLE,
        PortMessage: PPORT_MESSAGE,
        Flags: ULONG,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtAlpcQueryInformation(
        PortHandle: HANDLE,
        PortInformationClass: ALPC_PORT_INFORMATION_CLASS,
        PortInformation: PVOID,
        Length: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtAlpcQueryInformationMessage(
        PortHandle: HANDLE,
        PortMessage: PPORT_MESSAGE,
        MessageInformationClass: ALPC_MESSAGE_INFORMATION_CLASS,
        MessageInformation: PVOID,
        Length: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtAlpcRevokeSecurityContext(
        PortHandle: HANDLE,
        Flags: ULONG,
        ContextHandle: ALPC_HANDLE,
    ) -> NTSTATUS;
    pub fn NtAlpcSendWaitReceivePort(
        PortHandle: HANDLE,
        Flags: ULONG,
        SendMessageA: PPORT_MESSAGE,
        SendMessageAttributes: PALPC_MESSAGE_ATTRIBUTES,
        ReceiveMessage: PPORT_MESSAGE,
        BufferLength: PSIZE_T,
        ReceiveMessageAttributes: PALPC_MESSAGE_ATTRIBUTES,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtAlpcSetInformation(
        PortHandle: HANDLE,
        PortInformationClass: ALPC_PORT_INFORMATION_CLASS,
        PortInformation: PVOID,
        Length: ULONG,
    ) -> NTSTATUS;
    // TODO NtApphelpCacheControl

    pub fn NtAreMappedFilesTheSame(
        File1MappedAsAnImage: PVOID,
        File2MappedAsFile: PVOID,
    ) -> NTSTATUS;
    pub fn NtAssignProcessToJobObject(JobHandle: HANDLE, ProcessHandle: HANDLE) -> NTSTATUS;
    pub fn NtAssociateWaitCompletionPacket(
        WaitCompletionPacketHandle: HANDLE,
        IoCompletionHandle: HANDLE,
        TargetObjectHandle: HANDLE,
        KeyContext: PVOID,
        ApcContext: PVOID,
        IoStatus: NTSTATUS,
        IoStatusInformation: ULONG_PTR,
        AlreadySignaled: PBOOLEAN,
    ) -> NTSTATUS;
    // TODO NtCallEnclave

    pub fn NtCallbackReturn(OutputBuffer: PVOID, OutputLength: ULONG, Status: NTSTATUS)
        -> NTSTATUS;
    pub fn NtCancelIoFile(FileHandle: HANDLE, IoStatusBlock: PIO_STATUS_BLOCK) -> NTSTATUS;
    pub fn NtCancelIoFileEx(
        FileHandle: HANDLE,
        IoRequestToCancel: PIO_STATUS_BLOCK,
        IoStatusBlock: PIO_STATUS_BLOCK,
    ) -> NTSTATUS;
    pub fn NtCancelSynchronousIoFile(
        ThreadHandle: HANDLE,
        IoRequestToCancel: PIO_STATUS_BLOCK,
        IoStatusBlock: PIO_STATUS_BLOCK,
    ) -> NTSTATUS;
    pub fn NtCancelTimer(TimerHandle: HANDLE, CurrentState: PBOOLEAN) -> NTSTATUS;
    pub fn NtCancelTimer2(TimerHandle: HANDLE, Parameters: PT2_CANCEL_PARAMETERS) -> NTSTATUS;
    pub fn NtCancelWaitCompletionPacket(
        WaitCompletionPacketHandle: HANDLE,
        RemoveSignaledPacket: BOOLEAN,
    ) -> NTSTATUS;
    // TODO NtChangeProcessState

    // TODO NtChangeThreadState

    pub fn NtClearEvent(EventHandle: HANDLE) -> NTSTATUS;
    pub fn NtClose(Handle: HANDLE) -> NTSTATUS;
    pub fn NtCloseObjectAuditAlarm(
        SubsystemName: PUNICODE_STRING,
        HandleId: PVOID,
        GenerateOnClose: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtCommitComplete(EnlistmentHandle: HANDLE, TmVirtualClock: PLARGE_INTEGER) -> NTSTATUS;
    pub fn NtCommitEnlistment(EnlistmentHandle: HANDLE, TmVirtualClock: PLARGE_INTEGER)
        -> NTSTATUS;
    // TODO NtCommitRegistryTransaction

    pub fn NtCommitTransaction(TransactionHandle: HANDLE, Wait: BOOLEAN) -> NTSTATUS;
    pub fn NtCompactKeys(Count: ULONG, KeyArray: *mut HANDLE) -> NTSTATUS;
    pub fn NtCompareObjects(FirstObjectHandle: HANDLE, SecondObjectHandle: HANDLE) -> NTSTATUS;
    // TODO NtCompareSigningLevels

    pub fn NtCompareTokens(
        FirstTokenHandle: HANDLE,
        SecondTokenHandle: HANDLE,
        Equal: PBOOLEAN,
    ) -> NTSTATUS;
    pub fn NtCompleteConnectPort(PortHandle: HANDLE) -> NTSTATUS;
    pub fn NtCompressKey(Key: HANDLE) -> NTSTATUS;
    pub fn NtConnectPort(
        PortHandle: PHANDLE,
        PortName: PUNICODE_STRING,
        SecurityQos: PSECURITY_QUALITY_OF_SERVICE,
        ClientView: PPORT_VIEW,
        ServerView: PREMOTE_PORT_VIEW,
        MaxMessageLength: PULONG,
        ConnectionInformation: PVOID,
        ConnectionInformationLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtContinue(ContextRecord: PCONTEXT, TestAlert: BOOLEAN) -> NTSTATUS;
    // TODO NtContinueEx

    // TODO NtConvertBetweenAuxiliaryCounterAndPerformanceCounter

    // TODO NtCreateCrossVmEvent

    // TODO NtCreateCrossVmMutant

    pub fn NtCreateDebugObject(
        DebugObjectHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        Flags: ULONG,
    ) -> NTSTATUS;
    pub fn NtCreateDirectoryObject(
        DirectoryHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtCreateDirectoryObjectEx(
        DirectoryHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        ShadowDirectoryHandle: HANDLE,
        Flags: ULONG,
    ) -> NTSTATUS;
    // TODO NtCreateEnclave

    pub fn NtCreateEnlistment(
        EnlistmentHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ResourceManagerHandle: HANDLE,
        TransactionHandle: HANDLE,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        CreateOptions: ULONG,
        NotificationMask: NOTIFICATION_MASK,
        EnlistmentKey: PVOID,
    ) -> NTSTATUS;
    pub fn NtCreateEvent(
        EventHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        EventType: EVENT_TYPE,
        InitialState: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtCreateEventPair(
        EventPairHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtCreateFile(
        FileHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        IoStatusBlock: PIO_STATUS_BLOCK,
        AllocationSize: PLARGE_INTEGER,
        FileAttributes: ULONG,
        ShareAccess: ULONG,
        CreateDisposition: ULONG,
        CreateOptions: ULONG,
        EaBuffer: PVOID,
        EaLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtCreateIRTimer(TimerHandle: PHANDLE, DesiredAccess: ACCESS_MASK) -> NTSTATUS;
    pub fn NtCreateIoCompletion(
        IoCompletionHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        Count: ULONG,
    ) -> NTSTATUS;
    // TODO NtCreateIoRing

    pub fn NtCreateJobObject(
        JobHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtCreateJobSet(NumJob: ULONG, UserJobSet: PJOB_SET_ARRAY, Flags: ULONG) -> NTSTATUS;
    pub fn NtCreateKey(
        KeyHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        TitleIndex: ULONG,
        Class: PUNICODE_STRING,
        CreateOptions: ULONG,
        Disposition: PULONG,
    ) -> NTSTATUS;
    pub fn NtCreateKeyTransacted(
        KeyHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        TitleIndex: ULONG,
        Class: PUNICODE_STRING,
        CreateOptions: ULONG,
        TransactionHandle: HANDLE,
        Disposition: PULONG,
    ) -> NTSTATUS;
    pub fn NtCreateKeyedEvent(
        KeyedEventHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        Flags: ULONG,
    ) -> NTSTATUS;
    pub fn NtCreateLowBoxToken(
        TokenHandle: PHANDLE,
        ExistingTokenHandle: HANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        PackageSid: PSID,
        CapabilityCount: ULONG,
        Capabilities: PSID_AND_ATTRIBUTES,
        HandleCount: ULONG,
        Handles: *mut HANDLE,
    ) -> NTSTATUS;
    pub fn NtCreateMailslotFile(
        FileHandle: PHANDLE,
        DesiredAccess: ULONG,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        IoStatusBlock: PIO_STATUS_BLOCK,
        CreateOptions: ULONG,
        MailslotQuota: ULONG,
        MaximumMessageSize: ULONG,
        ReadTimeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtCreateMutant(
        MutantHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        InitialOwner: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtCreateNamedPipeFile(
        FileHandle: PHANDLE,
        DesiredAccess: ULONG,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        IoStatusBlock: PIO_STATUS_BLOCK,
        ShareAccess: ULONG,
        CreateDisposition: ULONG,
        CreateOptions: ULONG,
        NamedPipeType: ULONG,
        ReadMode: ULONG,
        CompletionMode: ULONG,
        MaximumInstances: ULONG,
        InboundQuota: ULONG,
        OutboundQuota: ULONG,
        DefaultTimeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtCreatePagingFile(
        PageFileName: PUNICODE_STRING,
        MinimumSize: PLARGE_INTEGER,
        MaximumSize: PLARGE_INTEGER,
        Priority: ULONG,
    ) -> NTSTATUS;
    pub fn NtCreatePartition(
        PartitionHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        PreferredNode: ULONG,
    ) -> NTSTATUS;
    pub fn NtCreatePort(
        PortHandle: PHANDLE,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        MaxConnectionInfoLength: ULONG,
        MaxMessageLength: ULONG,
        MaxPoolUsage: ULONG,
    ) -> NTSTATUS;
    pub fn NtCreatePrivateNamespace(
        NamespaceHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        BoundaryDescriptor: PVOID,
    ) -> NTSTATUS;
    pub fn NtCreateProcess(
        ProcessHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        ParentProcess: HANDLE,
        InheritObjectTable: BOOLEAN,
        SectionHandle: HANDLE,
        DebugPort: HANDLE,
        ExceptionPort: HANDLE,
    ) -> NTSTATUS;
    pub fn NtCreateProcessEx(
        ProcessHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        ParentProcess: HANDLE,
        Flags: ULONG,
        SectionHandle: HANDLE,
        DebugPort: HANDLE,
        ExceptionPort: HANDLE,
        JobMemberLevel: ULONG,
    ) -> NTSTATUS;
    // TODO NtCreateProcessStateChange

    pub fn NtCreateProfile(
        ProfileHandle: PHANDLE,
        Process: HANDLE,
        ProfileBase: PVOID,
        ProfileSize: SIZE_T,
        BucketSize: ULONG,
        Buffer: PULONG,
        BufferSize: ULONG,
        ProfileSource: KPROFILE_SOURCE,
        Affinity: KAFFINITY,
    ) -> NTSTATUS;
    pub fn NtCreateProfileEx(
        ProfileHandle: PHANDLE,
        Process: HANDLE,
        ProfileBase: PVOID,
        ProfileSize: SIZE_T,
        BucketSize: ULONG,
        Buffer: PULONG,
        BufferSize: ULONG,
        ProfileSource: KPROFILE_SOURCE,
        GroupCount: USHORT,
        GroupAffinity: PGROUP_AFFINITY,
    ) -> NTSTATUS;
    // TODO NtCreateRegistryTransaction

    pub fn NtCreateResourceManager(
        ResourceManagerHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        TmHandle: HANDLE,
        RmGuid: LPGUID,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        CreateOptions: ULONG,
        Description: PUNICODE_STRING,
    ) -> NTSTATUS;
    pub fn NtCreateSection(
        SectionHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        MaximumSize: PLARGE_INTEGER,
        SectionPageProtection: ULONG,
        AllocationAttributes: ULONG,
        FileHandle: HANDLE,
    ) -> NTSTATUS;
    pub fn NtCreateSectionEx(
        SectionHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        MaximumSize: PLARGE_INTEGER,
        SectionPageProtection: ULONG,
        AllocationAttributes: ULONG,
        FileHandle: HANDLE,
        ExtendedParameters: PMEM_EXTENDED_PARAMETER,
        ExtendedParameterCount: ULONG,
    ) -> NTSTATUS;
    pub fn NtCreateSemaphore(
        SemaphoreHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        InitialCount: LONG,
        MaximumCount: LONG,
    ) -> NTSTATUS;
    pub fn NtCreateSymbolicLinkObject(
        LinkHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        LinkTarget: PUNICODE_STRING,
    ) -> NTSTATUS;
    pub fn NtCreateThread(
        ThreadHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        ProcessHandle: HANDLE,
        ClientId: PCLIENT_ID,
        ThreadContext: PCONTEXT,
        InitialTeb: PINITIAL_TEB,
        CreateSuspended: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtCreateThreadEx(
        ThreadHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        ProcessHandle: HANDLE,
        StartRoutine: PVOID,
        Argument: PVOID,
        CreateFlags: ULONG,
        ZeroBits: SIZE_T,
        StackSize: SIZE_T,
        MaximumStackSize: SIZE_T,
        AttributeList: PPS_ATTRIBUTE_LIST,
    ) -> NTSTATUS;
    // TODO NtCreateThreadStateChange

    pub fn NtCreateTimer(
        TimerHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        TimerType: TIMER_TYPE,
    ) -> NTSTATUS;
    pub fn NtCreateTimer2(
        TimerHandle: PHANDLE,
        Reserved1: PVOID,
        Reserved2: PVOID,
        Attributes: ULONG,
        DesiredAccess: ACCESS_MASK,
    ) -> NTSTATUS;
    pub fn NtCreateToken(
        TokenHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        TokenType: TOKEN_TYPE,
        AuthenticationId: PLUID,
        ExpirationTime: PLARGE_INTEGER,
        User: PTOKEN_USER,
        Groups: PTOKEN_GROUPS,
        Privileges: PTOKEN_PRIVILEGES,
        Owner: PTOKEN_OWNER,
        PrimaryGroup: PTOKEN_PRIMARY_GROUP,
        DefaultDacl: PTOKEN_DEFAULT_DACL,
        TokenSource: PTOKEN_SOURCE,
    ) -> NTSTATUS;
    pub fn NtCreateTokenEx(
        TokenHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        TokenType: TOKEN_TYPE,
        AuthenticationId: PLUID,
        ExpirationTime: PLARGE_INTEGER,
        User: PTOKEN_USER,
        Groups: PTOKEN_GROUPS,
        Privileges: PTOKEN_PRIVILEGES,
        UserAttributes: PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
        DeviceAttributes: PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
        DeviceGroups: PTOKEN_GROUPS,
        TokenMandatoryPolicy: PTOKEN_MANDATORY_POLICY,
        Owner: PTOKEN_OWNER,
        PrimaryGroup: PTOKEN_PRIMARY_GROUP,
        DefaultDacl: PTOKEN_DEFAULT_DACL,
        TokenSource: PTOKEN_SOURCE,
    ) -> NTSTATUS;
    pub fn NtCreateTransaction(
        TransactionHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        Uow: LPGUID,
        TmHandle: HANDLE,
        CreateOptions: ULONG,
        IsolationLevel: ULONG,
        IsolationFlags: ULONG,
        Timeout: PLARGE_INTEGER,
        Description: PUNICODE_STRING,
    ) -> NTSTATUS;
    pub fn NtCreateTransactionManager(
        TmHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        LogFileName: PUNICODE_STRING,
        CreateOptions: ULONG,
        CommitStrength: ULONG,
    ) -> NTSTATUS;
    pub fn NtCreateUserProcess(
        ProcessHandle: PHANDLE,
        ThreadHandle: PHANDLE,
        ProcessDesiredAccess: ACCESS_MASK,
        ThreadDesiredAccess: ACCESS_MASK,
        ProcessObjectAttributes: POBJECT_ATTRIBUTES,
        ThreadObjectAttributes: POBJECT_ATTRIBUTES,
        ProcessFlags: ULONG,
        ThreadFlags: ULONG,
        ProcessParameters: PVOID,
        CreateInfo: PPS_CREATE_INFO,
        AttributeList: PPS_ATTRIBUTE_LIST,
    ) -> NTSTATUS;
    pub fn NtCreateWaitCompletionPacket(
        WaitCompletionPacketHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtCreateWaitablePort(
        PortHandle: PHANDLE,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        MaxConnectionInfoLength: ULONG,
        MaxMessageLength: ULONG,
        MaxPoolUsage: ULONG,
    ) -> NTSTATUS;
    pub fn NtCreateWnfStateName(
        StateName: PWNF_STATE_NAME,
        NameLifetime: WNF_STATE_NAME_LIFETIME,
        DataScope: WNF_DATA_SCOPE,
        PersistData: BOOLEAN,
        TypeId: PCWNF_TYPE_ID,
        MaximumStateSize: ULONG,
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
    ) -> NTSTATUS;
    pub fn NtCreateWorkerFactory(
        WorkerFactoryHandleReturn: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        CompletionPortHandle: HANDLE,
        WorkerProcessHandle: HANDLE,
        StartRoutine: PVOID,
        StartParameter: PVOID,
        MaxThreadCount: ULONG,
        StackReserve: SIZE_T,
        StackCommit: SIZE_T,
    ) -> NTSTATUS;
    pub fn NtDebugActiveProcess(ProcessHandle: HANDLE, DebugObjectHandle: HANDLE) -> NTSTATUS;
    pub fn NtDebugContinue(
        DebugObjectHandle: HANDLE,
        ClientId: PCLIENT_ID,
        ContinueStatus: NTSTATUS,
    ) -> NTSTATUS;
    pub fn NtDelayExecution(Alertable: BOOLEAN, DelayInterval: PLARGE_INTEGER) -> NTSTATUS;
    pub fn NtDeleteAtom(Atom: RTL_ATOM) -> NTSTATUS;
    pub fn NtDeleteBootEntry(Id: ULONG) -> NTSTATUS;
    pub fn NtDeleteDriverEntry(Id: ULONG) -> NTSTATUS;
    pub fn NtDeleteFile(ObjectAttributes: POBJECT_ATTRIBUTES) -> NTSTATUS;
    pub fn NtDeleteKey(KeyHandle: HANDLE) -> NTSTATUS;
    pub fn NtDeleteObjectAuditAlarm(
        SubsystemName: PUNICODE_STRING,
        HandleId: PVOID,
        GenerateOnClose: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtDeletePrivateNamespace(NamespaceHandle: HANDLE) -> NTSTATUS;
    pub fn NtDeleteValueKey(KeyHandle: HANDLE, ValueName: PUNICODE_STRING) -> NTSTATUS;
    pub fn NtDeleteWnfStateData(
        StateName: PCWNF_STATE_NAME,
        ExplicitScope: *const VOID,
    ) -> NTSTATUS;
    pub fn NtDeleteWnfStateName(StateName: PCWNF_STATE_NAME) -> NTSTATUS;
    pub fn NtDeviceIoControlFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: PVOID,
        IoStatusBlock: PIO_STATUS_BLOCK,
        IoControlCode: ULONG,
        InputBuffer: PVOID,
        InputBufferLength: ULONG,
        OutputBuffer: PVOID,
        OutputBufferLength: ULONG,
    ) -> NTSTATUS;
    // TODO NtDirectGraphicsCall

    pub fn NtDisableLastKnownGood() -> NTSTATUS;
    pub fn NtDisplayString(String: PUNICODE_STRING) -> NTSTATUS;
    pub fn NtDrawText(Text: PUNICODE_STRING) -> NTSTATUS;
    pub fn NtDuplicateObject(
        SourceProcessHandle: HANDLE,
        SourceHandle: HANDLE,
        TargetProcessHandle: HANDLE,
        TargetHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        HandleAttributes: ULONG,
        Options: ULONG,
    ) -> NTSTATUS;
    pub fn NtDuplicateToken(
        ExistingTokenHandle: HANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        EffectiveOnly: BOOLEAN,
        TokenType: TOKEN_TYPE,
        NewTokenHandle: PHANDLE,
    ) -> NTSTATUS;
    pub fn NtEnableLastKnownGood() -> NTSTATUS;
    pub fn NtEnumerateBootEntries(Buffer: PVOID, BufferLength: PULONG) -> NTSTATUS;
    pub fn NtEnumerateDriverEntries(Buffer: PVOID, BufferLength: PULONG) -> NTSTATUS;
    pub fn NtEnumerateKey(
        KeyHandle: HANDLE,
        Index: ULONG,
        KeyInformationClass: KEY_INFORMATION_CLASS,
        KeyInformation: PVOID,
        Length: ULONG,
        ResultLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtEnumerateSystemEnvironmentValuesEx(
        InformationClass: ULONG,
        Buffer: PVOID,
        BufferLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtEnumerateTransactionObject(
        RootObjectHandle: HANDLE,
        QueryType: KTMOBJECT_TYPE,
        ObjectCursor: PKTMOBJECT_CURSOR,
        ObjectCursorLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtEnumerateValueKey(
        KeyHandle: HANDLE,
        Index: ULONG,
        KeyValueInformationClass: KEY_VALUE_INFORMATION_CLASS,
        KeyValueInformation: PVOID,
        Length: ULONG,
        ResultLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtExtendSection(SectionHandle: HANDLE, NewSectionSize: PLARGE_INTEGER) -> NTSTATUS;
    pub fn NtFilterBootOption(
        FilterOperation: FILTER_BOOT_OPTION_OPERATION,
        ObjectType: ULONG,
        ElementType: ULONG,
        Data: PVOID,
        DataSize: ULONG,
    ) -> NTSTATUS;
    pub fn NtFilterToken(
        ExistingTokenHandle: HANDLE,
        Flags: ULONG,
        SidsToDisable: PTOKEN_GROUPS,
        PrivilegesToDelete: PTOKEN_PRIVILEGES,
        RestrictedSids: PTOKEN_GROUPS,
        NewTokenHandle: PHANDLE,
    ) -> NTSTATUS;
    pub fn NtFilterTokenEx(
        ExistingTokenHandle: HANDLE,
        Flags: ULONG,
        SidsToDisable: PTOKEN_GROUPS,
        PrivilegesToDelete: PTOKEN_PRIVILEGES,
        RestrictedSids: PTOKEN_GROUPS,
        DisableUserClaimsCount: ULONG,
        UserClaimsToDisable: PUNICODE_STRING,
        DisableDeviceClaimsCount: ULONG,
        DeviceClaimsToDisable: PUNICODE_STRING,
        DeviceGroupsToDisable: PTOKEN_GROUPS,
        RestrictedUserAttributes: PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
        RestrictedDeviceAttributes: PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
        RestrictedDeviceGroups: PTOKEN_GROUPS,
        NewTokenHandle: PHANDLE,
    ) -> NTSTATUS;
    pub fn NtFindAtom(AtomName: PWSTR, Length: ULONG, Atom: PRTL_ATOM) -> NTSTATUS;
    pub fn NtFlushBuffersFile(FileHandle: HANDLE, IoStatusBlock: PIO_STATUS_BLOCK) -> NTSTATUS;
    pub fn NtFlushBuffersFileEx(
        FileHandle: HANDLE,
        Flags: ULONG,
        Parameters: PVOID,
        ParametersSize: ULONG,
        IoStatusBlock: PIO_STATUS_BLOCK,
    ) -> NTSTATUS;
    pub fn NtFlushInstallUILanguage(InstallUILanguage: LANGID, SetComittedFlag: ULONG) -> NTSTATUS;
    pub fn NtFlushInstructionCache(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        Length: SIZE_T,
    ) -> NTSTATUS;
    pub fn NtFlushKey(KeyHandle: HANDLE) -> NTSTATUS;
    pub fn NtFlushProcessWriteBuffers();
    // TODO NtFlushVirtualMemory

    pub fn NtFlushWriteBuffer() -> NTSTATUS;
    pub fn NtFreeUserPhysicalPages(
        ProcessHandle: HANDLE,
        NumberOfPages: PULONG_PTR,
        UserPfnArray: PULONG_PTR,
    ) -> NTSTATUS;
    pub fn NtFreeVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: PSIZE_T,
        FreeType: ULONG,
    ) -> NTSTATUS;
    pub fn NtFreezeRegistry(TimeOutInSeconds: ULONG) -> NTSTATUS;
    pub fn NtFreezeTransactions(
        FreezeTimeout: PLARGE_INTEGER,
        ThawTimeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtFsControlFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: PVOID,
        IoStatusBlock: PIO_STATUS_BLOCK,
        FsControlCode: ULONG,
        InputBuffer: PVOID,
        InputBufferLength: ULONG,
        OutputBuffer: PVOID,
        OutputBufferLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtGetCachedSigningLevel(
        File: HANDLE,
        Flags: PULONG,
        SigningLevel: PSE_SIGNING_LEVEL,
        Thumbprint: PUCHAR,
        ThumbprintSize: PULONG,
        ThumbprintAlgorithm: PULONG,
    ) -> NTSTATUS;
    pub fn NtGetCompleteWnfStateSubscription(
        OldDescriptorStateName: PWNF_STATE_NAME,
        OldSubscriptionId: *mut ULONG64,
        OldDescriptorEventMask: ULONG,
        OldDescriptorStatus: ULONG,
        NewDeliveryDescriptor: PWNF_DELIVERY_DESCRIPTOR,
        DescriptorSize: ULONG,
    ) -> NTSTATUS;
    pub fn NtGetContextThread(ThreadHandle: HANDLE, ThreadContext: PCONTEXT) -> NTSTATUS;
    pub fn NtGetCurrentProcessorNumber() -> ULONG;
    // TODO NtGetCurrentProcessorNumberEx

    pub fn NtGetDevicePowerState(Device: HANDLE, State: PDEVICE_POWER_STATE) -> NTSTATUS;
    pub fn NtGetMUIRegistryInfo(Flags: ULONG, DataSize: PULONG, Data: PVOID) -> NTSTATUS;
    pub fn NtGetNextProcess(
        ProcessHandle: HANDLE,
        DesiredAccess: ACCESS_MASK,
        HandleAttributes: ULONG,
        Flags: ULONG,
        NewProcessHandle: PHANDLE,
    ) -> NTSTATUS;
    pub fn NtGetNextThread(
        ProcessHandle: HANDLE,
        ThreadHandle: HANDLE,
        DesiredAccess: ACCESS_MASK,
        HandleAttributes: ULONG,
        Flags: ULONG,
        NewThreadHandle: PHANDLE,
    ) -> NTSTATUS;
    pub fn NtGetNlsSectionPtr(
        SectionType: ULONG,
        SectionData: ULONG,
        ContextData: PVOID,
        SectionPointer: *mut PVOID,
        SectionSize: PULONG,
    ) -> NTSTATUS;
    pub fn NtGetNotificationResourceManager(
        ResourceManagerHandle: HANDLE,
        TransactionNotification: PTRANSACTION_NOTIFICATION,
        NotificationLength: ULONG,
        Timeout: PLARGE_INTEGER,
        ReturnLength: PULONG,
        Asynchronous: ULONG,
        AsynchronousContext: ULONG_PTR,
    ) -> NTSTATUS;
    pub fn NtGetWriteWatch(
        ProcessHandle: HANDLE,
        Flags: ULONG,
        BaseAddress: PVOID,
        RegionSize: SIZE_T,
        UserAddressArray: *mut PVOID,
        EntriesInUserAddressArray: PULONG_PTR,
        Granularity: PULONG,
    ) -> NTSTATUS;
    pub fn NtImpersonateAnonymousToken(ThreadHandle: HANDLE) -> NTSTATUS;
    pub fn NtImpersonateClientOfPort(PortHandle: HANDLE, Message: PPORT_MESSAGE) -> NTSTATUS;
    pub fn NtImpersonateThread(
        ServerThreadHandle: HANDLE,
        ClientThreadHandle: HANDLE,
        SecurityQos: PSECURITY_QUALITY_OF_SERVICE,
    ) -> NTSTATUS;
    // TODO NtInitializeEnclave

    pub fn NtInitializeNlsFiles(
        BaseAddress: *mut PVOID,
        DefaultLocaleId: PLCID,
        DefaultCasingTableSize: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtInitializeRegistry(BootCondition: USHORT) -> NTSTATUS;
    pub fn NtInitiatePowerAction(
        SystemAction: POWER_ACTION,
        LightestSystemState: SYSTEM_POWER_STATE,
        Flags: ULONG,
        Asynchronous: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtIsProcessInJob(ProcessHandle: HANDLE, JobHandle: HANDLE) -> NTSTATUS;
    pub fn NtIsSystemResumeAutomatic() -> BOOLEAN;
    pub fn NtIsUILanguageComitted() -> NTSTATUS;
    pub fn NtListenPort(PortHandle: HANDLE, ConnectionRequest: PPORT_MESSAGE) -> NTSTATUS;
    pub fn NtLoadDriver(DriverServiceName: PUNICODE_STRING) -> NTSTATUS;
    // TODO NtLoadEnclaveData

    pub fn NtLoadKey(TargetKey: POBJECT_ATTRIBUTES, SourceFile: POBJECT_ATTRIBUTES) -> NTSTATUS;
    pub fn NtLoadKey2(
        TargetKey: POBJECT_ATTRIBUTES,
        SourceFile: POBJECT_ATTRIBUTES,
        Flags: ULONG,
    ) -> NTSTATUS;
    // TODO NtLoadKey3

    pub fn NtLoadKeyEx(
        TargetKey: POBJECT_ATTRIBUTES,
        SourceFile: POBJECT_ATTRIBUTES,
        Flags: ULONG,
        TrustClassKey: HANDLE,
        Event: HANDLE,
        DesiredAccess: ACCESS_MASK,
        RootHandle: PHANDLE,
        IoStatus: PIO_STATUS_BLOCK,
    ) -> NTSTATUS;
    pub fn NtLockFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: PVOID,
        IoStatusBlock: PIO_STATUS_BLOCK,
        ByteOffset: PLARGE_INTEGER,
        Length: PLARGE_INTEGER,
        Key: ULONG,
        FailImmediately: BOOLEAN,
        ExclusiveLock: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtLockProductActivationKeys(pPrivateVer: *mut ULONG, pSafeMode: *mut ULONG) -> NTSTATUS;
    pub fn NtLockRegistryKey(KeyHandle: HANDLE) -> NTSTATUS;
    pub fn NtLockVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: PSIZE_T,
        MapType: ULONG,
    ) -> NTSTATUS;
    pub fn NtMakePermanentObject(Handle: HANDLE) -> NTSTATUS;
    pub fn NtMakeTemporaryObject(Handle: HANDLE) -> NTSTATUS;
    // TODO NtManageHotPatch

    pub fn NtManagePartition(
        PartitionInformationClass: MEMORY_PARTITION_INFORMATION_CLASS,
        PartitionInformation: PVOID,
        PartitionInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtMapCMFModule(
        What: ULONG,
        Index: ULONG,
        CacheIndexOut: PULONG,
        CacheFlagsOut: PULONG,
        ViewSizeOut: PULONG,
        BaseAddress: *mut PVOID,
    ) -> NTSTATUS;
    pub fn NtMapUserPhysicalPages(
        VirtualAddress: PVOID,
        NumberOfPages: ULONG_PTR,
        UserPfnArray: PULONG_PTR,
    ) -> NTSTATUS;
    pub fn NtMapUserPhysicalPagesScatter(
        VirtualAddresses: *mut PVOID,
        NumberOfPages: ULONG_PTR,
        UserPfnArray: PULONG_PTR,
    ) -> NTSTATUS;
    pub fn NtMapViewOfSection(
        SectionHandle: HANDLE,
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        ZeroBits: ULONG_PTR,
        CommitSize: SIZE_T,
        SectionOffset: PLARGE_INTEGER,
        ViewSize: PSIZE_T,
        InheritDisposition: SECTION_INHERIT,
        AllocationType: ULONG,
        Win32Protect: ULONG,
    ) -> NTSTATUS;
    // TODO NtMapViewOfSectionEx

    pub fn NtModifyBootEntry(BootEntry: PBOOT_ENTRY) -> NTSTATUS;
    pub fn NtModifyDriverEntry(DriverEntry: PEFI_DRIVER_ENTRY) -> NTSTATUS;
    pub fn NtNotifyChangeDirectoryFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: PVOID,
        IoStatusBlock: PIO_STATUS_BLOCK,
        Buffer: PVOID,
        Length: ULONG,
        CompletionFilter: ULONG,
        WatchTree: BOOLEAN,
    ) -> NTSTATUS;
    // TODO NtNotifyChangeDirectoryFileEx

    pub fn NtNotifyChangeKey(
        KeyHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: PVOID,
        IoStatusBlock: PIO_STATUS_BLOCK,
        CompletionFilter: ULONG,
        WatchTree: BOOLEAN,
        Buffer: PVOID,
        BufferSize: ULONG,
        Asynchronous: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtNotifyChangeMultipleKeys(
        MasterKeyHandle: HANDLE,
        Count: ULONG,
        SubordinateObjects: *mut OBJECT_ATTRIBUTES,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: PVOID,
        IoStatusBlock: PIO_STATUS_BLOCK,
        CompletionFilter: ULONG,
        WatchTree: BOOLEAN,
        Buffer: PVOID,
        BufferSize: ULONG,
        Asynchronous: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtNotifyChangeSession(
        SessionHandle: HANDLE,
        ChangeSequenceNumber: ULONG,
        ChangeTimeStamp: PLARGE_INTEGER,
        Event: IO_SESSION_EVENT,
        NewState: IO_SESSION_STATE,
        PreviousState: IO_SESSION_STATE,
        Payload: PVOID,
        PayloadSize: ULONG,
    ) -> NTSTATUS;
    pub fn NtOpenDirectoryObject(
        DirectoryHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenEnlistment(
        EnlistmentHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ResourceManagerHandle: HANDLE,
        EnlistmentGuid: LPGUID,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenEvent(
        EventHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenEventPair(
        EventPairHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenFile(
        FileHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        IoStatusBlock: PIO_STATUS_BLOCK,
        ShareAccess: ULONG,
        OpenOptions: ULONG,
    ) -> NTSTATUS;
    pub fn NtOpenIoCompletion(
        IoCompletionHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenJobObject(
        JobHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenKey(
        KeyHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenKeyEx(
        KeyHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        OpenOptions: ULONG,
    ) -> NTSTATUS;
    pub fn NtOpenKeyTransacted(
        KeyHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        TransactionHandle: HANDLE,
    ) -> NTSTATUS;
    pub fn NtOpenKeyTransactedEx(
        KeyHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        OpenOptions: ULONG,
        TransactionHandle: HANDLE,
    ) -> NTSTATUS;
    pub fn NtOpenKeyedEvent(
        KeyedEventHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenMutant(
        MutantHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenObjectAuditAlarm(
        SubsystemName: PUNICODE_STRING,
        HandleId: PVOID,
        ObjectTypeName: PUNICODE_STRING,
        ObjectName: PUNICODE_STRING,
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
        ClientToken: HANDLE,
        DesiredAccess: ACCESS_MASK,
        GrantedAccess: ACCESS_MASK,
        Privileges: PPRIVILEGE_SET,
        ObjectCreation: BOOLEAN,
        AccessGranted: BOOLEAN,
        GenerateOnClose: PBOOLEAN,
    ) -> NTSTATUS;
    pub fn NtOpenPartition(
        PartitionHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenPrivateNamespace(
        NamespaceHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        BoundaryDescriptor: PVOID,
    ) -> NTSTATUS;
    pub fn NtOpenProcess(
        ProcessHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        ClientId: PCLIENT_ID,
    ) -> NTSTATUS;
    pub fn NtOpenProcessToken(
        ProcessHandle: HANDLE,
        DesiredAccess: ACCESS_MASK,
        TokenHandle: PHANDLE,
    ) -> NTSTATUS;
    pub fn NtOpenProcessTokenEx(
        ProcessHandle: HANDLE,
        DesiredAccess: ACCESS_MASK,
        HandleAttributes: ULONG,
        TokenHandle: PHANDLE,
    ) -> NTSTATUS;
    // TODO NtOpenRegistryTransaction

    pub fn NtOpenResourceManager(
        ResourceManagerHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        TmHandle: HANDLE,
        ResourceManagerGuid: LPGUID,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenSection(
        SectionHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenSemaphore(
        SemaphoreHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenSession(
        SessionHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenSymbolicLinkObject(
        LinkHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenThread(
        ThreadHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        ClientId: PCLIENT_ID,
    ) -> NTSTATUS;
    pub fn NtOpenThreadToken(
        ThreadHandle: HANDLE,
        DesiredAccess: ACCESS_MASK,
        OpenAsSelf: BOOLEAN,
        TokenHandle: PHANDLE,
    ) -> NTSTATUS;
    pub fn NtOpenThreadTokenEx(
        ThreadHandle: HANDLE,
        DesiredAccess: ACCESS_MASK,
        OpenAsSelf: BOOLEAN,
        HandleAttributes: ULONG,
        TokenHandle: PHANDLE,
    ) -> NTSTATUS;
    pub fn NtOpenTimer(
        TimerHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtOpenTransaction(
        TransactionHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        Uow: LPGUID,
        TmHandle: HANDLE,
    ) -> NTSTATUS;
    pub fn NtOpenTransactionManager(
        TmHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        LogFileName: PUNICODE_STRING,
        TmIdentity: LPGUID,
        OpenOptions: ULONG,
    ) -> NTSTATUS;
    pub fn NtPlugPlayControl(
        PnPControlClass: PLUGPLAY_CONTROL_CLASS,
        PnPControlData: PVOID,
        PnPControlDataLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtPowerInformation(
        InformationLevel: POWER_INFORMATION_LEVEL,
        InputBuffer: PVOID,
        InputBufferLength: ULONG,
        OutputBuffer: PVOID,
        OutputBufferLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtPrePrepareComplete(
        EnlistmentHandle: HANDLE,
        TmVirtualClock: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtPrePrepareEnlistment(
        EnlistmentHandle: HANDLE,
        TmVirtualClock: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtPrepareComplete(EnlistmentHandle: HANDLE, TmVirtualClock: PLARGE_INTEGER) -> NTSTATUS;
    pub fn NtPrepareEnlistment(
        EnlistmentHandle: HANDLE,
        TmVirtualClock: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtPrivilegeCheck(
        ClientToken: HANDLE,
        RequiredPrivileges: PPRIVILEGE_SET,
        Result: PBOOLEAN,
    ) -> NTSTATUS;
    pub fn NtPrivilegeObjectAuditAlarm(
        SubsystemName: PUNICODE_STRING,
        HandleId: PVOID,
        ClientToken: HANDLE,
        DesiredAccess: ACCESS_MASK,
        Privileges: PPRIVILEGE_SET,
        AccessGranted: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtPrivilegedServiceAuditAlarm(
        SubsystemName: PUNICODE_STRING,
        ServiceName: PUNICODE_STRING,
        ClientToken: HANDLE,
        Privileges: PPRIVILEGE_SET,
        AccessGranted: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtPropagationComplete(
        ResourceManagerHandle: HANDLE,
        RequestCookie: ULONG,
        BufferLength: ULONG,
        Buffer: PVOID,
    ) -> NTSTATUS;
    pub fn NtPropagationFailed(
        ResourceManagerHandle: HANDLE,
        RequestCookie: ULONG,
        PropStatus: NTSTATUS,
    ) -> NTSTATUS;
    pub fn NtProtectVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: PSIZE_T,
        NewProtect: ULONG,
        OldProtect: PULONG,
    ) -> NTSTATUS;
    // TODO NtPssCaptureVaSpaceBulk

    pub fn NtPulseEvent(EventHandle: HANDLE, PreviousState: PLONG) -> NTSTATUS;
    pub fn NtQueryAttributesFile(
        ObjectAttributes: POBJECT_ATTRIBUTES,
        FileInformation: PFILE_BASIC_INFORMATION,
    ) -> NTSTATUS;
    // TODO NtQueryAuxiliaryCounterFrequency

    pub fn NtQueryBootEntryOrder(Ids: PULONG, Count: PULONG) -> NTSTATUS;
    pub fn NtQueryBootOptions(BootOptions: PBOOT_OPTIONS, BootOptionsLength: PULONG) -> NTSTATUS;
    pub fn NtQueryDebugFilterState(ComponentId: ULONG, Level: ULONG) -> NTSTATUS;
    pub fn NtQueryDefaultLocale(UserProfile: BOOLEAN, DefaultLocaleId: PLCID) -> NTSTATUS;
    pub fn NtQueryDefaultUILanguage(DefaultUILanguageId: *mut LANGID) -> NTSTATUS;
    pub fn NtQueryDirectoryFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: PVOID,
        IoStatusBlock: PIO_STATUS_BLOCK,
        FileInformation: PVOID,
        Length: ULONG,
        FileInformationClass: FILE_INFORMATION_CLASS,
        ReturnSingleEntry: BOOLEAN,
        FileName: PUNICODE_STRING,
        RestartScan: BOOLEAN,
    ) -> NTSTATUS;
    // TODO NtQueryDirectoryFileEx

    pub fn NtQueryDirectoryObject(
        DirectoryHandle: HANDLE,
        Buffer: PVOID,
        Length: ULONG,
        ReturnSingleEntry: BOOLEAN,
        RestartScan: BOOLEAN,
        Context: PULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryDriverEntryOrder(Ids: PULONG, Count: PULONG) -> NTSTATUS;
    pub fn NtQueryEaFile(
        FileHandle: HANDLE,
        IoStatusBlock: PIO_STATUS_BLOCK,
        Buffer: PVOID,
        Length: ULONG,
        ReturnSingleEntry: BOOLEAN,
        EaList: PVOID,
        EaListLength: ULONG,
        EaIndex: PULONG,
        RestartScan: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtQueryEvent(
        EventHandle: HANDLE,
        EventInformationClass: EVENT_INFORMATION_CLASS,
        EventInformation: PVOID,
        EventInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryFullAttributesFile(
        ObjectAttributes: POBJECT_ATTRIBUTES,
        FileInformation: PFILE_NETWORK_OPEN_INFORMATION,
    ) -> NTSTATUS;
    pub fn NtQueryInformationAtom(
        Atom: RTL_ATOM,
        AtomInformationClass: ATOM_INFORMATION_CLASS,
        AtomInformation: PVOID,
        AtomInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryInformationByName(
        ObjectAttributes: POBJECT_ATTRIBUTES,
        IoStatusBlock: PIO_STATUS_BLOCK,
        FileInformation: PVOID,
        Length: ULONG,
        FileInformationClass: FILE_INFORMATION_CLASS,
    ) -> NTSTATUS;
    pub fn NtQueryInformationEnlistment(
        EnlistmentHandle: HANDLE,
        EnlistmentInformationClass: ENLISTMENT_INFORMATION_CLASS,
        EnlistmentInformation: PVOID,
        EnlistmentInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryInformationFile(
        FileHandle: HANDLE,
        IoStatusBlock: PIO_STATUS_BLOCK,
        FileInformation: PVOID,
        Length: ULONG,
        FileInformationClass: FILE_INFORMATION_CLASS,
    ) -> NTSTATUS;
    pub fn NtQueryInformationJobObject(
        JobHandle: HANDLE,
        JobObjectInformationClass: JOBOBJECTINFOCLASS,
        JobObjectInformation: PVOID,
        JobObjectInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryInformationPort(
        PortHandle: HANDLE,
        PortInformationClass: PORT_INFORMATION_CLASS,
        PortInformation: PVOID,
        Length: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: PROCESSINFOCLASS,
        ProcessInformation: PVOID,
        ProcessInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryInformationResourceManager(
        ResourceManagerHandle: HANDLE,
        ResourceManagerInformationClass: RESOURCEMANAGER_INFORMATION_CLASS,
        ResourceManagerInformation: PVOID,
        ResourceManagerInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryInformationThread(
        ThreadHandle: HANDLE,
        ThreadInformationClass: THREADINFOCLASS,
        ThreadInformation: PVOID,
        ThreadInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryInformationToken(
        TokenHandle: HANDLE,
        TokenInformationClass: TOKEN_INFORMATION_CLASS,
        TokenInformation: PVOID,
        TokenInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryInformationTransaction(
        TransactionHandle: HANDLE,
        TransactionInformationClass: TRANSACTION_INFORMATION_CLASS,
        TransactionInformation: PVOID,
        TransactionInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryInformationTransactionManager(
        TransactionManagerHandle: HANDLE,
        TransactionManagerInformationClass: TRANSACTIONMANAGER_INFORMATION_CLASS,
        TransactionManagerInformation: PVOID,
        TransactionManagerInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryInformationWorkerFactory(
        WorkerFactoryHandle: HANDLE,
        WorkerFactoryInformationClass: WORKERFACTORYINFOCLASS,
        WorkerFactoryInformation: PVOID,
        WorkerFactoryInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryInstallUILanguage(InstallUILanguageId: *mut LANGID) -> NTSTATUS;
    pub fn NtQueryIntervalProfile(ProfileSource: KPROFILE_SOURCE, Interval: PULONG) -> NTSTATUS;
    pub fn NtQueryIoCompletion(
        IoCompletionHandle: HANDLE,
        IoCompletionInformationClass: IO_COMPLETION_INFORMATION_CLASS,
        IoCompletionInformation: PVOID,
        IoCompletionInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    // TODO NtQueryIoRingCapabilities

    pub fn NtQueryKey(
        KeyHandle: HANDLE,
        KeyInformationClass: KEY_INFORMATION_CLASS,
        KeyInformation: PVOID,
        Length: ULONG,
        ResultLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryLicenseValue(
        ValueName: PUNICODE_STRING,
        Type: PULONG,
        Data: PVOID,
        DataSize: ULONG,
        ResultDataSize: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryMultipleValueKey(
        KeyHandle: HANDLE,
        ValueEntries: PKEY_VALUE_ENTRY,
        EntryCount: ULONG,
        ValueBuffer: PVOID,
        BufferLength: PULONG,
        RequiredBufferLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryMutant(
        MutantHandle: HANDLE,
        MutantInformationClass: MUTANT_INFORMATION_CLASS,
        MutantInformation: PVOID,
        MutantInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryObject(
        Handle: HANDLE,
        ObjectInformationClass: OBJECT_INFORMATION_CLASS,
        ObjectInformation: PVOID,
        ObjectInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryOpenSubKeys(TargetKey: POBJECT_ATTRIBUTES, HandleCount: PULONG) -> NTSTATUS;
    pub fn NtQueryOpenSubKeysEx(
        TargetKey: POBJECT_ATTRIBUTES,
        BufferLength: ULONG,
        Buffer: PVOID,
        RequiredSize: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryPerformanceCounter(
        PerformanceCounter: PLARGE_INTEGER,
        PerformanceFrequency: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtQueryPortInformationProcess() -> NTSTATUS;
    pub fn NtQueryQuotaInformationFile(
        FileHandle: HANDLE,
        IoStatusBlock: PIO_STATUS_BLOCK,
        Buffer: PVOID,
        Length: ULONG,
        ReturnSingleEntry: BOOLEAN,
        SidList: PVOID,
        SidListLength: ULONG,
        StartSid: PSID,
        RestartScan: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtQuerySection(
        SectionHandle: HANDLE,
        SectionInformationClass: SECTION_INFORMATION_CLASS,
        SectionInformation: PVOID,
        SectionInformationLength: SIZE_T,
        ReturnLength: PSIZE_T,
    ) -> NTSTATUS;
    pub fn NtQuerySecurityAttributesToken(
        TokenHandle: HANDLE,
        Attributes: PUNICODE_STRING,
        NumberOfAttributes: ULONG,
        Buffer: PVOID,
        Length: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQuerySecurityObject(
        Handle: HANDLE,
        SecurityInformation: SECURITY_INFORMATION,
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
        Length: ULONG,
        LengthNeeded: PULONG,
    ) -> NTSTATUS;
    // TODO NtQuerySecurityPolicy

    pub fn NtQuerySemaphore(
        SemaphoreHandle: HANDLE,
        SemaphoreInformationClass: SEMAPHORE_INFORMATION_CLASS,
        SemaphoreInformation: PVOID,
        SemaphoreInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQuerySymbolicLinkObject(
        LinkHandle: HANDLE,
        LinkTarget: PUNICODE_STRING,
        ReturnedLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQuerySystemEnvironmentValue(
        VariableName: PUNICODE_STRING,
        VariableValue: PWSTR,
        ValueLength: USHORT,
        ReturnLength: PUSHORT,
    ) -> NTSTATUS;
    pub fn NtQuerySystemEnvironmentValueEx(
        VariableName: PUNICODE_STRING,
        VendorGuid: LPGUID,
        Value: PVOID,
        ValueLength: PULONG,
        Attributes: PULONG,
    ) -> NTSTATUS;
    pub fn NtQuerySystemInformation(
        SystemInformationClass: SYSTEM_INFORMATION_CLASS,
        SystemInformation: PVOID,
        SystemInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQuerySystemInformationEx(
        SystemInformationClass: SYSTEM_INFORMATION_CLASS,
        InputBuffer: PVOID,
        InputBufferLength: ULONG,
        SystemInformation: PVOID,
        SystemInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryTimer(
        TimerHandle: HANDLE,
        TimerInformationClass: TIMER_INFORMATION_CLASS,
        TimerInformation: PVOID,
        TimerInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryTimerResolution(
        MaximumTime: PULONG,
        MinimumTime: PULONG,
        CurrentTime: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryValueKey(
        KeyHandle: HANDLE,
        ValueName: PUNICODE_STRING,
        KeyValueInformationClass: KEY_VALUE_INFORMATION_CLASS,
        KeyValueInformation: PVOID,
        Length: ULONG,
        ResultLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        MemoryInformationClass: MEMORY_INFORMATION_CLASS,
        MemoryInformation: PVOID,
        MemoryInformationLength: SIZE_T,
        ReturnLength: PSIZE_T,
    ) -> NTSTATUS;
    pub fn NtQueryVolumeInformationFile(
        FileHandle: HANDLE,
        IoStatusBlock: PIO_STATUS_BLOCK,
        FsInformation: PVOID,
        Length: ULONG,
        FsInformationClass: FS_INFORMATION_CLASS,
    ) -> NTSTATUS;
    pub fn NtQueryWnfStateData(
        StateName: PCWNF_STATE_NAME,
        TypeId: PCWNF_TYPE_ID,
        ExplicitScope: *const VOID,
        ChangeStamp: PWNF_CHANGE_STAMP,
        Buffer: PVOID,
        BufferSize: PULONG,
    ) -> NTSTATUS;
    pub fn NtQueryWnfStateNameInformation(
        StateName: PCWNF_STATE_NAME,
        NameInfoClass: WNF_STATE_NAME_INFORMATION,
        ExplicitScope: *const VOID,
        InfoBuffer: PVOID,
        InfoBufferSize: ULONG,
    ) -> NTSTATUS;
    pub fn NtQueueApcThread(
        ThreadHandle: HANDLE,
        ApcRoutine: PPS_APC_ROUTINE,
        ApcArgument1: PVOID,
        ApcArgument2: PVOID,
        ApcArgument3: PVOID,
    ) -> NTSTATUS;
    pub fn NtQueueApcThreadEx(
        ThreadHandle: HANDLE,
        UserApcReserveHandle: HANDLE,
        ApcRoutine: PPS_APC_ROUTINE,
        ApcArgument1: PVOID,
        ApcArgument2: PVOID,
        ApcArgument3: PVOID,
    ) -> NTSTATUS;
    // TODO NtQueueApcThreadEx2

    pub fn NtRaiseException(
        ExceptionRecord: PEXCEPTION_RECORD,
        ContextRecord: PCONTEXT,
        FirstChance: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtRaiseHardError(
        ErrorStatus: NTSTATUS,
        NumberOfParameters: ULONG,
        UnicodeStringParameterMask: ULONG,
        Parameters: PULONG_PTR,
        ValidResponseOptions: ULONG,
        Response: PULONG,
    ) -> NTSTATUS;
    pub fn NtReadFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: PVOID,
        IoStatusBlock: PIO_STATUS_BLOCK,
        Buffer: PVOID,
        Length: ULONG,
        ByteOffset: PLARGE_INTEGER,
        Key: PULONG,
    ) -> NTSTATUS;
    pub fn NtReadFileScatter(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: PVOID,
        IoStatusBlock: PIO_STATUS_BLOCK,
        SegmentArray: PFILE_SEGMENT_ELEMENT,
        Length: ULONG,
        ByteOffset: PLARGE_INTEGER,
        Key: PULONG,
    ) -> NTSTATUS;
    pub fn NtReadOnlyEnlistment(
        EnlistmentHandle: HANDLE,
        TmVirtualClock: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtReadRequestData(
        PortHandle: HANDLE,
        Message: PPORT_MESSAGE,
        DataEntryIndex: ULONG,
        Buffer: PVOID,
        BufferSize: SIZE_T,
        NumberOfBytesRead: PSIZE_T,
    ) -> NTSTATUS;
    pub fn NtReadVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        Buffer: PVOID,
        BufferSize: SIZE_T,
        NumberOfBytesRead: PSIZE_T,
    ) -> NTSTATUS;
    // TODO NtReadVirtualMemoryEx

    pub fn NtRecoverEnlistment(EnlistmentHandle: HANDLE, EnlistmentKey: PVOID) -> NTSTATUS;
    pub fn NtRecoverResourceManager(ResourceManagerHandle: HANDLE) -> NTSTATUS;
    pub fn NtRecoverTransactionManager(TransactionManagerHandle: HANDLE) -> NTSTATUS;
    pub fn NtRegisterProtocolAddressInformation(
        ResourceManager: HANDLE,
        ProtocolId: PCRM_PROTOCOL_ID,
        ProtocolInformationSize: ULONG,
        ProtocolInformation: PVOID,
        CreateOptions: ULONG,
    ) -> NTSTATUS;
    pub fn NtRegisterThreadTerminatePort(PortHandle: HANDLE) -> NTSTATUS;
    pub fn NtReleaseKeyedEvent(
        KeyedEventHandle: HANDLE,
        KeyValue: PVOID,
        Alertable: BOOLEAN,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtReleaseMutant(MutantHandle: HANDLE, PreviousCount: PLONG) -> NTSTATUS;
    pub fn NtReleaseSemaphore(
        SemaphoreHandle: HANDLE,
        ReleaseCount: LONG,
        PreviousCount: PLONG,
    ) -> NTSTATUS;
    pub fn NtReleaseWorkerFactoryWorker(WorkerFactoryHandle: HANDLE) -> NTSTATUS;
    pub fn NtRemoveIoCompletion(
        IoCompletionHandle: HANDLE,
        KeyContext: *mut PVOID,
        ApcContext: *mut PVOID,
        IoStatusBlock: PIO_STATUS_BLOCK,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtRemoveIoCompletionEx(
        IoCompletionHandle: HANDLE,
        IoCompletionInformation: PFILE_IO_COMPLETION_INFORMATION,
        Count: ULONG,
        NumEntriesRemoved: PULONG,
        Timeout: PLARGE_INTEGER,
        Alertable: BOOLEAN,
    ) -> NTSTATUS;
    pub fn NtRemoveProcessDebug(ProcessHandle: HANDLE, DebugObjectHandle: HANDLE) -> NTSTATUS;
    pub fn NtRenameKey(KeyHandle: HANDLE, NewName: PUNICODE_STRING) -> NTSTATUS;
    pub fn NtRenameTransactionManager(
        LogFileName: PUNICODE_STRING,
        ExistingTransactionManagerGuid: LPGUID,
    ) -> NTSTATUS;
    pub fn NtReplaceKey(
        NewFile: POBJECT_ATTRIBUTES,
        TargetHandle: HANDLE,
        OldFile: POBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    pub fn NtReplacePartitionUnit(
        TargetInstancePath: PUNICODE_STRING,
        SpareInstancePath: PUNICODE_STRING,
        Flags: ULONG,
    ) -> NTSTATUS;
    pub fn NtReplyPort(PortHandle: HANDLE, ReplyMessage: PPORT_MESSAGE) -> NTSTATUS;
    pub fn NtReplyWaitReceivePort(
        PortHandle: HANDLE,
        PortContext: *mut PVOID,
        ReplyMessage: PPORT_MESSAGE,
        ReceiveMessage: PPORT_MESSAGE,
    ) -> NTSTATUS;
    pub fn NtReplyWaitReceivePortEx(
        PortHandle: HANDLE,
        PortContext: *mut PVOID,
        ReplyMessage: PPORT_MESSAGE,
        ReceiveMessage: PPORT_MESSAGE,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtReplyWaitReplyPort(PortHandle: HANDLE, ReplyMessage: PPORT_MESSAGE) -> NTSTATUS;
    pub fn NtRequestPort(PortHandle: HANDLE, RequestMessage: PPORT_MESSAGE) -> NTSTATUS;
    pub fn NtRequestWaitReplyPort(
        PortHandle: HANDLE,
        RequestMessage: PPORT_MESSAGE,
        ReplyMessage: PPORT_MESSAGE,
    ) -> NTSTATUS;
    pub fn NtResetEvent(EventHandle: HANDLE, PreviousState: PLONG) -> NTSTATUS;
    pub fn NtResetWriteWatch(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        RegionSize: SIZE_T,
    ) -> NTSTATUS;
    pub fn NtRestoreKey(KeyHandle: HANDLE, FileHandle: HANDLE, Flags: ULONG) -> NTSTATUS;
    pub fn NtResumeProcess(ProcessHandle: HANDLE) -> NTSTATUS;
    pub fn NtResumeThread(ThreadHandle: HANDLE, PreviousSuspendCount: PULONG) -> NTSTATUS;
    pub fn NtRevertContainerImpersonation() -> NTSTATUS;
    pub fn NtRollbackComplete(EnlistmentHandle: HANDLE, TmVirtualClock: PLARGE_INTEGER)
        -> NTSTATUS;
    pub fn NtRollbackEnlistment(
        EnlistmentHandle: HANDLE,
        TmVirtualClock: PLARGE_INTEGER,
    ) -> NTSTATUS;
    // TODO NtRollbackRegistryTransaction

    pub fn NtRollbackTransaction(TransactionHandle: HANDLE, Wait: BOOLEAN) -> NTSTATUS;
    pub fn NtRollforwardTransactionManager(
        TransactionManagerHandle: HANDLE,
        TmVirtualClock: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtSaveKey(KeyHandle: HANDLE, FileHandle: HANDLE) -> NTSTATUS;
    pub fn NtSaveKeyEx(KeyHandle: HANDLE, FileHandle: HANDLE, Format: ULONG) -> NTSTATUS;
    pub fn NtSaveMergedKeys(
        HighPrecedenceKeyHandle: HANDLE,
        LowPrecedenceKeyHandle: HANDLE,
        FileHandle: HANDLE,
    ) -> NTSTATUS;
    pub fn NtSecureConnectPort(
        PortHandle: PHANDLE,
        PortName: PUNICODE_STRING,
        SecurityQos: PSECURITY_QUALITY_OF_SERVICE,
        ClientView: PPORT_VIEW,
        RequiredServerSid: PSID,
        ServerView: PREMOTE_PORT_VIEW,
        MaxMessageLength: PULONG,
        ConnectionInformation: PVOID,
        ConnectionInformationLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtSerializeBoot() -> NTSTATUS;
    pub fn NtSetBootEntryOrder(Ids: PULONG, Count: ULONG) -> NTSTATUS;
    pub fn NtSetBootOptions(BootOptions: PBOOT_OPTIONS, FieldsToChange: ULONG) -> NTSTATUS;
    pub fn NtSetCachedSigningLevel(
        Flags: ULONG,
        InputSigningLevel: SE_SIGNING_LEVEL,
        SourceFiles: PHANDLE,
        SourceFileCount: ULONG,
        TargetFile: HANDLE,
    ) -> NTSTATUS;
    // TODO NtSetCachedSigningLevel2

    pub fn NtSetContextThread(ThreadHandle: HANDLE, ThreadContext: PCONTEXT) -> NTSTATUS;
    pub fn NtSetDebugFilterState(ComponentId: ULONG, Level: ULONG, State: BOOLEAN) -> NTSTATUS;
    pub fn NtSetDefaultHardErrorPort(DefaultHardErrorPort: HANDLE) -> NTSTATUS;
    pub fn NtSetDefaultLocale(UserProfile: BOOLEAN, DefaultLocaleId: LCID) -> NTSTATUS;
    pub fn NtSetDefaultUILanguage(DefaultUILanguageId: LANGID) -> NTSTATUS;
    pub fn NtSetDriverEntryOrder(Ids: PULONG, Count: ULONG) -> NTSTATUS;
    pub fn NtSetEaFile(
        FileHandle: HANDLE,
        IoStatusBlock: PIO_STATUS_BLOCK,
        Buffer: PVOID,
        Length: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetEvent(EventHandle: HANDLE, PreviousState: PLONG) -> NTSTATUS;
    pub fn NtSetEventBoostPriority(EventHandle: HANDLE) -> NTSTATUS;
    pub fn NtSetHighEventPair(EventPairHandle: HANDLE) -> NTSTATUS;
    pub fn NtSetHighWaitLowEventPair(EventPairHandle: HANDLE) -> NTSTATUS;
    pub fn NtSetIRTimer(TimerHandle: HANDLE, DueTime: PLARGE_INTEGER) -> NTSTATUS;
    pub fn NtSetInformationDebugObject(
        DebugObjectHandle: HANDLE,
        DebugObjectInformationClass: DEBUGOBJECTINFOCLASS,
        DebugInformation: PVOID,
        DebugInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtSetInformationEnlistment(
        EnlistmentHandle: HANDLE,
        EnlistmentInformationClass: ENLISTMENT_INFORMATION_CLASS,
        EnlistmentInformation: PVOID,
        EnlistmentInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetInformationFile(
        FileHandle: HANDLE,
        IoStatusBlock: PIO_STATUS_BLOCK,
        FileInformation: PVOID,
        Length: ULONG,
        FileInformationClass: FILE_INFORMATION_CLASS,
    ) -> NTSTATUS;
    // TODO NtSetInformationIoRing

    pub fn NtSetInformationJobObject(
        JobHandle: HANDLE,
        JobObjectInformationClass: JOBOBJECTINFOCLASS,
        JobObjectInformation: PVOID,
        JobObjectInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetInformationKey(
        KeyHandle: HANDLE,
        KeySetInformationClass: KEY_SET_INFORMATION_CLASS,
        KeySetInformation: PVOID,
        KeySetInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetInformationObject(
        Handle: HANDLE,
        ObjectInformationClass: OBJECT_INFORMATION_CLASS,
        ObjectInformation: PVOID,
        ObjectInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: PROCESSINFOCLASS,
        ProcessInformation: PVOID,
        ProcessInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetInformationResourceManager(
        ResourceManagerHandle: HANDLE,
        ResourceManagerInformationClass: RESOURCEMANAGER_INFORMATION_CLASS,
        ResourceManagerInformation: PVOID,
        ResourceManagerInformationLength: ULONG,
    ) -> NTSTATUS;
    // TODO NtSetInformationSymbolicLink

    pub fn NtSetInformationThread(
        ThreadHandle: HANDLE,
        ThreadInformationClass: THREADINFOCLASS,
        ThreadInformation: PVOID,
        ThreadInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetInformationToken(
        TokenHandle: HANDLE,
        TokenInformationClass: TOKEN_INFORMATION_CLASS,
        TokenInformation: PVOID,
        TokenInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetInformationTransaction(
        TransactionHandle: HANDLE,
        TransactionInformationClass: TRANSACTION_INFORMATION_CLASS,
        TransactionInformation: PVOID,
        TransactionInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetInformationTransactionManager(
        TmHandle: HANDLE,
        TransactionManagerInformationClass: TRANSACTIONMANAGER_INFORMATION_CLASS,
        TransactionManagerInformation: PVOID,
        TransactionManagerInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetInformationVirtualMemory(
        ProcessHandle: HANDLE,
        VmInformationClass: VIRTUAL_MEMORY_INFORMATION_CLASS,
        NumberOfEntries: ULONG_PTR,
        VirtualAddresses: PMEMORY_RANGE_ENTRY,
        VmInformation: PVOID,
        VmInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetInformationWorkerFactory(
        WorkerFactoryHandle: HANDLE,
        WorkerFactoryInformationClass: WORKERFACTORYINFOCLASS,
        WorkerFactoryInformation: PVOID,
        WorkerFactoryInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetIntervalProfile(Interval: ULONG, Source: KPROFILE_SOURCE) -> NTSTATUS;
    pub fn NtSetIoCompletion(
        IoCompletionHandle: HANDLE,
        KeyContext: PVOID,
        ApcContext: PVOID,
        IoStatus: NTSTATUS,
        IoStatusInformation: ULONG_PTR,
    ) -> NTSTATUS;
    pub fn NtSetIoCompletionEx(
        IoCompletionHandle: HANDLE,
        IoCompletionPacketHandle: HANDLE,
        KeyContext: PVOID,
        ApcContext: PVOID,
        IoStatus: NTSTATUS,
        IoStatusInformation: ULONG_PTR,
    ) -> NTSTATUS;
    pub fn NtSetLdtEntries(
        Selector0: ULONG,
        Entry0Low: ULONG,
        Entry0Hi: ULONG,
        Selector1: ULONG,
        Entry1Low: ULONG,
        Entry1Hi: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetLowEventPair(EventPairHandle: HANDLE) -> NTSTATUS;
    pub fn NtSetLowWaitHighEventPair(EventPairHandle: HANDLE) -> NTSTATUS;
    pub fn NtSetQuotaInformationFile(
        FileHandle: HANDLE,
        IoStatusBlock: PIO_STATUS_BLOCK,
        Buffer: PVOID,
        Length: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetSecurityObject(
        Handle: HANDLE,
        SecurityInformation: SECURITY_INFORMATION,
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
    ) -> NTSTATUS;
    pub fn NtSetSystemEnvironmentValue(
        VariableName: PUNICODE_STRING,
        VariableValue: PUNICODE_STRING,
    ) -> NTSTATUS;
    pub fn NtSetSystemEnvironmentValueEx(
        VariableName: PUNICODE_STRING,
        VendorGuid: LPGUID,
        Value: PVOID,
        ValueLength: ULONG,
        Attributes: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetSystemInformation(
        SystemInformationClass: SYSTEM_INFORMATION_CLASS,
        SystemInformation: PVOID,
        SystemInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetSystemPowerState(
        SystemAction: POWER_ACTION,
        LightestSystemState: SYSTEM_POWER_STATE,
        Flags: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetSystemTime(SystemTime: PLARGE_INTEGER, PreviousTime: PLARGE_INTEGER) -> NTSTATUS;
    pub fn NtSetThreadExecutionState(
        NewFlags: EXECUTION_STATE,
        PreviousFlags: PEXECUTION_STATE,
    ) -> NTSTATUS;
    pub fn NtSetTimer(
        TimerHandle: HANDLE,
        DueTime: PLARGE_INTEGER,
        TimerApcRoutine: PTIMER_APC_ROUTINE,
        TimerContext: PVOID,
        ResumeTimer: BOOLEAN,
        Period: LONG,
        PreviousState: PBOOLEAN,
    ) -> NTSTATUS;
    pub fn NtSetTimer2(
        TimerHandle: HANDLE,
        DueTime: PLARGE_INTEGER,
        Period: PLARGE_INTEGER,
        Parameters: PT2_SET_PARAMETERS,
    ) -> NTSTATUS;
    pub fn NtSetTimerEx(
        TimerHandle: HANDLE,
        TimerSetInformationClass: TIMER_SET_INFORMATION_CLASS,
        TimerSetInformation: PVOID,
        TimerSetInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetTimerResolution(
        DesiredTime: ULONG,
        SetResolution: BOOLEAN,
        ActualTime: PULONG,
    ) -> NTSTATUS;
    pub fn NtSetUuidSeed(Seed: PCHAR) -> NTSTATUS;
    pub fn NtSetValueKey(
        KeyHandle: HANDLE,
        ValueName: PUNICODE_STRING,
        TitleIndex: ULONG,
        Type: ULONG,
        Data: PVOID,
        DataSize: ULONG,
    ) -> NTSTATUS;
    pub fn NtSetVolumeInformationFile(
        FileHandle: HANDLE,
        IoStatusBlock: PIO_STATUS_BLOCK,
        FsInformation: PVOID,
        Length: ULONG,
        FsInformationClass: FS_INFORMATION_CLASS,
    ) -> NTSTATUS;
    pub fn NtSetWnfProcessNotificationEvent(NotificationEvent: HANDLE) -> NTSTATUS;
    pub fn NtShutdownSystem(Action: SHUTDOWN_ACTION) -> NTSTATUS;
    pub fn NtShutdownWorkerFactory(
        WorkerFactoryHandle: HANDLE,
        PendingWorkerCount: *mut LONG,
    ) -> NTSTATUS;
    pub fn NtSignalAndWaitForSingleObject(
        SignalHandle: HANDLE,
        WaitHandle: HANDLE,
        Alertable: BOOLEAN,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtSinglePhaseReject(
        EnlistmentHandle: HANDLE,
        TmVirtualClock: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtStartProfile(ProfileHandle: HANDLE) -> NTSTATUS;
    pub fn NtStopProfile(ProfileHandle: HANDLE) -> NTSTATUS;
    // TODO NtSubmitIoRing

    pub fn NtSubscribeWnfStateChange(
        StateName: PCWNF_STATE_NAME,
        ChangeStamp: WNF_CHANGE_STAMP,
        EventMask: ULONG,
        SubscriptionId: PULONG64,
    ) -> NTSTATUS;
    pub fn NtSuspendProcess(ProcessHandle: HANDLE) -> NTSTATUS;
    pub fn NtSuspendThread(ThreadHandle: HANDLE, PreviousSuspendCount: PULONG) -> NTSTATUS;
    pub fn NtSystemDebugControl(
        Command: SYSDBG_COMMAND,
        InputBuffer: PVOID,
        InputBufferLength: ULONG,
        OutputBuffer: PVOID,
        OutputBufferLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    // TODO NtTerminateEnclave

    pub fn NtTerminateJobObject(JobHandle: HANDLE, ExitStatus: NTSTATUS) -> NTSTATUS;
    pub fn NtTerminateProcess(ProcessHandle: HANDLE, ExitStatus: NTSTATUS) -> NTSTATUS;
    pub fn NtTerminateThread(ThreadHandle: HANDLE, ExitStatus: NTSTATUS) -> NTSTATUS;
    pub fn NtTestAlert() -> NTSTATUS;
    pub fn NtThawRegistry() -> NTSTATUS;
    pub fn NtThawTransactions() -> NTSTATUS;
    pub fn NtTraceControl(
        FunctionCode: ULONG,
        InBuffer: PVOID,
        InBufferLen: ULONG,
        OutBuffer: PVOID,
        OutBufferLen: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtTraceEvent(
        TraceHandle: HANDLE,
        Flags: ULONG,
        FieldSize: ULONG,
        Fields: PVOID,
    ) -> NTSTATUS;
    pub fn NtTranslateFilePath(
        InputFilePath: PFILE_PATH,
        OutputType: ULONG,
        OutputFilePath: PFILE_PATH,
        OutputFilePathLength: PULONG,
    ) -> NTSTATUS;
    pub fn NtUmsThreadYield(SchedulerParam: PVOID) -> NTSTATUS;
    pub fn NtUnloadDriver(DriverServiceName: PUNICODE_STRING) -> NTSTATUS;
    pub fn NtUnloadKey(TargetKey: POBJECT_ATTRIBUTES) -> NTSTATUS;
    pub fn NtUnloadKey2(TargetKey: POBJECT_ATTRIBUTES, Flags: ULONG) -> NTSTATUS;
    pub fn NtUnloadKeyEx(TargetKey: POBJECT_ATTRIBUTES, Event: HANDLE) -> NTSTATUS;
    pub fn NtUnlockFile(
        FileHandle: HANDLE,
        IoStatusBlock: PIO_STATUS_BLOCK,
        ByteOffset: PLARGE_INTEGER,
        Length: PLARGE_INTEGER,
        Key: ULONG,
    ) -> NTSTATUS;
    pub fn NtUnlockVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: PSIZE_T,
        MapType: ULONG,
    ) -> NTSTATUS;
    pub fn NtUnmapViewOfSection(ProcessHandle: HANDLE, BaseAddress: PVOID) -> NTSTATUS;
    pub fn NtUnmapViewOfSectionEx(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        Flags: ULONG,
    ) -> NTSTATUS;
    pub fn NtUnsubscribeWnfStateChange(StateName: PCWNF_STATE_NAME) -> NTSTATUS;
    pub fn NtUpdateWnfStateData(
        StateName: PCWNF_STATE_NAME,
        Buffer: *const VOID,
        Length: ULONG,
        TypeId: PCWNF_TYPE_ID,
        ExplicitScope: *const VOID,
        MatchingChangeStamp: WNF_CHANGE_STAMP,
        CheckStamp: LOGICAL,
    ) -> NTSTATUS;
    pub fn NtVdmControl(Service: VDMSERVICECLASS, ServiceData: PVOID) -> NTSTATUS;
    pub fn NtWaitForAlertByThreadId(Address: PVOID, Timeout: PLARGE_INTEGER) -> NTSTATUS;
    pub fn NtWaitForDebugEvent(
        DebugObjectHandle: HANDLE,
        Alertable: BOOLEAN,
        Timeout: PLARGE_INTEGER,
        WaitStateChange: PVOID,
    ) -> NTSTATUS;
    pub fn NtWaitForKeyedEvent(
        KeyedEventHandle: HANDLE,
        KeyValue: PVOID,
        Alertable: BOOLEAN,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtWaitForMultipleObjects(
        Count: ULONG,
        Handles: *mut HANDLE,
        WaitType: WAIT_TYPE,
        Alertable: BOOLEAN,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtWaitForMultipleObjects32(
        Count: ULONG,
        Handles: *mut LONG,
        WaitType: WAIT_TYPE,
        Alertable: BOOLEAN,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtWaitForSingleObject(
        Handle: HANDLE,
        Alertable: BOOLEAN,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;
    pub fn NtWaitForWorkViaWorkerFactory(
        WorkerFactoryHandle: HANDLE,
        MiniPacket: *mut FILE_IO_COMPLETION_INFORMATION,
    ) -> NTSTATUS;
    pub fn NtWaitHighEventPair(EventPairHandle: HANDLE) -> NTSTATUS;
    pub fn NtWaitLowEventPair(EventPairHandle: HANDLE) -> NTSTATUS;
    pub fn NtWorkerFactoryWorkerReady(WorkerFactoryHandle: HANDLE) -> NTSTATUS;
    pub fn NtWriteFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: PVOID,
        IoStatusBlock: PIO_STATUS_BLOCK,
        Buffer: PVOID,
        Length: ULONG,
        ByteOffset: PLARGE_INTEGER,
        Key: PULONG,
    ) -> NTSTATUS;
    pub fn NtWriteFileGather(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: PVOID,
        IoStatusBlock: PIO_STATUS_BLOCK,
        SegmentArray: PFILE_SEGMENT_ELEMENT,
        Length: ULONG,
        ByteOffset: PLARGE_INTEGER,
        Key: PULONG,
    ) -> NTSTATUS;
    pub fn NtWriteRequestData(
        PortHandle: HANDLE,
        Message: PPORT_MESSAGE,
        DataEntryIndex: ULONG,
        Buffer: PVOID,
        BufferSize: SIZE_T,
        NumberOfBytesWritten: PSIZE_T,
    ) -> NTSTATUS;
    pub fn NtWriteVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        Buffer: PVOID,
        BufferSize: SIZE_T,
        NumberOfBytesWritten: PSIZE_T,
    ) -> NTSTATUS;
    pub fn NtYieldExecution() -> NTSTATUS;
}

global_asm!(
    r#"
.macro define_syscall name, id
.global \name
\name:
    mov r10, rcx
    mov eax, \id
    syscall
    ret
.endm
"#
);

global_asm!(include_str!("../resources/syscall_ids"));

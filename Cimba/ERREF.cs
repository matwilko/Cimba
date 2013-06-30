namespace Cimba
{
    using System.Diagnostics.CodeAnalysis;

    [SuppressMessage("StyleCop.CSharp.NamingRules", "SA1310:FieldNamesMustNotContainUnderscore", Justification = "Based on Microsoft Documentation, verbatim name of constants")]
    public static class NTSTATUS
    {
        internal const uint STATUS_SUCCESS = 0x00000000;
        internal const uint STATUS_LOGON_FAILURE = 0xC000006D;
        internal const uint STATUS_BAD_NETWORK_NAME = 0xC00000CC;
        internal const uint STATUS_ACCESS_DENIED = 0xC0000022;
        internal const uint STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016;
        internal const uint STATUS_USER_SESSION_DELETED = 0xC0000203;
        internal const uint STATUS_INVALID_PARAMETER = 0xC000000D;
        internal const uint STATUS_FS_DRIVER_REQUIRED = 0xC000019C;
        internal const uint STATUS_NOT_SUPPORTED = 0xC00000BB;
        internal const uint STATUS_NETWORK_NAME_DELETED = 0xC00000C9;
        internal const uint STATUS_FILE_CLOSED = 0xC0000128;
        internal const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;
        internal const uint STATUS_NO_MORE_FILES = 0x80000006;
    }
}

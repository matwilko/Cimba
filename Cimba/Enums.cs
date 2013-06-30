namespace Cimba
{
    using System;

    public enum SmbVersion
    {
        V20,
        V21
    }

    [Flags]
    public enum FileAccess
    {
        None = 0,
        Read = 1,
        Write = 2,
        Append = 4,
        Delete = 8,
        Execute = 16
    }

    [Flags]
    public enum PipeAccess
    {
        None = 0,
        Read = 1,
        Write = 2,
        Append = 4
    }

    [Flags]
    public enum Access
    {
        None = 0,
        Read = 1,
        Write = 2,
        ReadWrite = Read | Write
    }

    [Flags]
    public enum ImpersonationLevel
    {
        Anonymous,
        Identification,
        Impersonation,
        Delegate
    }

    [Flags]
    public enum OppurtunisticLockLevel
    {
        None = 0,
        II = 1,
        Exclusive = 2,
        Batch = 3
    }

    [Flags]
    public enum ShareAccess
    {
        Read = 0,
        Write = 1,
        Delete = 2
    }

    public enum OpenDisposition
    {
        Supersede = 1,
        Open = 2,
        Overwrite = 4
    }

    public enum CreateDisposition
    {
        Supersede,
        Open,
        Create,
        OpenOrCreate,
        Overwrite,
        OverwriteOrCreate
    }
}
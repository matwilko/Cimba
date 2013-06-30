namespace Cimba.Protocol
{
using System;

    internal static class AccessMask
    {
        [Flags]
        internal enum File_Pipe_Printer : uint
        {
            READ_DATA = 0x00000001,
            WRITE_DATA = 0x00000002,
            APPEND_DATA = 0x00000004,
            READ_EA = 0x00000008,
            WRITE_EA = 0x00000010,
            EXECUTE = 0x00000020,
            READ_ATTRIBUTES = 0x00000080,
            WRITE_ATTRIBUTES = 0x00000100,
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            ACCESS_SYSTEM_SECURITY = 0x01000000,
            MAXIMUM_ALLOWED = 0x02000000,
            GENERIC_ALL = 0x10000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_READ = 0x80000000
        }

        [Flags]
        internal enum Directory : uint
        {
            LIST_DIRECTORY = 0x00000001,
            ADD_FILE = 0x00000002,
            ADD_SUBDIRECTORY = 0x00000004,
            READ_EA = 0x00000008,
            WRITE_EA = 0x00000010,
            TRAVERSE = 0x00000020,
            DELETE_CHILD = 0x00000040,
            READ_ATTRIBUTES = 0x00000080,
            WRITE_ATTRIBUTES = 0x0000100,
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            ACCESS_SYSTEM_SECURITY = 0x01000000,
            MAXIMUM_ALLOWED = 0x02000000,
            GENERIC_ALL = 0x10000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_READ = 0x80000000
        }
    }
}

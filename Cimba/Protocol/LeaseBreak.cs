namespace Cimba.Protocol
{
    internal enum LeaseState : uint
    {
        NONE = 0x00000000,
        READ_CACHING = 0x00000001,
        HANDLE_CACHING = 0x00000002,
        WRITE_CACHING = 0x00000004
    }
}

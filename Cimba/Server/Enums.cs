namespace Cimba.Server
{
    public enum ClientSideCaching
    {
        Manual,
        Automatic,
        VDO,
        None
    }

    public enum ShareType
    {
        DiskDrive,
        PrintQueue,
        Device,
        InterProcessCommunication
    }
}
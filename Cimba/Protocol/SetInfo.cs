namespace Cimba.Protocol
{
    internal enum SetInfo_FileInformationClass : byte
    {
        AllocationInformation = 19,
        BasicInformation = 4,
        DispositionInformation = 13,
        EndofFileInformation = 20,
        FullEaInformation = 15,
        LinkInformation = 11,
        ModeInformation = 16,
        PipeInformation = 23,
        PositionInformation = 14,
        RenameInformation = 10,
        ShortNameInformation = 40,
        ValidDataLengthInformation = 39
    }

    internal enum SetInfo_FileSystemInformationClass : byte
    {
        FsControlInformation = 6,
        FsObjectIdInformation = 8
    }
}

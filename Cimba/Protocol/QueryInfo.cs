namespace Cimba.Protocol
{
    internal enum InfoType : byte
    {
        FILE = 0x01,
        FILESYSTEM = 0x02,
        SECURITY = 0x03,
        QUOTA = 0x04
    }

    internal enum QueryInfo_FileInformationClass : byte
    {
        AccessInformation = 8,
        AlignmentInformation = 17,
        AllInformation = 18,
        AlternateNameInformation = 21,
        AttributeTagInformation = 35,
        BasicInformation = 4,
        CompressionInformation = 28,
        EaInformation = 7,
        FullEaInformation = 15,
        InternalInformation = 6,
        ModeInformation = 16,
        NetworkOpenInformation = 34,
        PipeInformation = 23,
        PipeLocalInformation = 24,
        PipeRemoteInformation = 25,
        PositionInformation = 14,
        StandardInformation = 5,
        StreamInformation = 22
    }

    internal enum QueryInfo_FileSystemInformationClass : byte
    {
        AttributeInformation = 5,
        ControlInformation = 6,
        DeviceInformation = 4,
        FullSizeInformation = 7,
        ObjectIdInformation = 8,
        SizeInformation = 3,
        VolumeInformation = 1
    }

    internal enum QueryAdditionalInformation : uint
    {
        OWNER_SECURITY_INFORMATION = 0x00000001,
        GROUP_SECURITY_INFORMATION = 0x00000002,
        DACL_SECURITY_INFORMATION = 0x00000004,
        SACL_SECURITY_INFORMATION = 0x00000008,
        LABEL_SECURITY_INFORMATION = 0x00000010
    }

    internal enum QueryFlags : uint
    {
        RESTART_SCAN = 0x00000001,
        RETURN_SINGLE_ENTRY = 0x00000002,
        INDEX_SPECIFIED = 0x00000004
    }
}

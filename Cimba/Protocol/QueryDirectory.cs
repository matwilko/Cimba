namespace Cimba.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    internal enum FileInformationClass : byte
    {
        DirectoryInformation = 0x01,
        FullDirectoryInformation = 0x02,
        IdFullDirectoryInformation = 0x26,
        BothDirectoryInformation = 0x03,
        IdBothDirectoryInformation = 0x25,
        NamesInformation = 0x0C
    }

    internal enum QueryDirectory_Flags : byte
    {
        RESTART_SCANS = 0x01,
        RETURN_SINGLE_ENTRY = 0x02,
        INDEX_SPECIFIED = 0x04,
        REOPEN = 0x10
    }

    internal struct FileBothDirectoryInformation
    {
        internal uint NextEntryOffset;
        internal uint FileIndex;
        internal ulong CreationTime;
        internal ulong LastAccessTime;
        internal ulong LastWriteTime;
        internal ulong ChangeTime;
        internal ulong EndOfFile;
        internal ulong AllocationSize;
        internal uint Attributes;
        internal uint EaSize;
        internal string ShortName;
        internal string FileName;

        internal static FileBothDirectoryInformation Read(byte[] buffer, int offset = 0)
        {
            FileBothDirectoryInformation info = new FileBothDirectoryInformation();
            info.NextEntryOffset = BitConverterLE.ToUInt(buffer, offset);
            info.FileIndex = BitConverterLE.ToUInt(buffer, offset + 4);
            info.CreationTime = BitConverterLE.ToULong(buffer, offset + 8);
            info.LastAccessTime = BitConverterLE.ToULong(buffer, offset + 16);
            info.LastWriteTime = BitConverterLE.ToULong(buffer, offset + 24);
            info.ChangeTime = BitConverterLE.ToULong(buffer, offset + 32);
            info.EndOfFile = BitConverterLE.ToULong(buffer, offset + 40);
            info.AllocationSize = BitConverterLE.ToULong(buffer, offset + 48);
            info.Attributes = BitConverterLE.ToUInt(buffer, offset + 56);
            uint fileNameLength = BitConverterLE.ToUInt(buffer, offset + 60);
            info.EaSize = BitConverterLE.ToUInt(buffer, offset + 64);
            byte shortNameLength = buffer[offset + 68];

            byte[] shortnameBuffer = new byte[shortNameLength];
            Array.Copy(buffer, offset + 70, shortnameBuffer, 0, shortNameLength);
            info.ShortName = Encoding.Unicode.GetString(shortnameBuffer);

            byte[] filenameBuffer = new byte[fileNameLength];
            Array.Copy(buffer, offset + 94, filenameBuffer, 0, fileNameLength);
            info.FileName = Encoding.Unicode.GetString(filenameBuffer);

            return info;
        }

        internal static List<FileBothDirectoryInformation> ReadList(byte[] buffer)
        {
            List<FileBothDirectoryInformation> list = new List<FileBothDirectoryInformation>();
            uint nextEntryOffset = 0;
            uint bufferOffset = 0;
            do
            {
                FileBothDirectoryInformation fbdi = FileBothDirectoryInformation.Read(buffer, (int)bufferOffset);
                list.Add(fbdi);
                nextEntryOffset = fbdi.NextEntryOffset;
                bufferOffset += nextEntryOffset;
            }
            while (nextEntryOffset != 0);

            return list;
        }
    }
}

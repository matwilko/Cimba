namespace Cimba.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    internal enum NOTIFY_CHANGE : uint
    {
        FILE_NAME = 0x00000001,
        DIR_NAME = 0x00000002,
        ATTRIBUTES = 0x00000004,
        SIZE = 0x00000008,
        LAST_WRITE = 0x00000010,
        LAST_ACCESS = 0x00000020,
        CREATION = 0x00000040,
        EA = 0x00000080,
        SECURITY = 0x00000100,
        STREAM_NAME = 0x00000200,
        STREAM_SIZE = 0x00000400,
        STREAM_WRITE = 0x00000800
    }

    internal struct FILE_NOTIFY_INFORMATION
    {
        internal uint NextEntryOffset;
        internal uint Action;
        internal string FileName;

        internal FILE_NOTIFY_INFORMATION(uint nextEntryOffset, FILE_ACTION action, string fileName)
        {
            this.NextEntryOffset = nextEntryOffset;
            this.Action = (uint)action;
            this.FileName = fileName;
        }

        internal enum FILE_ACTION : uint
        {
            ADDED = 0x00000001,
            REMOVED = 0x00000002,
            MODIFIED = 0x00000003,
            RENAMED_OLD_NAME = 0x00000004,
            RENAMED_NEW_NAME = 0x00000005
        }

        internal static FILE_NOTIFY_INFORMATION Read(byte[] buffer, int offset = 0)
        {
            FILE_NOTIFY_INFORMATION fni = new FILE_NOTIFY_INFORMATION();
            fni.NextEntryOffset = BitConverterLE.ToUInt(buffer, offset + 0);
            fni.Action = BitConverterLE.ToUInt(buffer, offset + 4);
            uint fileNameLength = BitConverterLE.ToUInt(buffer, offset + 8);
            byte[] namebuffer = new byte[fileNameLength];
            Array.Copy(buffer, offset + 12, namebuffer, 0, fileNameLength);
            fni.FileName = Encoding.Unicode.GetString(namebuffer);
            return fni;
        }

        internal static List<FILE_NOTIFY_INFORMATION> ReadList(byte[] buffer)
        {
            List<FILE_NOTIFY_INFORMATION> list = new List<FILE_NOTIFY_INFORMATION>();
            int offset = 0;
            do
            {
                FILE_NOTIFY_INFORMATION next = Read(buffer, offset);
                offset = (int)next.NextEntryOffset;
                list.Add(next);
            }
            while (offset != 0);

            return list;
        }

        internal byte[] Flatten()
        {
            int length = 12 + Encoding.Unicode.GetByteCount(this.FileName);
            length += 8 - (length % 4);
            byte[] buffer = new byte[length];
            BitConverterLE.GetBytes(this.NextEntryOffset).CopyTo(buffer, 0);
            BitConverterLE.GetBytes(this.Action).CopyTo(buffer, 4);
            BitConverterLE.GetBytes((uint)Encoding.Unicode.GetByteCount(this.FileName)).CopyTo(buffer, 8);
            Encoding.Unicode.GetBytes(this.FileName).CopyTo(buffer, 12);
            return buffer;
        }
    }
}

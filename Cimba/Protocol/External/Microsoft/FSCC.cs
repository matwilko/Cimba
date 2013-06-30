namespace Cimba.Protocol.External.Microsoft
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    internal static class FSCC
    {
        internal enum FILE_ATTRIBUTE : uint
        {
            ARCHIVE = 0x00000020,
            COMPRESSED = 0x00000800,
            DIRECTORY = 0x00000010,
            ENCRYPTED = 0x00004000,
            HIDDEN = 0x00000002,
            NORMAL = 0x00000080,
            NOT_CONTENT_INDEXED = 0x00002000,
            OFFLINE = 0x00001000,
            READONLY = 0x00000001,
            REPARSE_POINT = 0x00000400,
            SPARSE_FILE = 0x00000200,
            SYSTEM = 0x00000004,
            TEMPORARY = 0x00000100
        }

        internal static Dictionary<string, byte[]> ReadFileFullEaInformation(byte[] stream)
        {
            Dictionary<string, byte[]> extendedAttributes = new Dictionary<string, byte[]>();

            uint bufferpos = 0;
            uint nextEntryOffset = BitConverterLE.ToUInt(stream, 0);
            while (nextEntryOffset != 0)
            {
                byte exattrNameLength = stream[bufferpos + 5];
                ushort exattrValueLength = BitConverterLE.ToUShort(stream, (int)(bufferpos + 6));
                byte[] exattrNameBytes = new byte[exattrNameLength];
                byte[] exattrValueBytes = new byte[exattrValueLength];
                Array.Copy(stream, bufferpos + 64, exattrNameBytes, 0, exattrNameLength);
                Array.Copy(stream, bufferpos + 64 + exattrNameLength, exattrValueBytes, 0, exattrValueLength);
                extendedAttributes.Add(Encoding.Unicode.GetString(exattrNameBytes), exattrValueBytes);
            }

            return extendedAttributes;
        }

        internal static byte[] GenerateFileFullEaInformation(Dictionary<string, byte[]> extendedAttributes)
        {
            int bufferlength = 64 * extendedAttributes.Count;
            foreach (KeyValuePair<string, byte[]> entry in extendedAttributes)
            {
                int total = Encoding.ASCII.GetByteCount(entry.Key) + entry.Value.Length;
                bufferlength += total + (8 - (total % 8));
            }

            byte[] buffer = new byte[bufferlength];
            int bufferpos = 0;
            foreach (KeyValuePair<string, byte[]> entry in extendedAttributes)
            {
                int total = 64 + Encoding.ASCII.GetByteCount(entry.Key) + entry.Value.Length;
                total = total + (8 - (total % 8));
                BitConverterLE.GetBytes((uint)total).CopyTo(buffer, bufferpos);
                BitConverterLE.GetBytes((byte)Encoding.ASCII.GetByteCount(entry.Key)).CopyTo(buffer, bufferpos + 40);
                BitConverterLE.GetBytes((ushort)entry.Value.Length).CopyTo(buffer, bufferpos + 48);
                Encoding.ASCII.GetBytes(entry.Key).CopyTo(buffer, bufferpos + 64);
                entry.Value.CopyTo(buffer, bufferpos + 64 + Encoding.ASCII.GetByteCount(entry.Key));
            }

            return buffer;
        }
    }
}

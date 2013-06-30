namespace Cimba.Protocol
{
    using System.IO;
    using System.Text;

    internal class QueryDirectoryRequest : Packet
    {
        internal QueryDirectoryRequest(FILE_ID fileId, FileInformationClass fileInformationClass, uint outputBufferLength, QueryDirectory_Flags flags = (QueryDirectory_Flags)0, string searchPattern = "*")
        {
            this.Command = PacketType.Query_Directory;
            this.FileId = fileId;
            this.FileInformationClass = fileInformationClass;
            this.Flags = flags;
            this.FileIndex = 0;
            this.OutputBufferLength = outputBufferLength;
            this.FileName = searchPattern;
        }

        private QueryDirectoryRequest()
        {
        }

        internal FileInformationClass FileInformationClass { get; set; }

        internal QueryDirectory_Flags Flags { get; set; }

        internal uint FileIndex { get; set; }

        internal FILE_ID FileId { get; set; }

        internal string FileName { get; set; }

        internal uint OutputBufferLength { get; set; }

        internal static QueryDirectoryRequest Read(MemoryStream stream)
        {
            // StructureSize (2 bytes)
            if (BitConverterLE.ToUShort(stream) != 33)
            {
                throw new SmbPacketException("Invalid QueryDirectoryRequest");
            }

            QueryDirectoryRequest packet = new QueryDirectoryRequest();

            // FileInformationClass (1 byte)
            packet.FileInformationClass = (FileInformationClass)(byte)stream.ReadByte();

            // Flags (1 byte)
            packet.Flags = (QueryDirectory_Flags)(byte)stream.ReadByte();

            // FileIndex (4 bytes)
            packet.FileIndex = BitConverterLE.ToUInt(stream);

            // FileId (16 bytes)
            byte[] fileid = new byte[16];
            stream.Read(fileid, 0, 16);
            packet.FileId = new FILE_ID(fileid);

            // FileNameOffset (2 bytes)
            ushort fileNameOffset = BitConverterLE.ToUShort(stream);

            // FileNameLength (2 bytes)
            ushort fileNameLength = BitConverterLE.ToUShort(stream);

            // OutputBufferLength (4 bytes)
            packet.OutputBufferLength = BitConverterLE.ToUInt(stream);

            // Buffer (variable)
            byte[] fileNameBytes = new byte[fileNameLength];
            stream.Seek(fileNameOffset, SeekOrigin.Begin);
            stream.Read(fileNameBytes, 0, fileNameLength);
            packet.FileName = Encoding.Unicode.GetString(fileNameBytes);

            return packet;
        }

        protected override byte[] Generate()
        {
            byte[] buffer;
            if (!string.IsNullOrEmpty(this.FileName))
            {
                buffer = new byte[32 + Encoding.Unicode.GetByteCount(this.FileName)];
            }
            else
            {
                buffer = new byte[32];
            }

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)33).CopyTo(buffer, 0);

            // FileInformationClass (1 byte)
            buffer[2] = (byte)this.FileInformationClass;

            // Flags (1 byte)
            buffer[3] = (byte)this.Flags;

            // FileIndex (4 bytes)
            BitConverterLE.GetBytes(this.FileIndex).CopyTo(buffer, 4);

            // FileId (16 bytes)
            this.FileId.Flatten().CopyTo(buffer, 8);

            // FileNameOffset (2 bytes)
            // FileNameLength (2 bytes)
            if (!string.IsNullOrEmpty(this.FileName))
            {
                BitConverterLE.GetBytes((ushort)(32 + Packet.HeaderLength)).CopyTo(buffer, 24);
                BitConverterLE.GetBytes((ushort)Encoding.Unicode.GetByteCount(this.FileName)).CopyTo(buffer, 26);
            }

            // OutputBufferLength (4 bytes)
            BitConverterLE.GetBytes(this.OutputBufferLength).CopyTo(buffer, 28);

            // Buffer (variable)
            if (!string.IsNullOrEmpty(this.FileName))
            {
                Encoding.Unicode.GetBytes(this.FileName).CopyTo(buffer, 32);
            }

            return buffer;
        }
    }
}

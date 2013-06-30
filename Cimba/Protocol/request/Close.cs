namespace Cimba.Protocol
{
    using System.IO;

    internal class CloseRequest : Packet
    {
        internal CloseRequest(FILE_ID fileId, bool correctAttributes = false)
        {
            this.Command = PacketType.Close;

            this.FileId = fileId;
            this.CorrectAttributes = correctAttributes;
        }

        private CloseRequest()
        {
        }

        internal FILE_ID FileId { get; set; }

        internal bool CorrectAttributes { get; set; }

        internal static CloseRequest Read(MemoryStream stream)
        {
            // StructureSize (2 bytes)
            if (BitConverterLittleEndian.ToUShort(stream) != 24)
            {
                throw new SmbPacketException("Invalid CloseRequest");
            }

            CloseRequest packet = new CloseRequest();

            // Flags (2 bytes)
            packet.CorrectAttributes = BitConverterLittleEndian.ToUShort(stream) == 0x0001;

            // Reserved (4 bytes) - MUST NOT be used, MUST be reserved - server MUST ignore on receipt
            stream.Seek(4, SeekOrigin.Current);

            // FileId (16 bytes)
            byte[] fileid = new byte[16];
            stream.Read(fileid, 0, 16);
            packet.FileId = new FILE_ID(fileid);

            return packet;
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[24];

            // StructureSize (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)24).CopyTo(buffer, 0);

            // Flags (2 bytes)
            if (this.CorrectAttributes)
            {
                BitConverterLittleEndian.GetBytes((ushort)0x0001).CopyTo(buffer, 2);
            }
            else
            {
                BitConverterLittleEndian.GetBytes((ushort)0).CopyTo(buffer, 2);
            }

            // Reserved (4 bytes)
            // FileId (16 bytes)
            this.FileId.Flatten().CopyTo(buffer, 8);

            return buffer;
        }
    }
}

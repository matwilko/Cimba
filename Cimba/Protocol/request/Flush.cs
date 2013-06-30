namespace Cimba.Protocol
{
    using System.IO;

    internal class FlushRequest : Packet
    {
        internal FlushRequest(FILE_ID fileId)
        {
            this.Command = PacketType.Flush;

            this.FileId = fileId;
        }

        private FlushRequest()
        {
        }

        internal FILE_ID FileId { get; set; }

        internal static FlushRequest Read(MemoryStream stream)
        {
            // StructureSize (2 bytes)
            if (BitConverterLittleEndian.ToUShort(stream) != 24)
            {
                throw new SmbPacketException("Invalid FlushRequest");
            }

            FlushRequest packet = new FlushRequest();

            // Reserved1 (2 bytes)
            stream.Seek(2, SeekOrigin.Current);

            // Reserved2 (2 bytes)
            stream.Seek(2, SeekOrigin.Current);

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

            // Reserved1 (2 bytes)
            // Reserved2 (4 bytes)
            // FileId (16 bytes)
            BitConverterLittleEndian.GetBytes(this.FileId.Persistent).CopyTo(buffer, 8);
            BitConverterLittleEndian.GetBytes(this.FileId.Volatile).CopyTo(buffer, 16);

            return buffer;
        }
    }
}

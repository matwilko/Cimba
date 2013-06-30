namespace Cimba.Protocol
{
    using System.IO;

    internal class ReadResponse : Packet
    {
        internal ReadResponse()
        {
            this.Command = PacketType.Read;
            this.IsRequest = false;
        }

        internal byte[] Data { get; set; }

        internal FILE_ID FileId { get; set; }

        internal static ReadResponse Read(MemoryStream stream)
        {
            if (BitConverterLE.ToUShort(stream) != 17)
            {
                throw new SmbPacketException("Invalid ReadResponse");
            }

            ReadResponse packet = new ReadResponse();

            // DataOffset (1 byte)
            byte dataOffset = (byte)stream.ReadByte();

            // Reserved (1 byte)
            stream.Seek(1, SeekOrigin.Current);

            // DataLength (4 bytes)
            uint dataLength = BitConverterLE.ToUInt(stream);

            // DataRemaining (4 bytes) - MUST NOT be used and MUST be reserved
            // Reserved2 (4 bytes)
            // Buffer (variable)
            packet.Data = new byte[dataLength];
            stream.Seek(dataOffset, SeekOrigin.Begin);
            stream.Read(packet.Data, 0, (int)dataLength);

            return packet;
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[16 + this.Data.Length];

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)17).CopyTo(buffer, 0);

            // DataOffset (1 byte)
            buffer[2] = Packet.HeaderLength + 16;

            // Reserved (1 byte)
            buffer[3] = 0;

            // DataLength (4 bytes)
            BitConverterLE.GetBytes((uint)this.Data.Length).CopyTo(buffer, 4);

            // DataRemaining (4 bytes) - MUST NOT be used and MUST be reserved - server MUST set to 0
            // Reserved2 (4 bytes)
            // Buffer (variable)
            this.Data.CopyTo(buffer, 16);

            return buffer;
        }
    }
}

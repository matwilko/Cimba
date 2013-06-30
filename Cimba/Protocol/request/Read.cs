namespace Cimba.Protocol
{
    using System.IO;

    internal class ReadRequest : Packet
    {
        internal ReadRequest(FILE_ID fileId, uint length, ulong offset, uint minimumCount, byte padding = 0x50)
        {
            this.Command = PacketType.Read;

            this.FileId = fileId;
            this.Length = length;
            this.Offset = offset;
            this.MinimumCount = minimumCount;
            this.Padding = 0x50;

            this.RemainingBytes = 0;
        }

        private ReadRequest()
        {
        }

        internal FILE_ID FileId { get; set; }

        internal uint Length { get; set; }

        internal ulong Offset { get; set; }

        internal uint MinimumCount { get; set; }

        internal uint RemainingBytes { get; set; }

        internal byte Padding { get; set; }

        internal static ReadRequest Read(MemoryStream stream)
        {
            // StructureSize (2 bytes)
            if (BitConverterLE.ToUShort(stream) != 49)
            {
                throw new SmbPacketException("Invalid ReadRequest");
            }

            ReadRequest packet = new ReadRequest();

            // Padding (1 byte)
            packet.Padding = (byte)stream.ReadByte();

            // Reserved (1 byte)
            stream.Seek(1, SeekOrigin.Current);

            // Length (4 bytes)
            packet.Length = BitConverterLE.ToUInt(stream);

            // Offset (8 bytes)
            packet.Offset = BitConverterLE.ToULong(stream);

            // FileId (16 bytes)
            byte[] fileid = new byte[16];
            stream.Read(fileid, 0, 16);
            packet.FileId = new FILE_ID(fileid);

            // MinimumCount (4 bytes)
            packet.MinimumCount = BitConverterLE.ToUInt(stream);

            // Channel (4 bytes) - MUST NOT be used and MUST be reserved
            stream.Seek(4, SeekOrigin.Current);

            // RemainingBytes (4 bytes)
            packet.RemainingBytes = BitConverterLE.ToUInt(stream);

            // ReadChannelInfoOffset (2 bytes) - MUST NOT be used and MUST be reserved
            // ReadChannelInfoLength (2 bytes) - MUST NOT be used and MUST be reserved
            // Buffer (variable) - server MUST ignore on receipt
            return packet;
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[49];

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)49).CopyTo(buffer, 0);

            // Padding (1 byte)
            buffer[2] = this.Padding;

            // Reserved (1 byte)

            // Length (4 bytes)
            BitConverterLE.GetBytes(this.Length).CopyTo(buffer, 4);

            // Offset (8 bytes)
            BitConverterLE.GetBytes((ulong)this.Offset).CopyTo(buffer, 8);

            // FileId (16 bytes)
            this.FileId.Flatten().CopyTo(buffer, 16);

            // MinimumCount (4 bytes)
            BitConverterLE.GetBytes(this.MinimumCount).CopyTo(buffer, 32);

            // Channel (4 bytes) - MUST NOT be used and MUST be reserved
            // RemainingBytes (4 bytes)
            BitConverterLE.GetBytes(this.RemainingBytes).CopyTo(buffer, 40);

            // ReadChannelInfoOffset (2 bytes) - MUST NOT be used and MUST be reserved
            // ReadChannelInfoLength (2 bytes) - MUST NOT be used and MUST be reserved
            // Buffer (variable) - contains ReadChannelInfo, but unused at present. Must contain a single null byte.
            return buffer;
        }
    }
}

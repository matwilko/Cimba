namespace Cimba.Protocol
{
    using System;
    using System.IO;

    internal class WriteRequest : Packet
    {
        internal WriteRequest(FILE_ID fileId, byte[] data, ulong offset = 0)
        {
            this.Command = PacketType.Write;

            this.FileId = fileId;
            this.Data = data;

            this.Offset = offset;
            this.RemainingBytes = 0;
            this.WriteThrough = false;
        }

        private WriteRequest()
        {
        }

        internal FILE_ID FileId { get; set; }

        internal byte[] Data { get; set; }

        internal ulong Offset { get; set; }

        internal uint RemainingBytes { get; set; }

        internal bool WriteThrough { get; set; }

        internal static WriteRequest Read(MemoryStream stream)
        {
            // StructureSize (2 bytes)
            if (BitConverterLittleEndian.ToUShort(stream) != 49)
            {
                throw new SmbPacketException("Invalid WriteRequest");
            }

            WriteRequest packet = new WriteRequest();

            // DataOffset (2 bytes)
            int dataOffset = BitConverterLittleEndian.ToUShort(stream);

            // Length (4 bytes)
            uint dataLength = BitConverterLittleEndian.ToUInt(stream);

            // Offset (8 bytes)
            packet.Offset = BitConverterLittleEndian.ToULong(stream);

            // FileId (16 bytes)
            packet.FileId = new FILE_ID(BitConverterLittleEndian.ToULong(stream), BitConverterLittleEndian.ToULong(stream));

            // Channel (4 bytes) - MUST NOT be used and MUST be reserved, server MUST ignore
            stream.Seek(4, SeekOrigin.Current);

            // RemainingBytes (4 bytes)
            packet.RemainingBytes = BitConverterLittleEndian.ToUInt(stream);

            // WriteChannelInfoOffset (2 bytes) - MUST NOT be used and MUST be reserved - server MUST ignore
            stream.Seek(4, SeekOrigin.Current);

            // WriteChannelInfoLength (2 bytes) - MUST NOT be used and MUST be reserved - server MUST ignore
            stream.Seek(4, SeekOrigin.Current);

            // Flags (4 bytes)
            packet.WriteThrough = (BitConverterLittleEndian.ToUInt(stream) & 0x00000001) == 0x00000001;

            // Buffer (variable)
            stream.Seek(dataOffset, SeekOrigin.Begin);
            packet.Data = new byte[dataLength];
            if (dataLength > int.MaxValue)
            {
                double halfpoint = (double)(dataLength / 2);
                stream.Read(packet.Data, 0, (int)Math.Floor(halfpoint));
                stream.Read(packet.Data, (int)Math.Floor(halfpoint), (int)Math.Ceiling(halfpoint));
            }
            else
            {
                stream.Read(packet.Data, 0, (int)dataLength);
            }

            return packet;
        }

        protected override byte[] Generate()
        {
            byte[] packet = new byte[48];

            // StructureSize (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)49).CopyTo(packet, 0);

            // DataOffset (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)(48 + Packet.HeaderLength)).CopyTo(packet, 2);

            // Length (4 bytes)
            BitConverterLittleEndian.GetBytes((uint)this.Data.Length).CopyTo(packet, 4);

            // Offset (8 bytes)
            BitConverterLittleEndian.GetBytes(this.Offset).CopyTo(packet, 8);

            // FileId (16 bytes)
            this.FileId.Flatten().CopyTo(packet, 16);

            // Channel (4 bytes) - MUST NOT be used and MUST be reserved
            // RemainingBytes (4 bytes)
            BitConverterLittleEndian.GetBytes(this.RemainingBytes).CopyTo(packet, 36);

            // WriteChannelInfoOffset (2 bytes) - MUST NOT be used and MUST be reserved
            // WriteChannelInfoLength (2 bytes) - MUST NOT be used and MUST be reserved
            // Flags (4 bytes)
            if (this.WriteThrough)
            {
                BitConverterLittleEndian.GetBytes((uint)0x00000001).CopyTo(packet, 44);
            }
            else
            {
                BitConverterLittleEndian.GetBytes((uint)0).CopyTo(packet, 44);
            }

            // Buffer (variable)
            byte[] packet_and_buffer = new byte[packet.Length + this.Data.Length];
            packet.CopyTo(packet_and_buffer, 0);
            this.Data.CopyTo(packet_and_buffer, packet.Length);

            return packet_and_buffer;
        }
    }
}

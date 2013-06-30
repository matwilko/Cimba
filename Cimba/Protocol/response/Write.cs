namespace Cimba.Protocol
{
    using System;
    using System.IO;

    internal class WriteResponse : Packet
    {
        internal WriteResponse()
        {
            this.Command = PacketType.Write;
            this.IsRequest = false;
        }

        internal uint Count { get; set; }

        internal static WriteResponse Read(MemoryStream stream)
        {
            if (BitConverterLittleEndian.ToUShort(stream) != 17)
            {
                throw new SmbPacketException("Invalid WriteResponse");
            }

            WriteResponse packet = new WriteResponse();

            // Reserved (2 bytes)
            stream.Seek(2, SeekOrigin.Current);

            // Count (4 bytes)
            packet.Count = BitConverterLittleEndian.ToUInt(stream);

            // Remaining (4 bytes)
            // WriteChannelInfoOffset (2 bytes)
            // WriteChannelInfoLength (2 bytes)
            return packet;
        }

        protected override byte[] Generate()
        {
            throw new NotImplementedException();
        }
    }
}

namespace Cimba.Protocol
{
    using System;
    using System.IO;

    internal class QueryInfoResponse : Packet
    {
        internal QueryInfoResponse()
        {
            this.Command = PacketType.Query_Info;
            this.IsRequest = false;
        }

        internal byte[] OutputBuffer { get; set; }

        internal static QueryInfoResponse Read(MemoryStream stream)
        {
            if (BitConverterLE.ToUShort(stream) != 9)
            {
                throw new SmbPacketException("Invalid QueryInfoResponse");
            }

            QueryInfoResponse packet = new QueryInfoResponse();

            // OutputBufferOffset (2 bytes)
            ushort outputBufferOffset = BitConverterLE.ToUShort(stream);

            // OutputBufferLength (4 bytes)
            uint outputBufferLength = BitConverterLE.ToUInt(stream);

            packet.OutputBuffer = new byte[outputBufferLength];
            stream.Seek(outputBufferOffset - Packet.HeaderLength, SeekOrigin.Begin);
            stream.Read(packet.OutputBuffer, 0, (int)outputBufferLength);

            return packet;
        }

        protected override byte[] Generate()
        {
            throw new NotImplementedException();
        }
    }
}

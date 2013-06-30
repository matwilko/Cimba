namespace Cimba.Protocol
{
    using System.IO;

    internal class QueryDirectoryResponse : Packet
    {
        internal QueryDirectoryResponse()
        {
            this.Command = PacketType.Query_Directory;
            this.IsRequest = false;
        }

        internal byte[] Buffer { get; set; }

        internal static QueryDirectoryResponse Read(MemoryStream stream)
        {
            QueryDirectoryResponse packet = new QueryDirectoryResponse();

            if (BitConverterLE.ToUShort(stream) != 9)
            {
                throw new SmbPacketException("Invalid QueryDirectoryResponse");
            }

            // OutputBufferOffset (2 bytes)
            int outputBufferOffset = BitConverterLE.ToUShort(stream);

            // OutputBufferLength (4 bytes)
            uint outputBufferLength = BitConverterLE.ToUInt(stream);

            // Buffer (variable)
            packet.Buffer = new byte[outputBufferLength];
            stream.Seek(outputBufferOffset, SeekOrigin.Begin);
            stream.Read(packet.Buffer, 0, (int)outputBufferLength);

            return packet;
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[8 + this.Buffer.Length];

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)9).CopyTo(buffer, 0);

            // OutputBufferOffset (2 bytes)
            BitConverterLE.GetBytes((ushort)Packet.HeaderLength + 8).CopyTo(buffer, 2);

            // OutputBufferLength (4 bytes)
            BitConverterLE.GetBytes((uint)this.Buffer.Length).CopyTo(buffer, 4);

            // Buffer (variable)
            this.Buffer.CopyTo(buffer, 8);

            return buffer;
        }
    }
}

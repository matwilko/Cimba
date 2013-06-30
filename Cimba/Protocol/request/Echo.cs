namespace Cimba.Protocol
{
    using System.IO;

    internal class EchoRequest : Packet
    {
        internal EchoRequest()
        {
            this.Command = PacketType.Echo;
        }

        internal static EchoRequest Read(MemoryStream stream)
        {
            if (BitConverterLittleEndian.ToUShort(stream) != 4)
            {
                throw new SmbPacketException("Invalid EchoRequest");
            }

            return new EchoRequest();
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[4];

            // StructureSize (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)4).CopyTo(buffer, 0);

            // Reserved (2 bytes) - MUST NOT be used and MUST be reserved
            return buffer;
        }
    }
}

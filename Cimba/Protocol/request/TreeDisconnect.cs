namespace Cimba.Protocol
{
    using System.IO;

    internal class TreeDisconnectRequest : Packet
    {
        internal TreeDisconnectRequest()
        {
            this.Command = PacketType.Tree_Disconnect;
        }

        internal static TreeDisconnectRequest Read(MemoryStream stream)
        {
            if (BitConverterLE.ToUShort(stream) != 4)
            {
                throw new SmbPacketException("Invalid TreeDisconnectRequest");
            }

            return new TreeDisconnectRequest();
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[4];

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)4).CopyTo(buffer, 0);

            // Reserved (2 bytes) - MUST NOT be used and MUST be reserved
            return buffer;
        }
    }
}

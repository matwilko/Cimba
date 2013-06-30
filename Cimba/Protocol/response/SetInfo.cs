namespace Cimba.Protocol
{
    using System.IO;

    internal class SetInfoResponse : Packet
    {
        internal SetInfoResponse()
        {
            this.Command = PacketType.Set_Info;
            this.IsRequest = false;
        }

        internal static SetInfoResponse Read(MemoryStream stream)
        {
            if (BitConverterLittleEndian.ToUShort(stream) != 2)
            {
                throw new SmbPacketException("Invalid SetInfoResponse");
            }
            else
            {
                return new SetInfoResponse();
            }
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[2];
            BitConverterLittleEndian.GetBytes((ushort)2).CopyTo(buffer, 0);
            return buffer;
        }
    }
}

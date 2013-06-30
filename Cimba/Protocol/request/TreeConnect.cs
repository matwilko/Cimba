namespace Cimba.Protocol
{
    using System.IO;
    using System.Text;

    internal class TreeConnectRequest : Packet
    {
        internal TreeConnectRequest(string shareName)
        {
            this.ShareName = shareName;
            this.Command = PacketType.Tree_Connect;
            this.IsRequest = true;
        }

        internal TreeConnectRequest()
        {
        }

        internal string ShareName { get; set; }

        internal static TreeConnectRequest Read(MemoryStream stream)
        {
            // StructureSize (2 bytes)
            if (BitConverterLE.ToUShort(stream) != 9)
            {
                throw new SmbPacketException("Invalid TreeConnectRequest");
            }

            TreeConnectRequest packet = new TreeConnectRequest();

            // Reserved (2 bytes) - MUST NOT be used and MUST be reserved - server MUST ignore on receipt
            stream.Seek(2, SeekOrigin.Current);

            // PathOffset (2 bytes)
            int pathOffset = BitConverterLE.ToUShort(stream);

            // PathLength (2 bytes)
            int pathLength = BitConverterLE.ToUShort(stream);

            // Buffer (variable)
            byte[] path = new byte[pathLength];
            stream.Seek(pathOffset, SeekOrigin.Begin);
            stream.Read(path, 0, pathLength);
            packet.ShareName = Encoding.Unicode.GetString(path);

            return packet;
        }

        protected override byte[] Generate()
        {
            byte[] data = new byte[8 + Encoding.Unicode.GetByteCount(this.ShareName)];

            // StructureSize (2 bytes) - MUST be 8 (spec says 9...)
            BitConverterLE.GetBytes((ushort)9).CopyTo(data, 0);

            // Reserved (2 bytes) - MUST NOT be used

            // PathOffset - Offset, in bytes, of the full share path name from the beginning of the packet header
            BitConverterLE.GetBytes((ushort)(Packet.HeaderLength + 8)).CopyTo(data, 4);

            // PathLength - Length, in bytes, of the path name
            BitConverterLE.GetBytes((ushort)Encoding.Unicode.GetByteCount(this.ShareName)).CopyTo(data, 6);

            Encoding.Unicode.GetBytes(this.ShareName).CopyTo(data, 8);

            return data;
        }
    }
}

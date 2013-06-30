namespace Cimba.Protocol
{
    using System.IO;

    internal class TreeConnectResponse : Packet
    {
        internal TreeConnectResponse()
        {
            this.Command = PacketType.Tree_Connect;
            this.IsRequest = false;
        }

        internal enum ShareType : byte
        {
            DISK = 0x01,
            PIPE = 0x02,
            PRINT = 0x03
        }

        internal enum ShareFlags : uint
        {
            MANUAL_CACHING = 0x00000000,
            AUTO_CACHING = 0x00000010,
            VDO_CACHING = 0x00000020,
            NO_CACHING = 0x00000030,
            DFS = 0x00000001,
            DFS_ROOT = 0x00000002,
            RESTRICT_EXLUSIVE_OPENS = 0x00000100,
            FORCE_SHARED_DELETE = 0x00000200,
            ALLOW_NAMESPACE_CACHING = 0x00000400,
            ACCESS_BASED_DIRECTORY_ENUM = 0x00000800,
            FORCE_LEVELII_OPLOCK = 0x00001000,
            ENABLE_HASH = 0x00002000
        }

        internal enum ShareCapabilities : uint
        {
            CAP_DFS = 0x00000008,
        }

        internal ShareType Type { get; set; }

        internal ShareFlags Flags { get; set; }

        internal ShareCapabilities Capabilities { get; set; }

        internal AccessMask.File_Pipe_Printer MaximalAccess { get; set; }

        internal static TreeConnectResponse Read(MemoryStream stream)
        {
            byte[] data = new byte[16];
            stream.Read(data, 0, 16);

            TreeConnectResponse packet = new TreeConnectResponse();

            // StructureSize (2 bytes)
            if (BitConverterLE.ToUShort(data, 0) != 16)
            {
                throw new SmbPacketException("Malformed Tree_Connect Response");
            }

            // ShareType (1 byte)
            packet.Type = (ShareType)data[2];

            // Reserved (1 byte)

            // ShareFlags (4 bytes)
            packet.Flags = (ShareFlags)BitConverterLE.ToUInt(data, 4);

            // Capabilities (4 bytes)
            packet.Capabilities = (ShareCapabilities)BitConverterLE.ToUInt(data, 8);

            // MaximalAccess (4 bytes)
            packet.MaximalAccess = (AccessMask.File_Pipe_Printer)BitConverterLE.ToUInt(data, 12);

            return packet;
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[16];

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)16).CopyTo(buffer, 0);

            // ShareType (1 byte)
            buffer[2] = (byte)this.Type;

            // Reserved (1 byte) - MUST NOT be used and MUST be reserved - server MUST set to 0
            buffer[3] = 0;

            // ShareFlags (4 bytes)
            BitConverterLE.GetBytes((uint)this.Flags).CopyTo(buffer, 4);

            // Capabilities (4 bytes)
            BitConverterLE.GetBytes((uint)this.Capabilities).CopyTo(buffer, 8);

            // MaximalAccess (4 bytes)
            BitConverterLE.GetBytes((uint)this.MaximalAccess).CopyTo(buffer, 12);

            return buffer;
        }
    }
}

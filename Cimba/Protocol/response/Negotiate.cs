namespace Cimba.Protocol
{
    using System;
    using System.IO;
    using Cimba.Server;

    internal class NegotiateResponse : Packet
    {
        internal NegotiateResponse()
        {
            this.Command = PacketType.Negotiate;
            this.IsRequest = false;
        }

        internal enum Caps : uint
        {
            GLOBAL_CAP_DFS = 0x00000001,
            GLOBAL_CAP_LEASING = 0x00000002,
            GLOBAL_CAP_LARGE_MTU
        }

        internal Negotiate_SecurityMode SecurityMode { get; set; }

        internal ushort DialectRevision { get; set; }

        internal Guid ServerGuid { get; set; }

        internal Caps Capabilities { get; set; }

        internal uint MaxTransactSize { get; set; }

        internal uint MaxReadSize { get; set; }

        internal uint MaxWriteSize { get; set; }

        internal DateTime SystemTime { get; set; }

        internal DateTime ServerStartTime { get; set; }

        internal byte[] SecurityBuffer { get; set; }

        internal static NegotiateResponse Read(SmbVersion version, MemoryStream stream)
        {
            NegotiateResponse newpacket = new NegotiateResponse();

            byte[] packet = new byte[65]; // Packet with Buffer[]
            stream.Read(packet, 0, 65);

            ushort structureSize = BitConverterLittleEndian.ToUShort(packet, 0);
            if (structureSize != 65)
            {
                throw new SmbPacketException("Negotiate.StructureSize incorrect, received: " + structureSize);
            }

            newpacket.SecurityMode = (Negotiate_SecurityMode)BitConverterLittleEndian.ToUShort(packet, 2);
            if (!newpacket.SecurityMode.HasFlag(Negotiate_SecurityMode.SigningEnabled))
            {
                // TODO: Client MUST return STATUS_INVALID_NETWORK_RESPONSE if flag is missing
            }

            newpacket.DialectRevision = BitConverterLittleEndian.ToUShort(packet, 4);

            // Reserved (2 bytes) - MUST ignore
            // ServerGuid (16 bytes)
            byte[] guidbytes = new byte[16];
            Array.Copy(packet, 8, guidbytes, 0, 16);
            newpacket.ServerGuid = new Guid(guidbytes);

            newpacket.Capabilities = (Caps)BitConverterLittleEndian.ToUInt(packet, 24);

            newpacket.MaxTransactSize = BitConverterLittleEndian.ToUInt(packet, 28);
            newpacket.MaxReadSize = BitConverterLittleEndian.ToUInt(packet, 32);
            newpacket.MaxWriteSize = BitConverterLittleEndian.ToUInt(packet, 36);
            newpacket.SystemTime = DateTime.FromFileTime(BitConverterLittleEndian.ToLong(packet, 40));
            newpacket.ServerStartTime = DateTime.FromFileTime(BitConverterLittleEndian.ToLong(packet, 48));
            ushort securityBufferOffset = BitConverterLittleEndian.ToUShort(packet, 56);
            ushort securityBufferLength = BitConverterLittleEndian.ToUShort(packet, 58);

            // Reserved2 - MUST ignore
            // Read in buffer
            newpacket.SecurityBuffer = new byte[securityBufferLength];
            stream.Seek(securityBufferOffset, SeekOrigin.Begin);
            stream.Read(newpacket.SecurityBuffer, 0, securityBufferLength);

            return newpacket;
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[64 + this.SecurityBuffer.Length];

            // StructureSize (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)65).CopyTo(buffer, 0);

            // SecurityMode (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)this.SecurityMode).CopyTo(buffer, 2);

            // DialectRevision (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)this.DialectRevision).CopyTo(buffer, 4);

            // Reserved (2 bytes)
            // ServerGuid (16 bytes)
            this.ServerGuid.ToByteArray().CopyTo(buffer, 8);

            // Capabilities (4 bytes)
            BitConverterLittleEndian.GetBytes((uint)this.Capabilities).CopyTo(buffer, 24);

            // MaxTransactSize (4 bytes)
            BitConverterLittleEndian.GetBytes((uint)this.MaxTransactSize).CopyTo(buffer, 28);

            // MaxReadSize (4 bytes)
            BitConverterLittleEndian.GetBytes((uint)this.MaxReadSize).CopyTo(buffer, 32);

            // MaxWriteSize (4 bytes)
            BitConverterLittleEndian.GetBytes((uint)this.MaxWriteSize).CopyTo(buffer, 36);

            // SystemTime (8 bytes)
            BitConverterLittleEndian.GetBytes((ulong)DateTime.Now.ToFileTime()).CopyTo(buffer, 40);

            // ServerStartTime (8 bytes)
            BitConverterLittleEndian.GetBytes((ulong)SmbServer.StartTime.ToFileTime()).CopyTo(buffer, 48);

            // SecurityBufferOffset (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)(64 + Packet.HeaderLength)).CopyTo(buffer, 56);

            // SecurityBufferLength (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)this.SecurityBuffer.Length).CopyTo(buffer, 58);

            // Reserved2 (4 bytes)
            // Buffer (variable)
            this.SecurityBuffer.CopyTo(buffer, 64);

            return buffer;
        }
    }
}

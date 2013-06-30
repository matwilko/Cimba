namespace Cimba.Protocol
{
    using System;
    using System.IO;

    internal class IOCTLResponse : Packet
    {
        internal IOCTLResponse()
        {
            this.Command = PacketType.IOCTL;
            this.IsRequest = false;
            this.OUT = new byte[0];
            this.FileId = new FILE_ID();
        }

        internal uint CtlCode { get; set; }

        internal FILE_ID FileId { get; set; }

        internal byte[] OUT { get; set; }

        internal static IOCTLResponse Read(MemoryStream stream)
        {
            throw new NotImplementedException();
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[48 + this.OUT.Length];

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)49).CopyTo(buffer, 0);

            // Reserved (2 bytes)
            // CtlCode (4 bytes)
            BitConverterLE.GetBytes(this.CtlCode).CopyTo(buffer, 4);

            // FileId (16 bytes)
            this.FileId.Flatten().CopyTo(buffer, 8);

            // InputOffset (4 bytes)
            // InputCount (4 bytes)
            // OutputOffset (4 bytes)
            BitConverterLE.GetBytes((uint)48).CopyTo(buffer, 32);

            // OutputCount (4 bytes)
            BitConverter.GetBytes((uint)this.OUT.Length).CopyTo(buffer, 36);

            // Flags (4 bytes)
            // Reserved2 (4 bytes)
            // Buffer (variable)
            this.OUT.CopyTo(buffer, 48);

            return buffer;
        }
    }
}

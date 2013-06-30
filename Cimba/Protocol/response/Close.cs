namespace Cimba.Protocol
{
    using System.IO;
    using Cimba.Protocol.External.Microsoft;

    internal class CloseResponse : Packet
    {
        internal CloseResponse()
        {
            this.Command = PacketType.Close;
            this.IsRequest = false;
        }

        internal bool AttributesValid { get; set; }

        internal ulong CreationTime { get; set; }

        internal ulong LastAccessTime { get; set; }

        internal ulong LastWriteTime { get; set; }

        internal ulong ChangeTime { get; set; }

        internal ulong AllocationSize { get; set; }

        internal ulong EndOfFile { get; set; }

        internal FSCC.FILE_ATTRIBUTE FileAttributes { get; set; }

        internal static CloseResponse Read(MemoryStream stream)
        {
            if (BitConverterLE.ToUShort(stream) != 60)
            {
                throw new SmbPacketException("Invalid CloseResponse");
            }

            CloseResponse packet = new CloseResponse();

            if (BitConverterLE.ToUShort(stream) == 0x0001)
            {
                // Attributes Valid
                packet.AttributesValid = true;
                stream.Seek(4, SeekOrigin.Current);
                packet.CreationTime = BitConverterLE.ToULong(stream);
                packet.LastAccessTime = BitConverterLE.ToULong(stream);
                packet.LastWriteTime = BitConverterLE.ToULong(stream);
                packet.ChangeTime = BitConverterLE.ToULong(stream);
                packet.AllocationSize = BitConverterLE.ToULong(stream);
                packet.EndOfFile = BitConverterLE.ToULong(stream);
                packet.FileAttributes = (FSCC.FILE_ATTRIBUTE)BitConverterLE.ToUInt(stream);
            }
            else
            {
                packet.AttributesValid = false;
            }

            return packet;
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[60];

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)60).CopyTo(buffer, 0);

            // Flags (2 bytes)
            BitConverterLE.GetBytes((ushort)(this.AttributesValid ? 0x0001 : 0x0000)).CopyTo(buffer, 2);

            // Reserved (4 bytes)
            BitConverterLE.GetBytes((uint)0).CopyTo(buffer, 4);

            // CreationTime (8 bytes)
            BitConverterLE.GetBytes(this.CreationTime).CopyTo(buffer, 8);

            // LastAccessTime (8 bytes)
            BitConverterLE.GetBytes(this.LastAccessTime).CopyTo(buffer, 16);

            // LastWriteTime (8 bytes)
            BitConverterLE.GetBytes(this.LastWriteTime).CopyTo(buffer, 24);

            // ChangeTime (8 bytes)
            BitConverterLE.GetBytes(this.ChangeTime).CopyTo(buffer, 32);

            // AllocationSize (8 bytes)
            BitConverterLE.GetBytes(this.AllocationSize).CopyTo(buffer, 40);

            // EndOfFile (8 bytes)
            BitConverterLE.GetBytes(this.EndOfFile).CopyTo(buffer, 48);

            // FileAttributes (4 bytes)
            BitConverterLE.GetBytes((uint)this.FileAttributes).CopyTo(buffer, 56);

            return buffer;
        }
    }
}

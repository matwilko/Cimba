namespace Cimba.Protocol
{
    using System.Collections.Generic;
    using System.IO;
    using Cimba.Protocol.External.Microsoft;

    internal class CreateResponse : Packet
    {
        internal CreateResponse()
        {
            this.Command = PacketType.Create;
            this.IsRequest = false;
        }

        internal enum Create_Action : uint
        {
            SUPERSEDED = 0x00000000,
            OPENED = 0x00000001,
            CREATED = 0x00000002,
            OVERWRITTEN = 0x00000003
        }

        internal Create_Oplock_Level OplockLevel { get; set; }

        internal Create_Action CreateAction { get; set; }

        internal ulong CreationTime { get; set; }

        internal ulong LastAccessTime { get; set; }

        internal ulong LastWriteTime { get; set; }

        internal ulong ChangeTime { get; set; }

        internal ulong AllocationSize { get; set; }

        internal ulong EndOfFile { get; set; }

        internal FSCC.FILE_ATTRIBUTE FileAttributes { get; set; }

        internal FILE_ID FileId { get; set; }

        internal List<Create_Create_Context> CreateContexts { get; set; }

        internal static CreateResponse Read(MemoryStream stream)
        {
            // StructureSize (2 bytes)
            if (BitConverterLE.ToUShort(stream) != 89)
            {
                throw new SmbPacketException("Bad CreateResponse packet");
            }

            CreateResponse packet = new CreateResponse();

            // OplockLevel (1 byte)
            packet.OplockLevel = (Create_Oplock_Level)stream.ReadByte();

            // Reserved (1 byte)
            stream.Seek(1, SeekOrigin.Current);

            // CreateAction (4 bytes)
            packet.CreateAction = (Create_Action)BitConverterLE.ToUInt(stream);

            // CreationTime (8 bytes)
            packet.CreationTime = BitConverterLE.ToULong(stream);

            // LastAccessTime (8 bytes)
            packet.LastAccessTime = BitConverterLE.ToULong(stream);

            // LastWriteTime (8 bytes)
            packet.LastWriteTime = BitConverterLE.ToULong(stream);

            // ChangeTime (8 bytes)
            packet.ChangeTime = BitConverterLE.ToULong(stream);

            // AllocationSize (8 bytes)
            packet.AllocationSize = BitConverterLE.ToULong(stream);

            // EndofFile (8 bytes)
            packet.EndOfFile = BitConverterLE.ToULong(stream);

            // FileAttributes (4 bytes)
            packet.FileAttributes = (FSCC.FILE_ATTRIBUTE)BitConverterLE.ToUInt(stream);

            // Reserved2 (4 bytes)
            stream.Seek(4, SeekOrigin.Current);

            // FileId (16 bytes)
            packet.FileId = new FILE_ID(BitConverterLE.ToULong(stream), BitConverterLE.ToULong(stream));

            // CreateContextsOffset (4 bytes)
            uint createContextsOffset = BitConverterLE.ToUInt(stream);

            // CreateContextsLength (4 bytes)
            uint createContextsLength = BitConverterLE.ToUInt(stream);

            stream.Seek(createContextsOffset, SeekOrigin.Begin);
            byte[] createcontexts = new byte[createContextsLength];
            stream.Read(createcontexts, 0, (int)createContextsLength);
            packet.CreateContexts = Create_Create_Context.UnflattenBuffer(createcontexts);

            return packet;
        }

        protected override byte[] Generate()
        {
            byte[] createContexts = Create_Create_Context.Flatten(this.CreateContexts);
            byte[] buffer = new byte[88 + createContexts.Length];

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)89).CopyTo(buffer, 0);

            // OplockLevel (1 byte)
            buffer[2] = (byte)this.OplockLevel;

            // Reserved (1 byte) - MUST NOT be used and MUST be reserved
            buffer[3] = 0;

            // CreateAction (4 bytes)
            BitConverterLE.GetBytes((uint)this.CreateAction).CopyTo(buffer, 4);

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

            // Reserved2 (4 bytes) - MUST NOT be used and MUSt be reserved
            BitConverterLE.GetBytes((uint)0).CopyTo(buffer, 60);

            // FileId (16 bytes)
            this.FileId.Flatten().CopyTo(buffer, 64);

            // CreateContextsOffset (4 bytes)
            BitConverterLE.GetBytes((uint)88).CopyTo(buffer, 80);

            // CreateContextsLength (4 bytes)
            BitConverterLE.GetBytes((uint)createContexts.Length).CopyTo(buffer, 84);

            createContexts.CopyTo(buffer, 88);

            return buffer;
        }
    }
}

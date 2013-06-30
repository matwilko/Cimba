namespace Cimba.Protocol
{
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using Cimba.Protocol.External.Microsoft;

    internal class CreateRequest : Packet
    {
        internal CreateRequest(string filename)
        {
            this.Command = PacketType.Create;
            this.IsRequest = true;

            this.RequestedOplockLevel = Create_Oplock_Level.NONE;
            this.ImpersonationLevel = Create_Impersonation_Level.Impersonation;
            this.FileAttributes = (FSCC.FILE_ATTRIBUTE)0;
            this.CreateContexts = new List<Create_Create_Context>();

            this.Filename = filename;
        }

        internal CreateRequest()
        {
        }

        internal Create_Oplock_Level RequestedOplockLevel { get; set; }

        internal Create_Impersonation_Level ImpersonationLevel { get; set; }

        internal AccessMask.File_Pipe_Printer DesiredAccess { get; set; }

        internal FSCC.FILE_ATTRIBUTE FileAttributes { get; set; }

        internal Create_Share_Access ShareAccess { get; set; }

        internal Create_Create_Disposition CreateDisposition { get; set; }

        internal Create_Create_Options CreateOptions { get; set; }

        internal List<Create_Create_Context> CreateContexts { get; set; }

        internal string Filename { get; set; }

        internal static CreateRequest Read(MemoryStream stream)
        {
            // StructureSize (2 bytes)
            if (BitConverterLE.ToUShort(stream) != 57)
            {
                throw new SmbPacketException("Invalid CreateRequest");
            }

            CreateRequest packet = new CreateRequest();

            // SecurityFlags (1 byte) - MUST NOT be used and MUST be reserved - server MUST ignore
            stream.Seek(1, SeekOrigin.Current);

            // RequestedOplockLevel (1 byte)
            packet.RequestedOplockLevel = (Create_Oplock_Level)stream.ReadByte();

            // ImpersonationLevel (4 bytes)
            packet.ImpersonationLevel = (Create_Impersonation_Level)BitConverterLE.ToUInt(stream);

            // SmbCreateFlags (8 bytes) - MUST NOT be used and MUST be reserved - server MUST ignore on receipt
            stream.Seek(8, SeekOrigin.Current);

            // Reserved (8 bytes) - MUST NOT be used and MUST be reserved - server MUST ignore on receipt
            stream.Seek(8, SeekOrigin.Current);

            // DesiredAccess (4 bytes)
            packet.DesiredAccess = (AccessMask.File_Pipe_Printer)BitConverterLE.ToUInt(stream);

            // FileAttributes (4 bytes)
            packet.FileAttributes = (FSCC.FILE_ATTRIBUTE)BitConverterLE.ToUInt(stream);

            // ShareAccess (4 bytes)
            packet.ShareAccess = (Create_Share_Access)BitConverterLE.ToUInt(stream);

            // CreateDisposition (4 bytes)
            packet.CreateDisposition = (Create_Create_Disposition)BitConverterLE.ToUInt(stream);

            // CreateOptions (4 bytes)
            packet.CreateOptions = (Create_Create_Options)BitConverterLE.ToUInt(stream);

            // NameOffset (2 bytes)
            int nameOffset = BitConverterLE.ToUShort(stream);

            // NameLength (2 bytes)
            int nameLength = BitConverterLE.ToUShort(stream);

            // CreateContextsOffset (4 bytes)
            int createContextsOffset = (int)BitConverterLE.ToUInt(stream);

            // CreateContextsLength
            int createContextsLength = (int)BitConverterLE.ToUInt(stream);

            // Buffer (variable)
            byte[] name = new byte[nameLength];
            stream.Seek(nameOffset, SeekOrigin.Begin);
            stream.Read(name, 0, nameLength);
            packet.Filename = Encoding.Unicode.GetString(name);

            /*byte[] createContexts = new byte[createContextsLength];
            stream.Seek(createContextsOffset, SeekOrigin.Begin);
            stream.Read(createContexts, 0, createContextsLength);
            packet.CreateContexts = Create_Create_Context.UnflattenBuffer(createContexts);*/

            return packet;
        }

        protected override byte[] Generate()
        {
            byte[] data = new byte[57 + Encoding.Unicode.GetByteCount(this.Filename)];

            int offset = Packet.HeaderLength + 57;
            offset += 8 - (offset % 8);

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)57).CopyTo(data, 0);

            // SecurityFlags (1 byte) - MUST NOT be used and MUST be reserved
            BitConverterLE.GetBytes((byte)0).CopyTo(data, 2);

            // RequestedOplockLevel (1 byte)
            BitConverterLE.GetBytes((byte)this.RequestedOplockLevel).CopyTo(data, 3);

            // ImpersonationLevel (4 bytes)
            BitConverterLE.GetBytes((uint)this.ImpersonationLevel).CopyTo(data, 4);

            // SmbCreateFlags (8 bytes) - MUST NOT be used and MUST be reserved
            BitConverterLE.GetBytes((ulong)0).CopyTo(data, 8);

            // Reserved (8 bytes) - MUST NOT be used and MUST be reserved
            BitConverterLE.GetBytes((ulong)0).CopyTo(data, 16);

            // DesiredAccess (4 bytes)
            BitConverterLE.GetBytes((uint)this.DesiredAccess).CopyTo(data, 24);

            // FileAttributes (4 bytes) 
            BitConverterLE.GetBytes((uint)this.FileAttributes).CopyTo(data, 28);

            // ShareAccess (4 bytes)
            BitConverterLE.GetBytes((uint)this.ShareAccess).CopyTo(data, 32);

            // CreateDisposition (4 bytes)
            BitConverterLE.GetBytes((uint)this.CreateDisposition).CopyTo(data, 36);

            // CreateOptions (4 bytes)
            BitConverterLE.GetBytes((uint)this.CreateOptions).CopyTo(data, 40);

            // NameOffset (2 bytes)
            BitConverterLE.GetBytes((ushort)offset).CopyTo(data, 44);
            int nameOffset = offset - Packet.HeaderLength;

            // NameLength (2 bytes)
            int length = Encoding.Unicode.GetByteCount(this.Filename);
            BitConverterLE.GetBytes((ushort)length).CopyTo(data, 46);
            offset += length + (8 - (length % 8));

            byte[] create_contexts = new byte[Create_Create_Context.Size(this.CreateContexts)];
            int ccoffset = 0;
            foreach (Create_Create_Context createcontext in this.CreateContexts)
            {
                createcontext.Flatten().CopyTo(create_contexts, ccoffset);
                ccoffset += createcontext.Size();
            }

            // CreateContextOffset (4 bytes)
            ccoffset = offset - Packet.HeaderLength;
            if (this.CreateContexts.Count == 0)
            {
                BitConverterLE.GetBytes((uint)0).CopyTo(data, 48);
            }
            else
            {
                BitConverterLE.GetBytes((uint)offset).CopyTo(data, 48);
                offset += create_contexts.Length;
            }

            // CreateContextLength (4 bytes)
            BitConverterLE.GetBytes((uint)create_contexts.Length).CopyTo(data, 52);

            // Buffer (variable)
            byte[] data_and_buffer = new byte[data.Length + (offset - Packet.HeaderLength - 57)];
            data.CopyTo(data_and_buffer, 0);
            Encoding.Unicode.GetBytes(this.Filename).CopyTo(data_and_buffer, nameOffset);
            create_contexts.CopyTo(data_and_buffer, ccoffset);

            return data_and_buffer;
        }
    }
}

namespace Cimba.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.Contracts;
    using System.Text;
    using Cimba.Protocol.External.Microsoft;

    internal enum Create_Oplock_Level : byte
    {
        NONE = 0x00,
        II = 0x01,
        EXCLUSIVE = 0x08,
        BATCH = 0x09,
        LEASE = 0xFF
    }

    internal enum Create_Impersonation_Level : uint
    {
        Anonymous = 0x00000000,
        Identification = 0x00000001,
        Impersonation = 0x00000002,
        Delegate = 0x00000003
    }

    internal enum Create_Share_Access : uint
    {
        SHARE_READ = 0x00000001,
        SHARE_WRITE = 0x00000002,
        SHARE_DELETE = 0x00000004
    }

    internal enum Create_Create_Disposition : uint
    {
        SUPERSEDE = 0x00000000,
        OPEN = 0x00000001,
        CREATE = 0x00000002,
        OPEN_IF = 0x00000003,
        OVERWRITE = 0x00000004,
        OVERWRITE_IF = 0x00000005
    }

    internal enum Create_Create_Options : uint
    {
        DIRECTORY_FILE = 0x00000001,
        WRITE_THROUGH = 0x00000002,
        SEQUENTIAL_ONLY = 0x00000004,
        NO_INTERMEDIATE_BUFFERING = 0x00000008,
        SYNCHRONOUS_IO_ALERT = 0x00000010,
        SYNCHRONOUS_IO_NONALERT = 0x00000020,
        NON_DIRECTORY_FILE = 0x00000040,
        COMPLETE_IF_OPLOCKED = 0x00000100,
        NO_EA_KNOWLEDGE = 0x00000200,
        RANDOM_ACCESS = 0x00000800,
        DELETE_ON_CLOSE = 0x00001000,
        OPEN_BY_FILE_ID = 0x00002000,
        OPEN_FOR_BACKUP_INTENT = 0x00004000,
        NO_COMPRESSION = 0x00008000,
        RESERVE_OPFILTER = 0x00100000,
        OPEN_REPARSE_POINT = 0x00200000,
        OPEN_NO_RECALL = 0x00400000,
        OPEN_FOR_FREE_SPACE_QUERY = 0x00800000
    }

    internal enum Create_Create_Action : uint
    {
        Superseded = 0x00000000,
        Opened = 0x00000001,
        Created = 0x00000002,
        Overwritten = 0x00000003
    }

    internal struct Create_Create_Context
    {
        internal uint Next;
        internal ushort NameOffset;
        internal ushort NameLength;
        internal ushort DataOffset;
        internal uint DataLength;
        internal byte[] Buffer;

        internal static Create_Create_Context Unflatten(byte[] buffer)
        {
            Create_Create_Context context = new Create_Create_Context();
            context.Next = BitConverterLE.ToUInt(buffer, 0);
            context.NameOffset = BitConverterLE.ToUShort(buffer, 4);
            context.NameLength = BitConverterLE.ToUShort(buffer, 6);
            context.DataOffset = BitConverterLE.ToUShort(buffer, 10);
            context.DataLength = BitConverterLE.ToUShort(buffer, 12);
            context.Buffer = new byte[buffer.Length - 16];
            Array.Copy(buffer, 16, context.Buffer, 0, context.Buffer.Length);
            return context;
        }

        internal static List<Create_Create_Context> UnflattenBuffer(byte[] buffer)
        {
            List<Create_Create_Context> returnlist = new List<Create_Create_Context>();
            if (buffer.Length > 0)
            {
                uint next = 0;
                do
                {
                    uint length = BitConverterLE.ToUInt(buffer, 0) - next;
                    byte[] tempbuffer = new byte[length];
                    Array.Copy(buffer, next, tempbuffer, 0, length);
                    returnlist.Add(Unflatten(tempbuffer));
                    next = +length;
                }
                while (next != 0);
            }

            return returnlist;
        }

        internal static int Size(List<Create_Create_Context> ccs)
        {
            int totallength = 0;
            foreach (Create_Create_Context createContext in ccs)
            {
                totallength += createContext.Size();
            }

            return totallength;
        }

        internal static byte[] Flatten(List<Create_Create_Context> list)
        {
            // TODO: IMPLEMENT!
            return new byte[0];
        }

        internal Create_Create_Context EA_BUFFER(Dictionary<string, byte[]> extendedAttributes, bool lastContext = false)
        {
            Create_Create_Context new_context = new Create_Create_Context();
            byte[] data = FSCC.GenerateFileFullEaInformation(extendedAttributes);

            new_context.NameOffset = 16;
            new_context.NameLength = (ushort)Encoding.ASCII.GetByteCount("ExtA");
            new_context.DataOffset = (ushort)(16 + new_context.NameLength + (8 - (new_context.NameLength % 8)));
            new_context.DataLength = (uint)data.Length;

            uint bufferlength = new_context.DataOffset + new_context.DataLength - 16;
            bufferlength = bufferlength + (8 - (bufferlength % 8));
            byte[] buffer = new byte[bufferlength];
            Encoding.ASCII.GetBytes("ExtA").CopyTo(buffer, 0);
            data.CopyTo(buffer, new_context.DataOffset - 16);
            new_context.Buffer = buffer;

            if (lastContext)
            {
                new_context.Next = 0;
            }
            else
            {
                new_context.Next = (uint)(16 + (buffer.Length + (8 - (buffer.Length % 8))));
            }

            return new_context;
        }

        internal Dictionary<string, byte[]> EA_BUFFER(byte[] buffer)
        {
            return FSCC.ReadFileFullEaInformation(buffer);
        }

        internal int Size()
        {
            return 16 + this.Buffer.Length;
        }

        internal byte[] Flatten()
        {
            byte[] buffer = new byte[this.Size()];
            BitConverterLE.GetBytes(this.Next).CopyTo(buffer, 0);
            BitConverterLE.GetBytes(this.NameOffset).CopyTo(buffer, 4);
            BitConverterLE.GetBytes(this.NameLength).CopyTo(buffer, 6);
            BitConverterLE.GetBytes(this.DataOffset).CopyTo(buffer, 10);
            BitConverterLE.GetBytes(this.DataLength).CopyTo(buffer, 12);
            this.Buffer.CopyTo(buffer, 16);
            return buffer;
        }
    }

    internal struct FILE_ID
    {
        internal ulong Persistent;
        internal ulong Volatile;

        internal FILE_ID(ulong persistent, ulong vol)
        {
            this.Persistent = persistent;
            this.Volatile = vol;
        }

        internal FILE_ID(byte[] bytestream)
        {
            Contract.Requires(bytestream.Length == 16);
            this.Persistent = BitConverterLE.ToULong(bytestream, 0);
            this.Volatile = BitConverterLE.ToULong(bytestream, 8);
        }

        public static bool operator ==(FILE_ID a, FILE_ID b)
        {
            return a.Persistent == b.Persistent && a.Volatile == b.Volatile;
        }

        public static bool operator !=(FILE_ID a, FILE_ID b)
        {
            return !(a == b);
        }

        public override bool Equals(object obj)
        {
            return obj is FILE_ID && (FILE_ID)obj == this;
        }

        public override int GetHashCode()
        {
            return BitConverterLE.ToInt(System.Security.Cryptography.MD5.Create().ComputeHash(BitConverterLE.GetBytes(this.Volatile * this.Persistent)), 0);
        }

        internal byte[] Flatten()
        {
            byte[] buffer = new byte[16];
            BitConverterLE.GetBytes(this.Persistent).CopyTo(buffer, 0);
            BitConverterLE.GetBytes(this.Volatile).CopyTo(buffer, 8);
            return buffer;
        }
    }
}
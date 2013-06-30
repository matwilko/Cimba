namespace Cimba.Protocol
{
    using System;
    using System.Diagnostics.Contracts;
    using System.IO;
    using System.Security.Cryptography;

    internal enum PacketType : ushort
    {
        Negotiate = 0x0000,
        Session_Setup = 0x0001,
        Logoff = 0x0002,
        Tree_Connect = 0x0003,
        Tree_Disconnect = 0x0004,
        Create = 0x0005,
        Close = 0x0006,
        Flush = 0x0007,
        Read = 0x0008,
        Write = 0x0009,
        Lock = 0x000A,
        IOCTL = 0x000B,
        Cancel = 0x000C,
        Echo = 0x000D,
        Query_Directory = 0x000E,
        Change_Notify = 0x000F,
        Query_Info = 0x0010,
        Set_Info = 0x0011,
        OpLock_Break = 0x0012
    }

    internal abstract class Packet
    {
        protected const int HeaderLength = 64;

        private Packet privnextpacket = null;

        private ushort privcreditrr = 0;

        private ulong privasyncid = 0;

        private uint privprocessid = 0x0000feff;

        private PacketFlags flags = PacketFlags.NO_FLAGS;

        private byte[] signature = new byte[16];

        private byte[] rawIncomingData;

        [Flags]
        private enum PacketFlags : uint
        {
            NO_FLAGS = 0x00000000,
            SERVER_TO_REDIR = 0x00000001, // When set indicates the message is a response
            ASYNC_COMMAND = 0x00000002, // When set, indicates the packet is an ASYNC packet
            RELATED_OPERATIONS = 0x00000004, // When set, when request, indicates that the request is a related operation in a compounded request chain. When set, when response, indicates that the request corresponding to this response was part of a related operation in a compounded request chain.
            SIGNED = 0x00000008, // When set, packet is signed
            DFS_OPERATIONS = 0x10000000, // When set, indicates this is a DFS operation
        }

        internal ulong MessageId
        {
            get;
            set;
        }

        internal uint Status { get; set; }

        internal uint TreeId { get; set; }

        internal ushort CreditRequest
        {
            get
            {
                return this.CreditRR;
            }

            set
            {
                this.CreditRR = value;
            }
        }

        internal ushort CreditResponse
        {
            get
            {
                return this.CreditRR;
            }

            set
            {
                this.CreditRR = value;
            }
        }

        internal ulong SessionId { get; set; }

        internal ushort CreditCharge { get; set; }

        internal bool ASync
        {
            get
            {
                return this.flags.HasFlag(PacketFlags.ASYNC_COMMAND);
            }

            set
            {
                if (value)
                {
                    this.flags |= PacketFlags.ASYNC_COMMAND;
                }
                else
                {
                    this.flags &= ~PacketFlags.ASYNC_COMMAND;
                }
            }
        }

        internal bool IsRequest
        {
            get
            {
                return !this.flags.HasFlag(PacketFlags.SERVER_TO_REDIR);
            }

            set
            {
                if (value && this.IsRequest)
                {
                    this.flags &= ~PacketFlags.SERVER_TO_REDIR;
                }
                else if (!value)
                {
                    this.flags |= PacketFlags.SERVER_TO_REDIR;
                }
            }
        }

        [PureAttribute]
        internal bool IsCompoundRequest
        {
            get
            {
                return this.CompoundedPacket != null;
            }
        }

        internal Packet CompoundedPacket
        {
            get;
            set;
        }

        internal bool CompoundedPacketsRelated { get; set; }

        internal PacketType Command { get; set; }

        protected SmbVersion Version { get; set; }

        protected Packet NextPacket
        {
            get
            {
                return this.privnextpacket;
            }

            set
            {
                this.privnextpacket = value;
            }
        }

        protected ushort CreditRR
        {
            get
            {
                return this.privcreditrr;
            }

            set
            {
                this.privcreditrr = value;
            }
        }

        protected ulong AsyncId
        {
            get
            {
                return this.privasyncid;
            }

            set
            {
                this.privasyncid = value;
            }
        }

        protected uint ProcessId
        {
            get
            {
                return this.privprocessid;
            }

            set
            {
                this.privprocessid = value;
            }
        }

        [PureAttribute]
        public static implicit operator byte[](Packet packet)
        {
            // Refer to 2.2.1.2
            byte[] payload = packet.Generate();

            int padding = 8 - ((payload.Length + HeaderLength + 4) % 8);
            padding = padding == 8 ? 0 : padding;

            byte[] output = new byte[HeaderLength + payload.Length + padding];

            // ProtocolId (4 bytes) - The protocol identifier. Value MUST be, (in network order) 0xFE, 's', 'M', 'B'
            output[0] = 0xFE;
            output[1] = BitConverter.GetBytes('S')[0];
            output[2] = BitConverter.GetBytes('M')[0];
            output[3] = BitConverter.GetBytes('B')[0];

            // StructureSize (2 bytes) - MUST be set to 64, the size, in bytes of the SMB2 packet structure
            BitConverterLE.GetBytes((ushort)64).CopyTo(output, 4);

            // CreditCharge (2 bytes) - If version is SMB 2.002, field MUST NOT be used, MUST be reserved and set to 0. For SMB 2.1, the the number of credits this request consumes.
            if (packet.Version == SmbVersion.V20)
            {
                BitConverterLE.GetBytes((ushort)0).CopyTo(output, 6);
            }
            else
            {
                BitConverterLE.GetBytes((ushort)packet.CreditCharge).CopyTo(output, 6);
            }

            // Status (4 bytes) - Status code for a response. For a request, client MUST set this field to 0 and server MUST ignore it. For response, this field can be set to any valid status code
            if (packet.IsRequest)
            {
                BitConverterLE.GetBytes((uint)0).CopyTo(output, 8);
            }
            else
            {
                BitConverterLE.GetBytes((uint)packet.Status).CopyTo(output, 8);
            }

            // Command (2 bytes) - the command code of this packet.
            BitConverterLE.GetBytes((ushort)packet.Command).CopyTo(output, 12);

            // CreditRequest/CreditResponse (2 bytes) - On a request, indicates number of credits requested; on a response, indicates the number of credits granted.
            BitConverterLE.GetBytes((ushort)packet.CreditRR).CopyTo(output, 14);

            // Flags (4 bytes)
            BitConverterLE.GetBytes((uint)packet.flags).CopyTo(output, 16);

            // NextCommand (4 bytes) - For a compounded request, field must be set to the offset in bytes from the beginning of this SMB2 packet to the start of the subsequent 8-byte aligned SMB2 packet
            if (packet.IsCompoundRequest)
            {
                BitConverterLE.GetBytes((uint)output.Length).CopyTo(output, 20);
            }
            else
            {
                BitConverterLE.GetBytes((uint)0).CopyTo(output, 20);
            }

            // MessageId (8 bytes) - Value that identifies a message request and response uniquely across all messages
            BitConverterLE.GetBytes((ulong)packet.MessageId).CopyTo(output, 24);

            // SYNC/ASYNC deviation
            if (packet.ASync)
            {
                BitConverterLE.GetBytes((ulong)packet.AsyncId).CopyTo(output, 32);
            }
            else
            {
                // ProcessId (4 bytes) - The client-side identification of the process that issued the request. Client MUST set this field to 0xFEFF; Server must send the same ProcessId received. Client MUST ignore this field.
                BitConverterLE.GetBytes((uint)packet.ProcessId).CopyTo(output, 32);

                // TreeId (4 bytes) - Uniquely identifies the TreeConnect for the command. Must be 0 for SMB2 TREE_CONNECT request.
                BitConverterLE.GetBytes((uint)packet.TreeId).CopyTo(output, 36);
            }

            // SessionId (8 bytes) - Uniquely identifies the established session for the command. MUST be 0 for requests that do not have a user context associated with them
            BitConverterLE.GetBytes((ulong)packet.SessionId).CopyTo(output, 40);

            // Signature (16 bytes) - While it may not necessarily be required to sign the packet (that is if neither client or server requires signing) but the client always MAY sign the packet, so in this implementation, always will
            packet.signature.CopyTo(output, 48);

            payload.CopyTo(output, 64);

            byte[] netbios_encapsulation = new byte[output.Length + 4];
            netbios_encapsulation[0] = 0x00;
            netbios_encapsulation[1] = 0x00;
            BitConverterBE.GetBytes((ushort)output.Length).CopyTo(netbios_encapsulation, 2);
            output.CopyTo(netbios_encapsulation, 4);

            // Packet must be padded to an 8 byte boundary
            Contract.Ensures((output.Length % 8) == 0);

            return netbios_encapsulation;
        }

        internal static Packet[] Read(SmbVersion version, bool signingrequired, MemoryStream stream)
        {
            byte[] header = new byte[64];
            stream.Read(header, 0, 64);

            ushort creditCharge = 0;
            uint status = 0;
            PacketType command;
            ushort creditResponse = 0;
            PacketFlags flags;
            uint nextCommand = 0;
            ulong messageId;

            // ASYNC
            ulong asyncId = 0;

            // SYNC
            uint processId = 0;
            uint treeId = 0;

            ulong sessionId;

            if (BitConverterLE.ToUInt(header, 0) != BitConverter.ToUInt32(new byte[] { 0xFE, (byte)'S', (byte)'M', (byte)'B' }, 0))
            {
                throw new SmbPacketException("Incorrect ProtocolId, received: " + BitConverter.ToString(header, 0, 4));
            }

            if (BitConverterLE.ToUShort(header, 4) != 64)
            {
                throw new SmbPacketException("Incorrect StructureSize, received: " + BitConverterLE.ToUShort(header, 4));
            }

            if (version == SmbVersion.V21)
            {
                creditCharge = BitConverterLE.ToUShort(header, 6);
            }

            status = BitConverterLE.ToUInt(header, 8);

            uint com = BitConverterLE.ToUShort(header, 12);
            command = (PacketType)com;

            if (version == SmbVersion.V21)
            {
                creditResponse = BitConverterLE.ToUShort(header, 14);
            }
            else
            {
                creditResponse = 1;
            }

            flags = (PacketFlags)BitConverterLE.ToUInt(header, 16);

            nextCommand = BitConverterLE.ToUInt(header, 20);
            messageId = BitConverterLE.ToULong(header, 24);

            if (flags.HasFlag(PacketFlags.ASYNC_COMMAND))
            {
                asyncId = BitConverterLE.ToULong(header, 32);
            }
            else
            {
                processId = BitConverterLE.ToUInt(header, 32);
                treeId = BitConverterLE.ToUInt(header, 36);
            }

            sessionId = BitConverterLE.ToULong(header, 40);

            Packet packet;
            if (status == NTSTATUS.STATUS_SUCCESS | (status == NTSTATUS.STATUS_MORE_PROCESSING_REQUIRED && command == PacketType.Session_Setup))
            {
                switch (command)
                {
                    case PacketType.Negotiate:
                        if (flags.HasFlag(PacketFlags.SERVER_TO_REDIR))
                        {
                            packet = NegotiateResponse.Read(version, stream);
                        }
                        else
                        {
                            packet = NegotiateRequest.Read(stream);
                        }

                        break;

                    case PacketType.Session_Setup:
                        if (flags.HasFlag(PacketFlags.SERVER_TO_REDIR))
                        {
                            packet = SessionSetupResponse.Read(stream);
                        }
                        else
                        {
                            packet = SessionSetupRequest.Read(stream);
                        }

                        break;

                    case PacketType.Logoff:
                        if (flags.HasFlag(PacketFlags.SERVER_TO_REDIR))
                        {
                            packet = LogoffResponse.Read(stream);
                        }
                        else
                        {
                            packet = LogoffRequest.Read(stream);
                        }

                        break;

                    case PacketType.Tree_Connect:
                        if (flags.HasFlag(PacketFlags.SERVER_TO_REDIR))
                        {
                            packet = TreeConnectResponse.Read(stream);
                        }
                        else
                        {
                            packet = TreeConnectRequest.Read(stream);
                        }

                        break;

                    case PacketType.Create:
                        if (flags.HasFlag(PacketFlags.SERVER_TO_REDIR))
                        {
                            packet = CreateResponse.Read(stream);
                        }
                        else
                        {
                            packet = CreateRequest.Read(stream);
                        }

                        break;

                    case PacketType.Close:
                        if (flags.HasFlag(PacketFlags.SERVER_TO_REDIR))
                        {
                            packet = CloseResponse.Read(stream);
                        }
                        else
                        {
                            packet = CloseRequest.Read(stream);
                        }

                        break;

                    case PacketType.Read:
                        if (flags.HasFlag(PacketFlags.SERVER_TO_REDIR))
                        {
                            packet = ReadResponse.Read(stream);
                        }
                        else
                        {
                            packet = ReadRequest.Read(stream);
                        }

                        break;

                    case PacketType.Write:
                        if (flags.HasFlag(PacketFlags.SERVER_TO_REDIR))
                        {
                            packet = WriteResponse.Read(stream);
                        }
                        else
                        {
                            packet = WriteRequest.Read(stream);
                        }

                        break;

                    case PacketType.Flush:
                        if (flags.HasFlag(PacketFlags.SERVER_TO_REDIR))
                        {
                            packet = FlushResponse.Read(stream);
                        }
                        else
                        {
                            packet = FlushRequest.Read(stream);
                        }

                        break;

                    case PacketType.Query_Directory:
                        if (flags.HasFlag(PacketFlags.SERVER_TO_REDIR))
                        {
                            packet = QueryDirectoryResponse.Read(stream);
                        }
                        else
                        {
                            packet = QueryDirectoryRequest.Read(stream);
                        }

                        break;

                    case PacketType.Tree_Disconnect:
                        if (flags.HasFlag(PacketFlags.SERVER_TO_REDIR))
                        {
                            packet = TreeDisconnectResponse.Read(stream);
                        }
                        else
                        {
                            packet = TreeDisconnectRequest.Read(stream);
                        }

                        break;

                    case PacketType.IOCTL:
                        if (flags.HasFlag(PacketFlags.SERVER_TO_REDIR))
                        {
                            packet = IOCTLResponse.Read(stream);
                        }
                        else
                        {
                            packet = IOCTLRequest.Read(stream);
                        }

                        break;

                    case PacketType.Query_Info:
                        if (flags.HasFlag(PacketFlags.SERVER_TO_REDIR))
                        {
                            packet = QueryInfoResponse.Read(stream);
                        }
                        else
                        {
                            packet = QueryInfoRequest.Read(stream);
                        }

                        break;

                    default:
                        throw new SmbPacketException("Unknown Command, received: " + (ushort)command);
                }
            }
            else
            { // Will be an error packet
                packet = ErrorResponse.Read(stream);
            }

            packet.Version = version;
            packet.CreditCharge = creditCharge;
            packet.Status = status;
            packet.CreditRR = creditResponse;
            packet.flags = flags;
            packet.MessageId = messageId;
            packet.Command = command;

            // ASYNC
            packet.AsyncId = asyncId;

            // SYNC
            packet.ProcessId = processId;
            packet.TreeId = treeId;
            packet.SessionId = sessionId;

            if (nextCommand != 0)
            {
                ////uint padding = 8 - (nextCommand % 8);
                ////stream.Seek(padding, SeekOrigin.Current);
                stream.Seek(nextCommand, SeekOrigin.Begin);
                byte[] newstream = new byte[stream.Length - nextCommand];
                stream.Read(newstream, 0, newstream.Length);
                Packet[] extrapackets = Packet.Read(version, signingrequired, new MemoryStream(newstream));
                Packet[] packets = new Packet[extrapackets.Length + 1];
                packets[0] = packet;
                extrapackets.CopyTo(packets, 1);
                return packets;
            }
            else
            {
                return new Packet[1] { packet };
            }
        }

        internal static byte[] ForceRead(Stream stream, byte[] buffer, int length)
        {
            Contract.Assert(buffer.Length == length);
            Contract.Assert(stream.CanRead);
            int bytesread = 0;
            while (bytesread < length)
            {
                bytesread += stream.Read(buffer, bytesread, length - bytesread);
            }

            return buffer;
        }

        internal static bool IsSmb1(byte[] data)
        {
            return data[0] == 0xFF && data[1] == 0x53 && data[2] == 0x4d && data[3] == 0x42;
        }

        internal static SmbComNegotiate ReadSmbComNegotiate(byte[] data)
        {
            return SmbComNegotiate.Read(new MemoryStream(data));
        }

        internal bool VerifySignature(byte[] sessionKey, bool requireSigning)
        {
            byte[] sig = this.signature;
            if (!requireSigning)
            {
                bool zeros = true;
                for (int i = 0; i < 16; i++)
                {
                    if (sig[i] != 0)
                    {
                        zeros = false;
                        break;
                    }
                }

                if (zeros)
                {
                    return true;
                }
            }

            this.signature = new byte[16];
            HMACSHA256 hasher = new HMACSHA256(sessionKey);
            byte[] compareSig = hasher.ComputeHash(this);
            this.signature = sig;
            for (int i = 0; i < 16; i++)
            {
                if (sig[i] != compareSig[i])
                {
                    return false;
                }
            }

            return true;
        }

        internal void SignPacket(byte[] sessionKey)
        {
            this.signature = new byte[16];
            HMACSHA256 hasher = new HMACSHA256(sessionKey);
            byte[] sig = hasher.ComputeHash(this);
            Array.Copy(sig, 0, this.signature, 0, 16);
            ////this.flags |= PacketFlags.SIGNED;
        }

        [PureAttribute]
        protected abstract byte[] Generate();
    }
}

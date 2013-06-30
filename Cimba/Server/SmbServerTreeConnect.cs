namespace Cimba.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Threading;
    using Cimba.Protocol;

    public delegate Tuple<OpenDelegate, ListDirectoryDelegate, ReadDelegate> NewTreeConnectDelegate(SmbServerTreeConnect treeConnect);

    public delegate bool CanAccessShareDelegate(string shareName);

    public delegate SmbServerShare GetShareDelegate(string shareName);

    public delegate byte[] ReadDelegate(string fileName, int length, int offset);

    public class SmbServerTreeConnect
    {
        private OpenDelegate open;

        private ListDirectoryDelegate listDir;

        private ReadDelegate read;

        private Dictionary<FILE_ID, SmbServerOpen> opens = new Dictionary<FILE_ID, SmbServerOpen>();

        private bool doneDirEnum = false;

        internal SmbServerTreeConnect(SmbServerSession session, TreeConnectRequest request, SmbServerShare share, NewTreeConnectDelegate notify)
        {
            this.Session = session;
            this.Share = share;
            if (this.Share == null)
            {
                throw new SmbTreeConnectException("Share does not exist");
            }

            this.TreeId = (uint)(new Random()).Next();

            TreeConnectResponse response = new TreeConnectResponse();
            response.Type = this.Share.ShareType;
            response.Flags = this.Share.Flags;
            response.Capabilities = this.Share.Capabilities;
            response.MaximalAccess = this.Share.MaximalAccess;

            this.SendPacket(request, response);
            Tuple<OpenDelegate, ListDirectoryDelegate, ReadDelegate> delegates = notify(this);
            this.open = delegates.Item1;
            this.listDir = delegates.Item2;
            this.read = delegates.Item3;
        }

        public delegate void DisconnectDelegate();

        public SmbServerShare Share { get; private set; }

        public SmbServerSession Session { get; private set; }

        internal uint TreeId { get; private set; }

        internal void SendPacket(Packet request, Packet response)
        {
            response.TreeId = this.TreeId;
            this.Session.SendPacket(request, response);
        }

        internal void ProcessPacket(Packet packet)
        {
            if (packet is IOCTLRequest)
            {
                IOCTLRequest request = (IOCTLRequest)packet;
                if (request.CtlCode == 0x00060194)
                {
                    this.Session.Connection.ClientError(packet, NTSTATUS.STATUS_FS_DRIVER_REQUIRED);
                }
                else
                {
                    this.Session.Connection.ClientError(packet, NTSTATUS.STATUS_NOT_SUPPORTED);
                }
            }
            else if (packet is CreateRequest)
            {
                SpinWait.SpinUntil(() =>
                    {
                        return this.open != null;
                    });
                try
                {
                    SmbServerOpen open = new SmbServerOpen(this, (CreateRequest)packet, this.open);
                    this.opens.Add(open.FileId, open);
                }
                catch (NotSupportedException)
                {
                    this.Session.Connection.ClientError(packet, NTSTATUS.STATUS_NOT_SUPPORTED);
                }
                catch (FileNotFoundException)
                {
                    this.Session.Connection.ClientError(packet, NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND);
                }
            }
            else if (packet is CloseRequest)
            {
                CloseRequest request = (CloseRequest)packet;
                Console.WriteLine(this.opens.Count);
                Console.WriteLine(BitConverter.ToString(request.FileId.Flatten()));
                foreach (KeyValuePair<FILE_ID, SmbServerOpen> open in this.opens)
                {
                    Console.WriteLine(BitConverter.ToString(open.Key.Flatten()));
                }

                if (this.opens.ContainsKey(request.FileId))
                {
                    CloseResponse response = new CloseResponse();
                    if (request.CorrectAttributes)
                    {
                        SmbServerOpenHandle handle = this.opens[request.FileId].Handle;
                        response.CreationTime = (ulong)handle.CreationTime.ToFileTime();
                        response.LastAccessTime = (ulong)handle.LastAccessTime.ToFileTime();
                        response.LastWriteTime = (ulong)handle.LastWriteTime.ToFileTime();
                        response.ChangeTime = (ulong)handle.ChangeTime.ToFileTime();
                        response.AllocationSize = (ulong)handle.AllocationSize;
                        response.EndOfFile = (ulong)handle.EndofFile;
                        response.FileAttributes = handle.BinaryAttributes;
                    }

                    this.opens.Remove(request.FileId);
                    this.SendPacket(packet, response);
                }
                else
                {
                    this.Session.Connection.ClientError(packet, NTSTATUS.STATUS_FILE_CLOSED);
                }
            }
            else if (packet is QueryDirectoryRequest)
            {
                QueryDirectoryRequest request = (QueryDirectoryRequest)packet;
                if (this.opens.ContainsKey(request.FileId))
                {
                    if (request.Flags.HasFlag(QueryDirectory_Flags.RESTART_SCANS))
                    {
                        this.opens[request.FileId].DirectoryEnumed = false;
                    }

                    if (!this.opens[request.FileId].DirectoryEnumed)
                    {
                        Console.WriteLine(this.opens[request.FileId].Handle.FileName);
                        byte[] list = SmbServerDirectoryListing.Flatten(this.listDir(this.opens[request.FileId].Handle.FileName, request.FileName));
                        QueryDirectoryResponse response = new QueryDirectoryResponse();
                        response.Buffer = list;
                        this.SendPacket(request, response);
                        this.opens[request.FileId].DirectoryEnumed = true;
                    }
                    else
                    {
                        QueryDirectoryResponse response = new QueryDirectoryResponse();
                        response.Buffer = new byte[0];
                        response.Status = NTSTATUS.STATUS_NO_MORE_FILES;
                        this.SendPacket(request, response);
                    }
                }
                else
                {
                    this.Session.Connection.ClientError(packet, NTSTATUS.STATUS_FILE_CLOSED);
                }
            }
            else if (packet is ReadRequest)
            {
                ReadRequest request = (ReadRequest)packet;
                if (this.opens.ContainsKey(request.FileId))
                {
                    SpinWait.SpinUntil(() =>
                        {
                            return this.read != null;
                        });
                    byte[] data = this.read(this.opens[request.FileId].Handle.FileName, (int)request.Length, (int)request.Offset);
                    ReadResponse response = new ReadResponse();
                    response.Data = data;
                    this.SendPacket(request, response);
                }
            }
        }
    }
}
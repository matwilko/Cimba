namespace Cimba.Client
{
    using System;
    using System.Diagnostics.Contracts;
    using Cimba.Protocol;

    public class SmbClientOpen_File : SmbClientOpen
    {
        internal SmbClientOpen_File(SmbClientTreeConnect treeConnect, string filePath, FileAccess desiredFilePermissions, ShareAccess sharingMode, OpenDisposition disposition, Access desiredExtendedAttributesPermission = Access.Read, Access desiredAttributesPermission = Access.Read, OppurtunisticLockLevel requestedOplockLevel = OppurtunisticLockLevel.Exclusive, ImpersonationLevel impersonationLevel = ImpersonationLevel.Impersonation, bool disableBuffering = false, bool randomAccess = false, bool noRecall = true)
        {
            this.TreeConnect = treeConnect;

            CreateRequest request = new CreateRequest(filePath);
            request.RequestedOplockLevel = ConvertOplockLevel(requestedOplockLevel);
            request.ImpersonationLevel = ConvertImpLevel(impersonationLevel);
            request.DesiredAccess = ConvertDesiredAccess(desiredFilePermissions, desiredExtendedAttributesPermission, desiredAttributesPermission);
            request.ShareAccess = ConvertShareAccess(sharingMode);
            request.CreateDisposition = ConvertDisposition(disposition);

            request.CreateOptions = Create_Create_Options.NON_DIRECTORY_FILE;
            if (disableBuffering)
            {
                request.CreateOptions |= Create_Create_Options.WRITE_THROUGH | Create_Create_Options.NO_INTERMEDIATE_BUFFERING;
            }

            if (randomAccess)
            {
                request.CreateOptions |= Create_Create_Options.RANDOM_ACCESS;
            }
            else
            {
                request.CreateOptions |= Create_Create_Options.SEQUENTIAL_ONLY;
            }

            if (noRecall)
            {
                request.CreateOptions |= Create_Create_Options.OPEN_NO_RECALL;
            }

            CreateResponse response = (CreateResponse)this.ReceivePacket(this.SendPacket(request));

            if (this.TreeConnect.IsDfsShare)
            {
                this.FileName = filePath;
            }
            else
            {
                this.FileName = this.TreeConnect.ShareName + "\\" + filePath;
            }

            this.Durable = false;
            this.FileId = response.FileId;
            this.OplockLevel = ConvertOplockLevel(response.OplockLevel);
            this.ResilientHandle = false;

            this.TreeConnect.Session.Connection.AddOpen(this);
        }

        internal SmbClientOpen_File(SmbClientTreeConnect treeConnect, string filePath, FileAccess desiredFilePermissions, ShareAccess sharingMode, FileAttributes attributes, Access desiredExtendedAttributesPermission, Access desiredAttributesPermission, OppurtunisticLockLevel requestedOplockLevel, ImpersonationLevel impersonationLevel, bool disableBuffering, bool randomAccess, bool noRecall)
        {
            this.TreeConnect = treeConnect;

            CreateRequest request = new CreateRequest(filePath);
            request.RequestedOplockLevel = ConvertOplockLevel(requestedOplockLevel);
            request.ImpersonationLevel = ConvertImpLevel(impersonationLevel);
            request.DesiredAccess = ConvertDesiredAccess(desiredFilePermissions, desiredExtendedAttributesPermission, desiredAttributesPermission);
            request.ShareAccess = ConvertShareAccess(sharingMode);
            request.CreateDisposition = Create_Create_Disposition.CREATE;
            request.FileAttributes = ConvertFileAttributes(attributes);

            request.CreateOptions = Create_Create_Options.NON_DIRECTORY_FILE;
            if (disableBuffering)
            {
                request.CreateOptions |= Create_Create_Options.WRITE_THROUGH | Create_Create_Options.NO_INTERMEDIATE_BUFFERING;
            }

            if (randomAccess)
            {
                request.CreateOptions |= Create_Create_Options.RANDOM_ACCESS;
            }
            else
            {
                request.CreateOptions |= Create_Create_Options.SEQUENTIAL_ONLY;
            }

            if (noRecall)
            {
                request.CreateOptions |= Create_Create_Options.OPEN_NO_RECALL;
            }

            CreateResponse response = (CreateResponse)this.ReceivePacket(this.SendPacket(request));

            if (this.TreeConnect.IsDfsShare)
            {
                this.FileName = filePath;
            }
            else
            {
                this.FileName = this.TreeConnect.ShareName + "\\" + filePath;
            }

            this.Durable = false;
            this.FileId = response.FileId;
            this.OplockLevel = ConvertOplockLevel(response.OplockLevel);
            this.ResilientHandle = false;

            this.TreeConnect.Session.Connection.AddOpen(this);
        }

        internal SmbClientOpen_File(SmbClientTreeConnect treeConnect, string filePath, FileAccess desiredFilePermissions, ShareAccess sharingMode, FileAttributes attributes, Access desiredExtendedAttributesPermission, Access desiredAttributesPermission, OppurtunisticLockLevel requestedOplockLevel, ImpersonationLevel impersonationLevel)
        {
            this.TreeConnect = treeConnect;

            CreateRequest request = new CreateRequest(filePath);
            request.RequestedOplockLevel = ConvertOplockLevel(requestedOplockLevel);
            request.ImpersonationLevel = ConvertImpLevel(impersonationLevel);
            request.DesiredAccess = ConvertDesiredAccess(desiredFilePermissions, desiredExtendedAttributesPermission, desiredAttributesPermission);
            request.ShareAccess = ConvertShareAccess(sharingMode);
            request.CreateDisposition = Create_Create_Disposition.CREATE;
            request.FileAttributes = Protocol.External.Microsoft.FSCC.FILE_ATTRIBUTE.TEMPORARY;

            request.CreateOptions = Create_Create_Options.NON_DIRECTORY_FILE | Create_Create_Options.DELETE_ON_CLOSE | Create_Create_Options.WRITE_THROUGH | Create_Create_Options.NO_INTERMEDIATE_BUFFERING | Create_Create_Options.RANDOM_ACCESS | Create_Create_Options.OPEN_NO_RECALL;

            CreateResponse response = (CreateResponse)this.ReceivePacket(this.SendPacket(request));

            if (this.TreeConnect.IsDfsShare)
            {
                this.FileName = filePath;
            }
            else
            {
                this.FileName = this.TreeConnect.ShareName + "\\" + filePath;
            }

            this.Durable = false;
            this.FileId = response.FileId;
            this.OplockLevel = ConvertOplockLevel(response.OplockLevel);
            this.ResilientHandle = false;

            this.TreeConnect.Session.Connection.AddOpen(this);
        }

        internal SmbClientOpen_File(SmbClientTreeConnect treeConnect, string filePath)
        {
            this.TreeConnect = treeConnect;

            CreateRequest request = new CreateRequest(filePath);
            request.RequestedOplockLevel = Create_Oplock_Level.EXCLUSIVE;
            request.ImpersonationLevel = Create_Impersonation_Level.Impersonation;
            request.DesiredAccess = AccessMask.File_Pipe_Printer.DELETE;
            request.ShareAccess = Create_Share_Access.SHARE_DELETE;
            request.CreateDisposition = Create_Create_Disposition.OPEN;

            request.CreateOptions = Create_Create_Options.NON_DIRECTORY_FILE | Create_Create_Options.DELETE_ON_CLOSE | Create_Create_Options.WRITE_THROUGH | Create_Create_Options.NO_INTERMEDIATE_BUFFERING;

            CreateResponse response = (CreateResponse)this.ReceivePacket(this.SendPacket(request));

            if (this.TreeConnect.IsDfsShare)
            {
                this.FileName = filePath;
            }
            else
            {
                this.FileName = this.TreeConnect.ShareName + "\\" + filePath;
            }

            this.Durable = false;
            this.FileId = response.FileId;
            this.OplockLevel = ConvertOplockLevel(response.OplockLevel);
            this.ResilientHandle = false;
        }

        public byte[] Read(int offset, int numBytes, int minNum)
        {
            Contract.Requires(offset >= 0);
            Contract.Requires(numBytes >= 0);
            Contract.Requires(minNum >= 0);

            if (numBytes > this.TreeConnect.Session.Connection.MaxReadSize)
            {
                // TODO: Split into multiple requests
                throw new NotImplementedException();
            }
            else
            {
                ReadRequest request = new ReadRequest(this.FileId, (uint)numBytes, (ulong)offset, (uint)minNum);
                if (this.TreeConnect.Session.Connection.SupportsMultiCredit)
                {
                    request.CreditCharge = (ushort)(1 + ((numBytes - 1) / 65536));
                }

                ReadResponse response = (ReadResponse)this.TreeConnect.ReceivePacket(this.TreeConnect.SendPacket(request));
                return response.Data;
            }
        }

        public void Write(long offset, byte[] bytes)
        {
            Contract.Requires(offset >= 0);
            if (this.Durable)
            {
                // TODO: Durable logic
                throw new NotImplementedException();
            }
            else
            {
                WriteRequest request = new WriteRequest(this.FileId, bytes, (ulong)offset);
                WriteResponse response = (WriteResponse)this.TreeConnect.ReceivePacket(this.TreeConnect.SendPacket(request));
            }
        }

        public void Flush()
        {
            // TODO: Durable handle
            this.TreeConnect.ReceivePacket(this.TreeConnect.SendPacket(new FlushRequest(this.FileId)));
        }
    }
}

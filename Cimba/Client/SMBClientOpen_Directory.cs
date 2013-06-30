namespace Cimba.Client
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using Cimba.Protocol;
    using Cimba.Protocol.External.Microsoft;

    public class SmbClientOpen_Directory : SmbClientOpen
    {
        internal SmbClientOpen_Directory(SmbClientTreeConnect treeConnect, string directoryPath, FileAccess desiredDirectoryPermissions, ShareAccess sharingMode, Access desiredExtendedAttributesPermission = Access.Read, Access desiredAttributesPermission = Access.Read, OppurtunisticLockLevel requestedOplockLevel = OppurtunisticLockLevel.Exclusive, ImpersonationLevel impersonationLevel = ImpersonationLevel.Impersonation)
        {
            this.TreeConnect = treeConnect;

            CreateRequest request = new CreateRequest(directoryPath);
            request.RequestedOplockLevel = ConvertOplockLevel(requestedOplockLevel);
            request.ImpersonationLevel = ConvertImpLevel(impersonationLevel);
            request.DesiredAccess = ConvertDesiredAccess(desiredDirectoryPermissions, desiredExtendedAttributesPermission, desiredAttributesPermission);
            request.ShareAccess = ConvertShareAccess(sharingMode);
            request.CreateDisposition = Create_Create_Disposition.OPEN;

            request.CreateOptions = Create_Create_Options.DIRECTORY_FILE;

            CreateResponse response = (CreateResponse)this.ReceivePacket(this.SendPacket(request));

            if (this.TreeConnect.IsDfsShare)
            {
                this.FileName = directoryPath;
            }
            else
            {
                this.FileName = this.TreeConnect.ShareName + "\\" + directoryPath;
            }

            this.Durable = false;
            this.FileId = response.FileId;
            this.OplockLevel = ConvertOplockLevel(response.OplockLevel);
            this.ResilientHandle = false;

            this.TreeConnect.Session.Connection.AddOpen(this);
        }

        internal SmbClientOpen_Directory(SmbClientTreeConnect treeConnect, string directoryPath, FileAccess desiredDirectoryPermissions, ShareAccess sharingMode, FileAttributes attributes, Access desiredExtendedAttributesPermission, Access desiredAttributesPermission, OppurtunisticLockLevel requestedOplockLevel, ImpersonationLevel impersonationLevel)
        {
            this.TreeConnect = treeConnect;

            CreateRequest request = new CreateRequest(directoryPath);
            request.RequestedOplockLevel = ConvertOplockLevel(requestedOplockLevel);
            request.ImpersonationLevel = ConvertImpLevel(impersonationLevel);
            request.DesiredAccess = ConvertDesiredAccess(desiredDirectoryPermissions, desiredExtendedAttributesPermission, desiredAttributesPermission);
            request.ShareAccess = ConvertShareAccess(sharingMode);
            request.CreateDisposition = Create_Create_Disposition.CREATE;
            request.FileAttributes = ConvertFileAttributes(attributes);

            request.CreateOptions = Create_Create_Options.DIRECTORY_FILE;

            CreateResponse response = (CreateResponse)this.ReceivePacket(this.SendPacket(request));

            if (this.TreeConnect.IsDfsShare)
            {
                this.FileName = directoryPath;
            }
            else
            {
                this.FileName = this.TreeConnect.ShareName + "\\" + directoryPath;
            }

            this.Durable = false;
            this.FileId = response.FileId;
            this.OplockLevel = ConvertOplockLevel(response.OplockLevel);
            this.ResilientHandle = false;

            this.TreeConnect.Session.Connection.AddOpen(this);
        }

        internal SmbClientOpen_Directory(SmbClientTreeConnect treeConnect, string directoryPath)
        {
            this.TreeConnect = treeConnect;

            CreateRequest request = new CreateRequest(directoryPath);
            request.RequestedOplockLevel = Create_Oplock_Level.EXCLUSIVE;
            request.ImpersonationLevel = Create_Impersonation_Level.Impersonation;
            request.DesiredAccess = AccessMask.File_Pipe_Printer.DELETE;
            request.ShareAccess = Create_Share_Access.SHARE_DELETE;
            request.CreateDisposition = Create_Create_Disposition.OPEN;

            request.CreateOptions = Create_Create_Options.DIRECTORY_FILE | Create_Create_Options.DELETE_ON_CLOSE;

            CreateResponse response = (CreateResponse)this.ReceivePacket(this.SendPacket(request));

            if (this.TreeConnect.IsDfsShare)
            {
                this.FileName = directoryPath;
            }
            else
            {
                this.FileName = this.TreeConnect.ShareName + "\\" + directoryPath;
            }

            this.Durable = false;
            this.FileId = response.FileId;
            this.OplockLevel = ConvertOplockLevel(response.OplockLevel);
            this.ResilientHandle = false;
        }

        public ReadOnlyCollection<DirectoryListing> GetDirectoryListing()
        {
            QueryDirectoryRequest request = new QueryDirectoryRequest(this.FileId, FileInformationClass.BothDirectoryInformation, this.TreeConnect.Session.Connection.MaxTransactSize);
            request.Flags = QueryDirectory_Flags.REOPEN;

            if (this.TreeConnect.Session.Connection.SupportsMultiCredit && this.TreeConnect.Session.Connection.Dialect == SmbVersion.V21)
            {
                request.CreditCharge = (ushort)(1 + ((this.TreeConnect.Session.Connection.MaxTransactSize - 1) / 65536));
            }

            QueryDirectoryResponse response = (QueryDirectoryResponse)this.TreeConnect.ReceivePacket(this.TreeConnect.SendPacket(request));
            List<FileBothDirectoryInformation> internallisting = FileBothDirectoryInformation.ReadList(response.Buffer);
            List<DirectoryListing> externallisting = new List<DirectoryListing>();
            foreach (FileBothDirectoryInformation file in internallisting)
            {
                externallisting.Add(new DirectoryListing(file.FileIndex, file.CreationTime, file.LastAccessTime, file.LastWriteTime, file.ChangeTime, file.EndOfFile, file.AllocationSize, (FSCC.FILE_ATTRIBUTE)file.Attributes, file.EaSize, file.ShortName, file.FileName, this.FileName));
            }

            return externallisting.AsReadOnly();
        }

        public class DirectoryListing
        {
            internal DirectoryListing(uint fileIndex, ulong creation, ulong lastAccess, ulong lastWrite, ulong change, ulong eof, ulong allocation, FSCC.FILE_ATTRIBUTE attributes, uint extendedAttributesSize, string shortName, string fileName, string filePath)
            {
                this.CreationTime = DateTime.FromFileTime((long)creation);
                this.LastAccessTime = DateTime.FromFileTime((long)lastAccess);
                this.LastWriteTime = DateTime.FromFileTime((long)lastWrite);
                this.ChangeTime = DateTime.FromFileTime((long)change);
                this.EndofFile = (long)eof;
                this.AllocationSize = (long)allocation;
                this.Attributes = SmbClientOpen.ConvertFileAttributes(attributes);
                this.IsDirectory = attributes.HasFlag(FSCC.FILE_ATTRIBUTE.DIRECTORY);
                this.FileName = fileName;
                this.FilePath = filePath;
                this.FileIndex = fileIndex;
                this.EaSize = extendedAttributesSize;
            }

            public bool IsDirectory { get; private set; }

            public DateTime CreationTime { get; private set; }

            public DateTime LastAccessTime { get; private set; }

            public DateTime LastWriteTime { get; private set; }

            public DateTime ChangeTime { get; private set; }

            public long EndofFile { get; private set; }

            public long AllocationSize { get; private set; }

            public FileAttributes Attributes { get; private set; }

            public string FilePath { get; private set; }

            public string FileName { get; private set; }

            internal uint FileIndex { get; private set; }

            internal uint EaSize { get; private set; }
        }
    }
}

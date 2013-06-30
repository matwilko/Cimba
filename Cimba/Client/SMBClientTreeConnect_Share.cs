namespace Cimba.Client
{
    using Cimba.Protocol;

    public class SmbClientTreeConnect_Share : SmbClientTreeConnect
    {
        internal SmbClientTreeConnect_Share(TreeConnectResponse response, SmbClientSession session, string shareName)
        {
            this.SetCommonProperties(response, session, shareName);

            this.FilePermissions = FileAccess.None;
            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.READ_DATA) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_READ) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.FilePermissions |= FileAccess.Read;
            }

            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.WRITE_DATA) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_WRITE) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.FilePermissions |= FileAccess.Write;
            }

            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.APPEND_DATA) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_WRITE) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.FilePermissions |= FileAccess.Append;
            }

            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.EXECUTE) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_EXECUTE) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.FilePermissions |= FileAccess.Execute;
            }

            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.DELETE) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.FilePermissions |= FileAccess.Delete;
            }

            this.ExtendedAttributePermissions = Access.None;
            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.READ_EA) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.ExtendedAttributePermissions |= Access.Read;
            }

            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.WRITE_EA) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.ExtendedAttributePermissions |= Access.Write;
            }

            this.AttributePermissions = Access.None;
            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.READ_ATTRIBUTES) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.AttributePermissions |= Access.Read;
            }

            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.WRITE_ATTRIBUTES) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.AttributePermissions |= Access.Write;
            }

            this.CanReadSecurityDescriptor = response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.READ_CONTROL) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL);

            this.CanChangeOwner = response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.WRITE_OWNER) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL);

            this.CanWriteDACL = response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.WRITE_DAC) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL);

            this.CanWriteSACL = response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.ACCESS_SYSTEM_SECURITY);
        }

        public FileAccess FilePermissions { get; private set; }

        public Access ExtendedAttributePermissions { get; private set; }

        public Access AttributePermissions { get; private set; }

        public bool CanReadSecurityDescriptor { get; private set; }

        public bool CanWriteDACL { get; private set; }

        public bool CanWriteSACL { get; private set; }

        public bool CanChangeOwner { get; private set; }

        public SmbClientOpen_File OpenFile(string filePath, FileAccess desiredFilePermissions, ShareAccess sharingMode, OpenDisposition disposition, Access desiredExtendedAttributesPermission = Access.Read, Access desiredAttributesPermission = Access.Read, OppurtunisticLockLevel requestedOplockLevel = OppurtunisticLockLevel.Exclusive, ImpersonationLevel impersonationLevel = ImpersonationLevel.Impersonation, bool disableBuffering = false, bool randomAccess = false, bool noRecall = true)
        {
            if (!this.Valid)
            {
                throw new SmbTreeConnectException("TreeConnect not valid");
            }

            if (!this.Session.Valid)
            {
                this.Valid = false;
                throw new SmbSessionException("Session not valid");
            }

            return new SmbClientOpen_File(this, filePath, desiredFilePermissions, sharingMode, disposition, desiredExtendedAttributesPermission, desiredAttributesPermission, requestedOplockLevel, impersonationLevel, disableBuffering, randomAccess, noRecall);
        }

        public SmbClientOpen_File CreateFile(string filePath, FileAccess desiredFilePermissions, ShareAccess sharingMode, SmbClientOpen.FileAttributes attributes, Access desiredExtendedAttributesPermission = Access.Read | Access.Write, Access desiredAttributesPermission = Access.Read | Access.Write, OppurtunisticLockLevel requestedOplockLevel = OppurtunisticLockLevel.Exclusive, ImpersonationLevel impersonationLevel = ImpersonationLevel.Impersonation, bool disableBuffering = false, bool randomAccess = false, bool noRecall = true)
        {
            if (!this.Valid)
            {
                throw new SmbTreeConnectException("TreeConnect not valid");
            }

            if (!this.Session.Valid)
            {
                this.Valid = false;
                throw new SmbSessionException("Session not valid");
            }

            return new SmbClientOpen_File(this, filePath, desiredFilePermissions, sharingMode, attributes, desiredExtendedAttributesPermission, desiredAttributesPermission, requestedOplockLevel, impersonationLevel, disableBuffering, randomAccess, noRecall);
        }

        public SmbClientOpen_File TempFile(string filePath, FileAccess desiredFilePermissions, ShareAccess sharingMode, SmbClientOpen.FileAttributes attributes, Access desiredExtendedAttributesPermission = Access.Read | Access.Write, Access desiredAttributesPermission = Access.Read | Access.Write, OppurtunisticLockLevel requestedOplockLevel = OppurtunisticLockLevel.Exclusive, ImpersonationLevel impersonationLevel = ImpersonationLevel.Impersonation, bool randomAccess = false)
        {
            if (!this.Valid)
            {
                throw new SmbTreeConnectException("TreeConnect not valid");
            }

            if (!this.Session.Valid)
            {
                this.Valid = false;
                throw new SmbSessionException("Session not valid");
            }

            return new SmbClientOpen_File(this, filePath, desiredFilePermissions, sharingMode, attributes, desiredExtendedAttributesPermission, desiredAttributesPermission, requestedOplockLevel, impersonationLevel);
        }

        public void DeleteFile(string filePath)
        {
            if (!this.Valid)
            {
                throw new SmbTreeConnectException("TreeConnect not valid");
            }

            if (!this.Session.Valid)
            {
                this.Valid = false;
                throw new SmbSessionException("Session not valid");
            }

            (new SmbClientOpen_File(this, filePath)).Close();
        }

        public SmbClientOpen_Directory OpenDirectory(string directoryPath, FileAccess desiredDirectoryPermissions, ShareAccess sharingMode, Access desiredExtendedAttributesPermission = Access.Read | Access.Write, Access desiredAttributesPermission = Access.Read | Access.Write, OppurtunisticLockLevel requestedOplockLevel = OppurtunisticLockLevel.Exclusive, ImpersonationLevel impersonationLevel = ImpersonationLevel.Impersonation)
        {
            if (!this.Valid)
            {
                throw new SmbTreeConnectException("TreeConnect not valid");
            }

            if (!this.Session.Valid)
            {
                this.Valid = false;
                throw new SmbSessionException("Session not valid");
            }

            return new SmbClientOpen_Directory(this, directoryPath, desiredDirectoryPermissions, sharingMode, desiredExtendedAttributesPermission, desiredAttributesPermission, requestedOplockLevel, impersonationLevel);
        }
    }
}

namespace Cimba.Client
{
    using Cimba.Protocol;

    public class SmbClientTreeConnect_Pipe : SmbClientTreeConnect
    {
        internal SmbClientTreeConnect_Pipe(TreeConnectResponse response, SmbClientSession session, string shareName)
        {
            this.SetCommonProperties(response, session, shareName);

            this.PipePermission = PipeAccess.None;
            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.READ_DATA) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_READ) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.PipePermission |= PipeAccess.Read;
            }

            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.WRITE_DATA) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_WRITE) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.PipePermission |= PipeAccess.Write;
            }

            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.APPEND_DATA) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_WRITE) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.PipePermission |= PipeAccess.Append;
            }

            this.ExtendedAttributesPermission = Access.None;
            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.READ_EA) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_READ) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.ExtendedAttributesPermission |= Access.Read;
            }

            if (response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.WRITE_EA) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_WRITE) | response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.GENERIC_ALL))
            {
                this.ExtendedAttributesPermission |= Access.Write;
            }

            this.CanReadSecurityDescriptor = response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.READ_CONTROL);
            this.CanWriteDACL = response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.WRITE_DAC);
            this.CanWriteSACL = response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.ACCESS_SYSTEM_SECURITY);
            this.CanChangeOwner = response.MaximalAccess.HasFlag(AccessMask.File_Pipe_Printer.WRITE_OWNER);
        }

        public PipeAccess PipePermission { get; private set; }

        public Access ExtendedAttributesPermission { get; private set; }

        public bool CanReadSecurityDescriptor { get; private set; }

        public bool CanWriteDACL { get; private set; }

        public bool CanWriteSACL { get; private set; }

        public bool CanChangeOwner { get; private set; }
    }
}

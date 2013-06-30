namespace Cimba.Protocol
{
    using System.Diagnostics.Contracts;

    internal class LeaseBreakAcknowledgement : Packet
    {
        internal LeaseBreakAcknowledgement(byte[] leaseKey, LeaseState leaseState)
        {
            Contract.Requires(leaseKey.Length == 16);

            this.LeaseKey = leaseKey;
            this.LeaseState = leaseState;
        }

        internal byte[] LeaseKey { get; set; }

        internal LeaseState LeaseState { get; set; }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[36];

            // StructureSize (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)36).CopyTo(buffer, 0);

            // Reserved (2 bytes)
            // Flags (4 bytes) - MUST NOT be used and MUST be reserved
            // LeaseKey (16 bytes)
            this.LeaseKey.CopyTo(buffer, 8);

            // LeaseState (4 bytes)
            BitConverterLittleEndian.GetBytes((uint)this.LeaseState).CopyTo(buffer, 24);

            // LeaseDuration (8 bytes) - MUST NOT be used and MUST be reserved
            return buffer;
        }
    }
}

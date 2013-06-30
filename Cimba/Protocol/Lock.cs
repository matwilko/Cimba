namespace Cimba.Protocol
{
    internal struct LOCK_ELEMENT
    {
        internal ulong Offset;
        internal ulong Length;
        internal uint Flags;

        internal LOCK_ELEMENT(ulong offset, ulong length, LOCK_FLAGS flags)
        {
            this.Offset = offset;
            this.Length = length;
            this.Flags = (uint)flags;
        }

        internal enum LOCK_FLAGS : uint
        {
            SHARED_LOCK = 0x00000001,
            EXLUSIVE_LOCK = 0x00000002,
            UNLOCK = 0x00000004,
            FAIL_IMMEDIATELY = 0x00000010
        }

        internal byte[] Flatten()
        {
            byte[] buffer = new byte[24];
            BitConverterLE.GetBytes(this.Offset).CopyTo(buffer, 0);
            BitConverterLE.GetBytes(this.Length).CopyTo(buffer, 8);
            BitConverterLE.GetBytes(this.Flags).CopyTo(buffer, 16);
            return buffer;
        }
    }
}

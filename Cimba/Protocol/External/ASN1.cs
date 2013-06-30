namespace Cimba.Protocol.External
{
    internal static class ASN1
    {
        internal enum IdentClass : byte
        {
            Universal = 0x00,
            Application = 0x40,
            ContextSpecific = 0x80,
            Private = 0xC0
        }

        internal enum IdentType : byte
        {
            Primitive = 0x00,
            Constructed = 0x20
        }

        internal static bool MatchOID(uint[] oid, uint[] asn_oid)
        {
            uint[] freeoid = new uint[oid.Length];
            oid.CopyTo(freeoid, 0);
            uint[] freeasn_oid = new uint[asn_oid.Length];
            asn_oid.CopyTo(freeasn_oid, 0);

            if (freeoid.Length == freeasn_oid.Length + 1)
            {
                bool success = true;
                for (int i = 0; i < freeasn_oid.Length; i++)
                {
                    if (i == 0)
                    {
                        if (!(freeasn_oid[0] == ((freeoid[0] * 40) + freeoid[1])))
                        {
                            success = false;
                            break;
                        }
                    }
                    else
                    {
                        if (freeasn_oid[i] != freeoid[i + 1])
                        {
                            success = false;
                            break;
                        }
                    }
                }

                return success;
            }
            else
            {
                return false;
            }
        }
    }
}

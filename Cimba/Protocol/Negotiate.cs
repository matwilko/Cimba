namespace Cimba.Protocol
{
    internal enum Negotiate_SecurityMode : ushort
    {
        SigningEnabled = 0x0001,
        SigningRequired = 0x0002
    }

    internal enum Negotiate_Dialects : ushort
    {
        V20 = 0x0202,
        V21 = 0x0210
    }
}

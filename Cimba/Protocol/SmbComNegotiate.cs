namespace Cimba.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;

    internal class SmbComNegotiate : Packet
    {
        internal List<string> Dialects { get; private set; }

        internal short SelectedDialect { private get; set; }

        internal static SmbComNegotiate Read(MemoryStream stream)
        {
            // Skip Header
            stream.Seek(32, SeekOrigin.Current);

            // Skip Word/Byte Count
            stream.Seek(3, SeekOrigin.Current);

            List<string> dialects = new List<string>();
            while (stream.Position < stream.Length)
            {
                stream.Seek(1, SeekOrigin.Current);
                long startpos = stream.Position;
                while (stream.ReadByte() != 0)
                {
                }

                long strlength = stream.Position - startpos;
                byte[] stringbytes = new byte[strlength - 1];
                stream.Seek(startpos, SeekOrigin.Begin);
                stream.Read(stringbytes, 0, (int)strlength - 1);
                stream.Seek(1, SeekOrigin.Current);
                dialects.Add(Encoding.ASCII.GetString(stringbytes));
            }

            SmbComNegotiate packet = new SmbComNegotiate();
            packet.Dialects = dialects;
            return packet;
        }

        /*internal byte[] DoGenerate()
        {
            byte[] buffer = new byte[39]
            {
            0x00, 0x00, 0x00, 0x27,
            0xFF, 0x53, 0x4D, 0x42,
            0x72,
            0x00, 0x00, 0x00, 0x00,
            0x80, 0xC8, 0x53,
            0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
            0xFF, 0xFF,
            0xFF, 0xFE,
            0x00, 0x00,
            0x00, 0x00,
            0x00,
            0x00, 0x00
            };
            BitConverterLE.GetBytes((ushort)this.SelectedDialect).CopyTo(buffer, 33);
            return buffer;
        }*/

        protected override byte[] Generate()
        {
            throw new NotImplementedException();
        }
    }
}

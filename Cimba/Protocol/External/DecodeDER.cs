namespace Cimba.Protocol.External
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.Contracts;
    using System.IO;

    internal static class DecodeDER
    {
        internal static bool DecodeBoolean(MemoryStream stream, int tag = 0x01, ASN1.IdentClass identclass = ASN1.IdentClass.Universal)
        {
            Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field = DecodeField(stream, tag, identclass);
            return DecodeBoolean(field);
        }

        internal static bool DecodeBoolean(Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field)
        {
            return field.Item2[0] != 0x00;
        }

        internal static int DecodeInteger(MemoryStream stream, int tag = 0x02, ASN1.IdentClass identclass = ASN1.IdentClass.Universal)
        {
            Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field = DecodeField(stream, tag, identclass);
            return DecodeInteger(field);
        }

        internal static int DecodeInteger(Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field)
        {
            byte[] integer = field.Item2;
            if (integer.Length == 1)
            {
                return integer[0];
            }
            else if (integer.Length == 2)
            {
                return BitConverterBE.ToUShort(integer, 0);
            }
            else if (integer.Length == 3)
            {
                byte[] newbytes = new byte[4];
                integer.CopyTo(newbytes, 0);
                return (int)BitConverterBE.ToUInt(newbytes, 0);
            }
            else if (integer.Length == 4)
            {
                return (int)BitConverterBE.ToUInt(integer, 0);
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        internal static bool[] DecodeBitstring(MemoryStream stream, int tag = 0x03, ASN1.IdentClass identclass = ASN1.IdentClass.Universal)
        {
            Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field = DecodeField(stream, tag, identclass);
            return DecodeBitstring(field);
        }

        internal static bool[] DecodeBitstring(Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field)
        {
            byte unusedbits = field.Item2[0];
            bool[] output = new bool[((field.Item2.Length - 1) * 8) - unusedbits];
            for (int i = 1; i < field.Item2.Length; i++)
            {
                bool lastbyte = i == (field.Item2.Length - 1);
                output[(i - 1) * 8] = (field.Item2[i] & 0x80) == 0x80;
                if (!lastbyte || (lastbyte && unusedbits < 7))
                {
                    output[((i - 1) * 8) + 1] = (field.Item2[i] & 0x40) == 0x40;
                }

                if (!lastbyte || (lastbyte && unusedbits < 6))
                {
                    output[((i - 1) * 8) + 2] = (field.Item2[i] & 0x20) == 0x20;
                }

                if (!lastbyte || (lastbyte && unusedbits < 5))
                {
                    output[((i - 1) * 8) + 3] = (field.Item2[i] & 0x10) == 0x10;
                }

                if (!lastbyte || (lastbyte && unusedbits < 4))
                {
                    output[((i - 1) * 8) + 4] = (field.Item2[i] & 0x08) == 0x08;
                }

                if (!lastbyte || (lastbyte && unusedbits < 3))
                {
                    output[((i - 1) * 8) + 5] = (field.Item2[i] & 0x04) == 0x04;
                }

                if (!lastbyte || (lastbyte && unusedbits < 2))
                {
                    output[((i - 1) * 8) + 6] = (field.Item2[i] & 0x02) == 0x02;
                }

                if (!lastbyte || (lastbyte && unusedbits < 1))
                {
                    output[((i - 1) * 8) + 7] = (field.Item2[i] & 0x01) == 0x01;
                }
            }

            return output;
        }

        internal static byte[] DecodeOctetString(MemoryStream stream, int tag = 0x04, ASN1.IdentClass identclass = ASN1.IdentClass.Universal)
        {
            Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field = DecodeField(stream, tag, identclass);
            return DecodeOctetString(field);
        }

        internal static byte[] DecodeOctetString(Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field)
        {
            return field.Item2;
        }

        internal static void DecodeNull(MemoryStream stream, int tag = 0x05, ASN1.IdentClass identclass = ASN1.IdentClass.Universal)
        {
            Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field = DecodeField(stream, tag, identclass);
            DecodeNull(field);
        }

        internal static void DecodeNull(Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field)
        {
            if (field.Item2.Length != 0)
            {
                throw new WrongFieldException(field);
            }
        }

        internal static byte[] DecodeSequence(MemoryStream stream, int tag = 0x10, ASN1.IdentClass identclass = ASN1.IdentClass.Universal)
        {
            Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field = DecodeField(stream, tag, identclass, ASN1.IdentType.Constructed);
            return DecodeSequence(field);
        }

        internal static byte[] DecodeSequence(MemoryStream stream, int tag, ASN1.IdentClass identclass, ASN1.IdentType identtype)
        {
            Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field = DecodeField(stream, tag, identclass, identtype);
            return DecodeSequence(field);
        }

        internal static byte[] DecodeSequence(Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field)
        {
            return field.Item2;
        }

        internal static uint[] DecodeOID(MemoryStream stream, int tag = 0x06, ASN1.IdentClass identclass = ASN1.IdentClass.Universal)
        {
            Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field = DecodeField(stream, tag, identclass);
            return DecodeOID(field);
        }

        internal static uint[] DecodeOID(Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field)
        {
            return Decode7BitIntegers(field.Item2, 0x7F);
        }

        internal static string DecodeUTF8String(MemoryStream stream, int tag = 0x0C, ASN1.IdentClass identclass = ASN1.IdentClass.Universal)
        {
            Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field = DecodeField(stream, tag, identclass);
            return DecodeUTF8String(field);
        }

        internal static string DecodeUTF8String(Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field)
        {
            return new string(System.Text.UTF8Encoding.UTF8.GetChars(field.Item2));
        }

        internal static string DecodeNumericString(MemoryStream stream, int tag = 0x12, ASN1.IdentClass identclass = ASN1.IdentClass.Universal)
        {
            Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field = DecodeField(stream, tag, identclass);
            return DecodeNumericString(field);
        }

        internal static string DecodeNumericString(Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field)
        {
            return new string(System.Text.ASCIIEncoding.ASCII.GetChars(field.Item2));
        }

        internal static string DecodeIA5String(MemoryStream stream, int tag = 0x16, ASN1.IdentClass identclass = ASN1.IdentClass.Universal)
        {
            Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field = DecodeField(stream, tag, identclass);
            return DecodeIA5String(field);
        }

        internal static string DecodeIA5String(Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> field)
        {
            return new string(System.Text.ASCIIEncoding.ASCII.GetChars(field.Item2));
        }

        private static Tuple<int, ASN1.IdentClass, ASN1.IdentType> DecodeIdentifier(MemoryStream stream)
        {
            byte initialoctet = (byte)stream.ReadByte();
            ASN1.IdentClass identclass = (ASN1.IdentClass)(initialoctet & 0xC0);
            ASN1.IdentType identtype = (ASN1.IdentType)(initialoctet & 0x20);
            if ((initialoctet & 0x1F) == 0x1F)
            {
                throw new NotImplementedException();
            }

            int tag = initialoctet & 0x1F;
            return new Tuple<int, ASN1.IdentClass, ASN1.IdentType>(tag, identclass, identtype);
        }

        private static int DecodeLength(MemoryStream stream)
        {
            byte initialoctet = (byte)stream.ReadByte();
            if ((initialoctet & 0x80) == 0x80)
            {
                // Long form
                byte numoctets = (byte)(initialoctet & 0x7F);
                byte[] length = new byte[numoctets];
                stream.Read(length, 0, numoctets);
                if (numoctets == 1)
                {
                    return length[0];
                }
                else if (numoctets == 2)
                {
                    return BitConverterBE.ToUShort(length, 0);
                }
                else if (numoctets == 3)
                {
                    byte[] newbytes = new byte[4];
                    length.CopyTo(newbytes, 0);
                    return (int)BitConverterBE.ToUInt(newbytes, 0);
                }
                else if (numoctets == 4)
                {
                    return (int)BitConverterBE.ToUInt(length, 0);
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
            else
            {
                // Short form
                return initialoctet;
            }
        }

        private static Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> DecodeField(MemoryStream stream, int tag, ASN1.IdentClass identclass = ASN1.IdentClass.Universal, ASN1.IdentType identtype = ASN1.IdentType.Primitive)
        {
            long pos = stream.Position;
            Tuple<int, ASN1.IdentClass, ASN1.IdentType> ident = DecodeIdentifier(stream);
            int length = DecodeLength(stream);
            byte[] content = new byte[length];
            stream.Read(content, 0, length);
            Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> returntuple = new Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType>(ident.Item1, content, ident.Item2, ident.Item3);
            if (ident.Item1 != tag || ident.Item2 != identclass || ident.Item3 != identtype)
            {
                stream.Seek(pos, SeekOrigin.Begin);
                throw new WrongFieldException(returntuple);
            }

            return returntuple;
        }

        private static uint Decode7BitInteger(byte[] input)
        {
            if (input.Length == 0)
            {
                return 0;
            }

            int extrabyte = input.Length == 5 ? input[0] : 0x00;
            int msb = input.Length == 5 ? input[1] : input.Length == 4 ? input[0] : 0x00;
            int mmsb = input.Length == 5 ? input[2] : input.Length == 4 ? input[1] : input.Length == 3 ? input[0] : 0x00;
            int mlsb = input.Length == 5 ? input[3] : input.Length == 4 ? input[2] : input.Length == 3 ? input[1] : input.Length == 2 ? input[0] : 0x00;
            int lsb = input.Length == 5 ? input[4] : input.Length == 4 ? input[3] : input.Length == 3 ? input[2] : input.Length == 2 ? input[1] : input.Length == 1 ? input[0] : 0x00;

            lsb = lsb & 0x0000007F;
            mlsb = (mlsb & 0x0000007F) << 7;
            mmsb = (mmsb & 0x0000007F) << 14;
            msb = (msb & 0x000000007F) << 21;
            extrabyte = (msb & 0x0000000F) << 28;
            return (uint)(lsb | mlsb | mmsb | msb | extrabyte);
        }

        private static uint[] Decode7BitIntegers(byte[] input, byte markend)
        {
            Contract.Requires(markend == 0x7F || markend == 0x80);
            List<uint> returnints = new List<uint>();
            byte[] currentint = new byte[5];
            byte pos = 0;
            markend = (byte)(markend & 0x80);
            for (int i = 0; i < input.Length; i++)
            {
                currentint[pos] = input[i];
                if ((input[i] & 0x80) == markend)
                {
                    byte[] decodeint = new byte[pos + 1];
                    Array.Copy(currentint, 0, decodeint, 0, pos + 1);
                    returnints.Add(Decode7BitInteger(decodeint));
                    pos = 0;
                }
                else
                {
                    pos++;
                }
            }

            return returnints.ToArray();
        }

        internal class WrongFieldException : Exception
        {
            internal WrongFieldException(Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> data)
            {
                this.ASNData = data;
            }

            internal Tuple<int, byte[], ASN1.IdentClass, ASN1.IdentType> ASNData { get; private set; }
        }
    }
}

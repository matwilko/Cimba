namespace Cimba.Protocol.External
{
    using System;
    using System.Diagnostics.Contracts;

    internal static class EncodeDER
    {
        private static readonly byte[] booleanTrue = new byte[3] { 1, 1, 0xFF };

        private static readonly byte[] booleanFalse = new byte[3] { 1, 1, 0x00 };

        private static readonly byte[] nullEncoded = new byte[2] { EncodeIdentifier(0x05)[0], 0 };

        internal static byte[] EncodeBoolean(bool input)
        {
            if (input)
            {
                return booleanTrue;
            }
            else
            {
                return booleanFalse;
            }
        }

        internal static byte[] EncodeInteger(int input, int tag = 0x02, ASN1.IdentClass identclass = ASN1.IdentClass.Universal)
        {
            byte[] returnbytes;
            if (input != 0)
            {
                byte[] intbytes = BitConverterBigEndian.GetBytes(input);
                byte numbytes = 0;
                while (numbytes < intbytes.Length && intbytes[numbytes] == 0x00)
                {
                    numbytes++;
                }

                returnbytes = new byte[(4 - numbytes)];
                Array.Copy(intbytes, numbytes, returnbytes, 0, (4 - numbytes));
            }
            else
            {
                returnbytes = new byte[1] { 0 };
            }

            return EncodeAll(tag, returnbytes, identclass);
        }

        internal static byte[] EncodeBitstring(bool[] input)
        {
            byte[] returnbytes = new byte[1 + (int)Math.Ceiling((float)input.Length / 8)];
            byte tempbyte = (byte)(8 - (input.Length % 8));
            int curbyte = 0;
            for (int i = 0; i < input.Length; i++)
            {
                if (i % 8 == 0)
                {
                    returnbytes[curbyte++] = tempbyte;
                    tempbyte = 0x00;
                }

                tempbyte = (byte)(tempbyte | (input[i] ? 0x01 : 0x00));
                if (i % 8 != 7)
                {
                    tempbyte = (byte)(tempbyte << 1);
                }
            }

            returnbytes[returnbytes.Length - 1] = (byte)(tempbyte << (returnbytes[0] != 0 ? returnbytes[0] - 1 : 0));
            return EncodeAll(0x03, returnbytes);
        }

        internal static byte[] EncodeOctetstring(byte[] input, int tag = 0x04, ASN1.IdentClass identclass = ASN1.IdentClass.Universal, ASN1.IdentType identtype = ASN1.IdentType.Primitive)
        {
            return EncodeAll(tag, input, identclass, identtype);
        }

        internal static byte[] EncodeNull()
        {
            return nullEncoded;
        }

        internal static byte[] EncodeSequence(byte[] input, int tag = 0x10, ASN1.IdentClass identclass = ASN1.IdentClass.Universal)
        {
            return EncodeAll(tag, input, identclass, ASN1.IdentType.Constructed);
        }

        internal static byte[] EncodeOID(uint[] identifiers)
        {
            uint[] freeidentifiers = new uint[identifiers.Length];
            identifiers.CopyTo(freeidentifiers, 0);
            byte[][] bytearrays = new byte[freeidentifiers.Length - 1][];
            int flatlength = 0;
            for (int i = 1; i < freeidentifiers.Length; i++)
            {
                if (i == 1)
                {
                    freeidentifiers[1] = (freeidentifiers[0] * 40) + freeidentifiers[1];
                }

                bytearrays[i - 1] = Encode7BitInteger(freeidentifiers[i], 0x7F);
                flatlength += bytearrays[i - 1].Length;
            }

            byte[] byteidentifiers = new byte[flatlength];
            for (int i = 0; i < bytearrays.Length; i++)
            {
                bytearrays[i].CopyTo(byteidentifiers, byteidentifiers.Length - flatlength);
                flatlength -= bytearrays[i].Length;
            }

            return EncodeAll(0x06, byteidentifiers);
        }

        internal static byte[] EncodeUTF8String(string input)
        {
            return EncodeAll(0x0C, System.Text.UTF8Encoding.UTF8.GetBytes(input));
        }

        internal static byte[] EncodeNumericString(string input)
        {
            Contract.Requires(System.Text.RegularExpressions.Regex.IsMatch(input, @"[0-9 ]*"));
            return EncodeAll(0x12, System.Text.ASCIIEncoding.ASCII.GetBytes(input));
        }

        internal static byte[] EncodeIA5String(string input)
        {
            Contract.Requires(System.Text.RegularExpressions.Regex.IsMatch(input, @"[\x00-\xFF]*"));
            return EncodeAll(0x16, System.Text.ASCIIEncoding.ASCII.GetBytes(input));
        }

        private static byte[] EncodeIdentifier(int tag, ASN1.IdentClass identclass = ASN1.IdentClass.Universal, ASN1.IdentType identtype = ASN1.IdentType.Primitive)
        {
            Contract.Requires(tag >= 0);
            if (tag <= 30)
            {
                return new byte[] { (byte)((byte)tag | (byte)identclass | (byte)identtype) };
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        private static byte[] EncodeLength(int length)
        {
            Contract.Requires(length >= 0);
            if (length < 127)
            {
                return new byte[1] { (byte)(((byte)length) & ((byte)127)) };
            }
            else if (length <= 0xFF)
            {
                return new byte[2] { 129, (byte)length };
            }
            else if (length <= 0xFFFF)
            {
                byte[] bytes = new byte[3] { 130, 0, 0 };
                BitConverterBigEndian.GetBytes((ushort)length).CopyTo(bytes, 1);
                return bytes;
            }
            else if (length <= 0xFFFFFF)
            {
                byte[] bytes = new byte[4] { 131, 0, 0, 0 };
                Array.Copy(BitConverterBigEndian.GetBytes((uint)length), 1, bytes, 1, 3);
                return bytes;
            }
            else
            {
                byte[] bytes = new byte[5] { 132, 0, 0, 0, 0 };
                BitConverterBigEndian.GetBytes((uint)length).CopyTo(bytes, 1);
                return bytes;
            }
        }

        private static byte[] EncodeAll(int tag, byte[] content, ASN1.IdentClass identclass = ASN1.IdentClass.Universal, ASN1.IdentType identtype = ASN1.IdentType.Primitive)
        {
            byte[] ident = EncodeIdentifier(tag, identclass, identtype);
            byte[] length = EncodeLength(content.Length);
            byte[] returnbytes = new byte[ident.Length + length.Length + content.Length];
            ident.CopyTo(returnbytes, 0);
            length.CopyTo(returnbytes, ident.Length);
            content.CopyTo(returnbytes, ident.Length + length.Length);
            return returnbytes;
        }

        private static byte[] Encode7BitInteger(uint input, byte markend = 0x80)
        {
            Contract.Requires(markend == 0x80 || markend == 0x7F);
            byte[] bytes = BitConverterBigEndian.GetBytes(input);
            byte intstart = 0;
            while (intstart < 4 && bytes[intstart] == 0x00)
            {
                intstart++;
            }

            byte[] bytes2 = new byte[5 - intstart];
            Array.Copy(bytes, intstart, bytes2, 1, 4 - intstart);

            for (int i = 0; i < bytes2.Length; i++)
            {
                bytes2[i] = (byte)(bytes2[i] << (bytes2.Length - 1 - i));
                if (i != bytes2.Length - 1)
                {
                    byte bits = ExtractBits(bytes2[i + 1], (bytes2.Length - 1 - i));
                    bytes2[i] = (byte)(bytes2[i] | bits);
                    bytes2[i] = MarkByte(bytes2[i], false, markend);
                }
                else
                {
                    bytes2[i] = MarkByte(bytes2[i], true, markend);
                }
            }

            if ((bytes2[0] & 0x0F) != 0x00)
            {
                return bytes2;
            }
            else
            {
                byte[] returnbytes = new byte[bytes2.Length - 1];
                Array.Copy(bytes2, 1, returnbytes, 0, bytes2.Length - 1);
                return returnbytes;
            }
        }

        private static byte ExtractBits(byte input, int num)
        {
            Contract.Requires(num <= 8);
            byte bitmask = 0x00;
            byte count = (byte)num;
            for (byte i = 0x80; count > 0; i = (byte)(i >> 1))
            {
                bitmask |= i;
                count--;
            }

            return (byte)((input & bitmask) >> (8 - num));
        }

        private static byte MarkByte(byte input, bool end, byte markend = 0x80)
        {
            Contract.Requires(markend == 0x80 || markend == 0x7F);
            if (end)
            {
                if (markend == 0x80)
                {
                    return (byte)(input | markend);
                }
                else
                {
                    return (byte)(input & markend);
                }
            }
            else
            {
                if (markend == 0x80)
                {
                    return (byte)(input & ~markend);
                }
                else
                {
                    return (byte)(input | ~markend);
                }
            }
        }
    }
}

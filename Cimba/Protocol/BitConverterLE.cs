﻿namespace Cimba.Protocol
{
    using System;
    using System.Diagnostics.Contracts;
    using System.IO;

    internal static class BitConverterLE
    {
        private static readonly byte[] shortbuffer = new byte[2];
        private static readonly byte[] intbuffer = new byte[4];
        private static readonly byte[] longbuffer = new byte[8];

        internal static byte[] GetBytes(ushort s)
        {
            return ToLittleEndian(BitConverter.GetBytes(s));
        }

        internal static byte[] GetBytes(uint i)
        {
            return ToLittleEndian(BitConverter.GetBytes(i));
        }

        internal static byte[] GetBytes(ulong l)
        {
            return ToLittleEndian(BitConverter.GetBytes(l));
        }

        internal static byte[] GetBytes(short s)
        {
            return ToLittleEndian(BitConverter.GetBytes(s));
        }

        internal static byte[] GetBytes(int i)
        {
            return ToLittleEndian(BitConverter.GetBytes(i));
        }

        internal static byte[] GetBytes(long l)
        {
            return ToLittleEndian(BitConverter.GetBytes(l));
        }

        internal static ushort ToUShort(byte[] bytes, bool fromBE = false)
        {
            Contract.Requires(bytes.Length == 2);
            return BitConverter.ToUInt16(fromBE ? FromBigEndian(bytes) : FromLittleEndian(bytes), 0);
        }

        internal static ushort ToUShort(byte[] bytes, int offset, bool fromBE = false)
        {
            Array.Copy(bytes, offset, shortbuffer, 0, 2);
            return ToUShort(shortbuffer, fromBE);
        }

        internal static ushort ToUShort(Stream stream, bool fromBE = false)
        {
            Contract.Requires(stream.CanRead);
            stream.Read(shortbuffer, 0, 2);
            return ToUShort(shortbuffer, fromBE);
        }

        internal static short ToShort(byte[] bytes, bool fromBE = false)
        {
            Contract.Requires(bytes.Length == 2);
            return BitConverter.ToInt16(fromBE ? FromBigEndian(bytes) : FromLittleEndian(bytes), 0);
        }

        internal static short ToShort(byte[] bytes, int offset, bool fromBE = false)
        {
            Array.Copy(bytes, offset, shortbuffer, 0, 2);
            return ToShort(shortbuffer, fromBE);
        }

        internal static short ToShort(Stream stream, bool fromBE = false)
        {
            Contract.Requires(stream.CanRead);
            stream.Read(shortbuffer, 0, 2);
            return ToShort(shortbuffer, fromBE);
        }

        internal static uint ToUInt(byte[] bytes, bool fromBE = false)
        {
            Contract.Requires(bytes.Length == 4);
            return BitConverter.ToUInt32(fromBE ? FromBigEndian(bytes) : FromLittleEndian(bytes), 0);
        }

        internal static uint ToUInt(byte[] bytes, int offset, bool fromBE = false)
        {
            Array.Copy(bytes, offset, intbuffer, 0, 4);
            return ToUInt(intbuffer, fromBE);
        }

        internal static uint ToUInt(Stream stream, bool fromBE = false)
        {
            Contract.Requires(stream.CanRead);
            stream.Read(intbuffer, 0, 4);
            return ToUInt(intbuffer, fromBE);
        }

        internal static int ToInt(byte[] bytes, bool fromBE = false)
        {
            Contract.Requires(bytes.Length == 4);
            return BitConverter.ToInt32(fromBE ? FromBigEndian(bytes) : FromLittleEndian(bytes), 0);
        }

        internal static int ToInt(byte[] bytes, int offset, bool fromBE = false)
        {
            Array.Copy(bytes, offset, intbuffer, 0, 4);
            return ToInt(intbuffer, fromBE);
        }

        internal static int ToInt(Stream stream, bool fromBE = false)
        {
            Contract.Requires(stream.CanRead);
            stream.Read(intbuffer, 0, 4);
            return ToInt(intbuffer, fromBE);
        }

        internal static ulong ToULong(byte[] bytes, bool fromBE = false)
        {
            Contract.Requires(bytes.Length == 8);
            return BitConverter.ToUInt64(fromBE ? FromBigEndian(bytes) : FromLittleEndian(bytes), 0);
        }

        internal static ulong ToULong(byte[] bytes, int offset, bool fromBE = false)
        {
            Array.Copy(bytes, offset, longbuffer, 0, 8);
            return ToULong(longbuffer, fromBE);
        }

        internal static ulong ToULong(Stream stream, bool fromBE = false)
        {
            Contract.Requires(stream.CanRead);
            stream.Read(longbuffer, 0, 8);
            return ToULong(longbuffer, fromBE);
        }

        internal static long ToLong(byte[] bytes, bool fromBE = false)
        {
            Contract.Requires(bytes.Length == 8);
            return BitConverter.ToInt64(fromBE ? FromBigEndian(bytes) : FromLittleEndian(bytes), 0);
        }

        internal static long ToLong(byte[] bytes, int offset, bool fromBE = false)
        {
            Array.Copy(bytes, offset, longbuffer, 0, 8);
            return ToLong(longbuffer, fromBE);
        }

        internal static long ToLong(Stream stream, bool fromBE = false)
        {
            Contract.Requires(stream.CanRead);
            stream.Read(intbuffer, 0, 8);
            return ToLong(longbuffer, fromBE);
        }

        private static byte[] ToLittleEndian(byte[] input)
        {
            if (!BitConverter.IsLittleEndian)
            {
                return ReverseBytes(input);
            }
            else
            {
                return input;
            }
        }

        private static byte[] ReverseBytes(byte[] input)
        {
            byte temp;
            for (int i = 0; i < input.Length / 2; i++)
            {
                temp = input[i];
                input[i] = input[input.Length - 1 - i];
                input[input.Length - 1 - i] = temp;
            }

            return input;
        }

        private static byte[] FromLittleEndian(byte[] input)
        {
            if (BitConverter.IsLittleEndian)
            {
                return input;
            }
            else
            {
                return ReverseBytes(input);
            }
        }

        private static byte[] FromBigEndian(byte[] input)
        {
            if (!BitConverter.IsLittleEndian)
            {
                return input;
            }
            else
            {
                return ReverseBytes(input);
            }
        }
    }
}
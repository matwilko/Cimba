namespace Cimba.Protocol
{
    using System;
    using System.Diagnostics.Contracts;
    using System.IO;

    internal static class BitConverterLittleEndian
    {
        private static readonly byte[] ShortBuffer = new byte[2];
        private static readonly byte[] IntBuffer = new byte[4];
        private static readonly byte[] LongBuffer = new byte[8];

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

        internal static ushort ToUShort(byte[] bytes, bool fromBigEndian = false)
        {
            Contract.Requires(bytes.Length == 2);
            return BitConverter.ToUInt16(fromBigEndian ? FromBigEndian(bytes) : FromLittleEndian(bytes), 0);
        }

        internal static ushort ToUShort(byte[] bytes, int offset, bool fromBigEndian = false)
        {
            Array.Copy(bytes, offset, ShortBuffer, 0, 2);
            return ToUShort(ShortBuffer, fromBigEndian);
        }

        internal static ushort ToUShort(Stream stream, bool fromBigEndian = false)
        {
            Contract.Requires(stream.CanRead);
            stream.Read(ShortBuffer, 0, 2);
            return ToUShort(ShortBuffer, fromBigEndian);
        }

        internal static short ToShort(byte[] bytes, bool fromBigEndian = false)
        {
            Contract.Requires(bytes.Length == 2);
            return BitConverter.ToInt16(fromBigEndian ? FromBigEndian(bytes) : FromLittleEndian(bytes), 0);
        }

        internal static short ToShort(byte[] bytes, int offset, bool fromBigEndian = false)
        {
            Array.Copy(bytes, offset, ShortBuffer, 0, 2);
            return ToShort(ShortBuffer, fromBigEndian);
        }

        internal static short ToShort(Stream stream, bool fromBigEndian = false)
        {
            Contract.Requires(stream.CanRead);
            stream.Read(ShortBuffer, 0, 2);
            return ToShort(ShortBuffer, fromBigEndian);
        }

        internal static uint ToUInt(byte[] bytes, bool fromBigEndian = false)
        {
            Contract.Requires(bytes.Length == 4);
            return BitConverter.ToUInt32(fromBigEndian ? FromBigEndian(bytes) : FromLittleEndian(bytes), 0);
        }

        internal static uint ToUInt(byte[] bytes, int offset, bool fromBigEndian = false)
        {
            Array.Copy(bytes, offset, IntBuffer, 0, 4);
            return ToUInt(IntBuffer, fromBigEndian);
        }

        internal static uint ToUInt(Stream stream, bool fromBigEndian = false)
        {
            Contract.Requires(stream.CanRead);
            stream.Read(IntBuffer, 0, 4);
            return ToUInt(IntBuffer, fromBigEndian);
        }

        internal static int ToInt(byte[] bytes, bool fromBigEndian = false)
        {
            Contract.Requires(bytes.Length == 4);
            return BitConverter.ToInt32(fromBigEndian ? FromBigEndian(bytes) : FromLittleEndian(bytes), 0);
        }

        internal static int ToInt(byte[] bytes, int offset, bool fromBigEndian = false)
        {
            Array.Copy(bytes, offset, IntBuffer, 0, 4);
            return ToInt(IntBuffer, fromBigEndian);
        }

        internal static int ToInt(Stream stream, bool fromBigEndian = false)
        {
            Contract.Requires(stream.CanRead);
            stream.Read(IntBuffer, 0, 4);
            return ToInt(IntBuffer, fromBigEndian);
        }

        internal static ulong ToULong(byte[] bytes, bool fromBigEndian = false)
        {
            Contract.Requires(bytes.Length == 8);
            return BitConverter.ToUInt64(fromBigEndian ? FromBigEndian(bytes) : FromLittleEndian(bytes), 0);
        }

        internal static ulong ToULong(byte[] bytes, int offset, bool fromBigEndian = false)
        {
            Array.Copy(bytes, offset, LongBuffer, 0, 8);
            return ToULong(LongBuffer, fromBigEndian);
        }

        internal static ulong ToULong(Stream stream, bool fromBigEndian = false)
        {
            Contract.Requires(stream.CanRead);
            stream.Read(LongBuffer, 0, 8);
            return ToULong(LongBuffer, fromBigEndian);
        }

        internal static long ToLong(byte[] bytes, bool fromBigEndian = false)
        {
            Contract.Requires(bytes.Length == 8);
            return BitConverter.ToInt64(fromBigEndian ? FromBigEndian(bytes) : FromLittleEndian(bytes), 0);
        }

        internal static long ToLong(byte[] bytes, int offset, bool fromBigEndian = false)
        {
            Array.Copy(bytes, offset, LongBuffer, 0, 8);
            return ToLong(LongBuffer, fromBigEndian);
        }

        internal static long ToLong(Stream stream, bool fromBigEndian = false)
        {
            Contract.Requires(stream.CanRead);
            stream.Read(IntBuffer, 0, 8);
            return ToLong(LongBuffer, fromBigEndian);
        }

        private static byte[] ToLittleEndian(byte[] input)
        {
            return !BitConverter.IsLittleEndian ? ReverseBytes(input) : input;
        }

        private static byte[] ReverseBytes(byte[] input)
        {
            for (var i = 0; i < input.Length / 2; i++)
            {
                byte temp = input[i];
                input[i] = input[input.Length - 1 - i];
                input[input.Length - 1 - i] = temp;
            }

            return input;
        }

        private static byte[] FromLittleEndian(byte[] input)
        {
            return BitConverter.IsLittleEndian ? input : ReverseBytes(input);
        }

        private static byte[] FromBigEndian(byte[] input)
        {
            return !BitConverter.IsLittleEndian ? input : ReverseBytes(input);
        }
    }
}

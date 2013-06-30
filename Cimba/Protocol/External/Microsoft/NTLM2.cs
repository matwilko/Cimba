namespace Cimba.Protocol.External.Microsoft
{
    using System;
    using System.Security.Cryptography;
    using System.Text;
    using Cimba.Client;
    using Cimba.Server;
    using Org.BouncyCastle.Crypto.Engines;
    using Org.BouncyCastle.Crypto.Parameters;

    internal class NTLM2
    {
        private static readonly ulong ntlmssp = 0x005053534d4c544e;

        [Flags]
        internal enum NEGOTIATE : uint
        {
            KEY_56 = 0x80000000,
            KEY_EXCH = 0x40000000,
            KEY_128 = 0x20000000,
            VERSION = 0x02000000,
            TARGET_INFO = 0x00800000,
            REQUEST_NON_NT_SESSION_KEY = 0x00400000,
            IDENTIFY = 0x00100000,
            EXTENDED_SESSIONSECURITY = 0x00080000,
            TARGET_TYPE_SERVER = 0x00020000,
            TARGET_TYPE_DOMAIN = 0x00010000,
            NEGOTIATE_ALWAYS_SIGN = 0x00008000,
            OEM_WORKSTATION_SUPPLIED = 0x00002000,
            OEM_DOMAIN_SUPPLIED = 0x00001000,
            ANONYMOUS = 0x00000800,
            NTLM = 0x00000200,
            LM_KEY = 0x00000080,
            DATAGRAM = 0x00000040,
            SEAL = 0x00000020,
            SIGN = 0x00000010,
            REQUEST_TARGET = 0x00000004,
            OEM = 0x00000002,
            UNICODE = 0x00000001
        }

        internal static byte[] NEGOTIATE_MESSAGE()
        {
            uint flags = (uint)(NEGOTIATE.KEY_128
                                | NEGOTIATE.KEY_EXCH
                                | NEGOTIATE.UNICODE
                                | NEGOTIATE.REQUEST_TARGET
                                | NEGOTIATE.NTLM
                                | NEGOTIATE.NEGOTIATE_ALWAYS_SIGN
                                | NEGOTIATE.EXTENDED_SESSIONSECURITY
                                | NEGOTIATE.SIGN
                                | NEGOTIATE.VERSION
                                | NEGOTIATE.LM_KEY);
            ulong version = 0x0601B1D10000000f;

            byte[] message = new byte[40];
            BitConverterLE.GetBytes(ntlmssp).CopyTo(message, 0);
            BitConverterLE.GetBytes((uint)1).CopyTo(message, 8);
            BitConverterLE.GetBytes(flags).CopyTo(message, 12);
            BitConverterLE.GetBytes(version).CopyTo(message, 32);

            return message;
        }

        internal static bool NEGOTIATE_MESSAGE(byte[] buffer)
        {
            uint flags = (uint)(NEGOTIATE.KEY_128
                                | NEGOTIATE.KEY_EXCH
                                | NEGOTIATE.UNICODE
                                | NEGOTIATE.REQUEST_TARGET
                                | NEGOTIATE.NTLM
                                | NEGOTIATE.NEGOTIATE_ALWAYS_SIGN
                                | NEGOTIATE.EXTENDED_SESSIONSECURITY
                                | NEGOTIATE.SIGN
                                | NEGOTIATE.VERSION);
            return BitConverterLE.ToULong(buffer, 0) == ntlmssp
                    && BitConverterLE.ToULong(buffer, 8) == 1
                    && (BitConverterLE.ToUInt(buffer, 12) & flags) == flags;
        }

        internal static Tuple<bool, ulong, byte[]> CHALLENGE_MESSAGE(byte[] buffer)
        {
            if (BitConverterLE.ToULong(buffer, 0) == ntlmssp
                && BitConverterLE.ToUInt(buffer, 8) == 2
                && (BitConverterLE.ToUInt(buffer, 20) & (uint)NEGOTIATE.TARGET_INFO) == (uint)NEGOTIATE.TARGET_INFO)
            {
                ushort targetInfoLen = BitConverterLE.ToUShort(buffer, 40);
                uint targetInfoOffset = BitConverterLE.ToUInt(buffer, 44);
                byte[] targetInfo = new byte[targetInfoLen];
                Array.Copy(buffer, targetInfoOffset, targetInfo, 0, targetInfoLen);
                return new Tuple<bool, ulong, byte[]>(true, BitConverterLE.ToULong(buffer, 24), targetInfo);
            }
            else
            {
                return new Tuple<bool, ulong, byte[]>(false, 0, null);
            }
        }

        internal static byte[] CHALLENGE_MESSAGE(ulong serverChallenge, string serverName)
        {
            uint flags = (uint)(NEGOTIATE.KEY_128
                                | NEGOTIATE.KEY_EXCH
                                | NEGOTIATE.VERSION
                                | NEGOTIATE.UNICODE
                                | NEGOTIATE.TARGET_INFO
                                | NEGOTIATE.TARGET_TYPE_SERVER
                                | NEGOTIATE.NTLM
                                | NEGOTIATE.NEGOTIATE_ALWAYS_SIGN
                                | NEGOTIATE.EXTENDED_SESSIONSECURITY
                                | NEGOTIATE.SIGN);
            ulong version = 0x0601B1D10000000f;
            byte[] targetName = Encoding.Unicode.GetBytes(serverName);
            byte[] targetInfo = NTLM2.TargetInfo(serverName);

            byte[] message = new byte[56 + targetName.Length + targetInfo.Length];
            BitConverterLE.GetBytes(ntlmssp).CopyTo(message, 0);
            BitConverterLE.GetBytes((uint)2).CopyTo(message, 8);
            BitConverterLE.GetBytes((ushort)targetName.Length).CopyTo(message, 12);
            BitConverterLE.GetBytes((ushort)targetName.Length).CopyTo(message, 14);
            BitConverterLE.GetBytes((uint)56).CopyTo(message, 16);
            BitConverterLE.GetBytes(flags).CopyTo(message, 20);
            BitConverterLE.GetBytes(serverChallenge).CopyTo(message, 24);
            BitConverterLE.GetBytes((ushort)targetInfo.Length).CopyTo(message, 40);
            BitConverterLE.GetBytes((ushort)targetInfo.Length).CopyTo(message, 42);
            BitConverterLE.GetBytes((uint)(56 + targetName.Length)).CopyTo(message, 44);
            BitConverterLE.GetBytes(version).CopyTo(message, 48);
            targetName.CopyTo(message, 56);
            targetInfo.CopyTo(message, 56 + targetName.Length);

            return message;
        }

        internal static byte[] AUTHENTICATE_MESSAGE(ulong serverChallenge, byte[] targetInfo, byte[] sessionKey, SmbClientCredentials creds, byte[] challengebytes)
        {
            Console.WriteLine("CLIENT KEY: " + BitConverter.ToString(sessionKey));
            ulong version = 0x0601B1D10000000f;
            byte[] targetName = Encoding.Unicode.GetBytes(creds.Domain);
            byte[] userName = Encoding.Unicode.GetBytes(creds.Username);
            byte[] workstationName = Encoding.Unicode.GetBytes(Environment.MachineName);

            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] clientNonce = new byte[8];
            rng.GetBytes(clientNonce);

            byte[] ntlmResponse = NTLMv2_Response(creds, creds.Domain, targetInfo, clientNonce, serverChallenge);
            byte[] lanmanResponse = new byte[24];
            byte[] encryptedSessionKey = NTLMv2_EncryptSessionKey(sessionKey, creds, ntlmResponse);

            byte[] message = new byte[88 + lanmanResponse.Length + ntlmResponse.Length + targetName.Length + userName.Length + workstationName.Length + encryptedSessionKey.Length];
            BitConverterLE.GetBytes(ntlmssp).CopyTo(message, 0);
            BitConverterLE.GetBytes((uint)3).CopyTo(message, 8);
            BitConverterLE.GetBytes((ushort)lanmanResponse.Length).CopyTo(message, 12);
            BitConverterLE.GetBytes((ushort)lanmanResponse.Length).CopyTo(message, 14);
            BitConverterLE.GetBytes((ushort)88).CopyTo(message, 16);
            BitConverterLE.GetBytes((ushort)ntlmResponse.Length).CopyTo(message, 20);
            BitConverterLE.GetBytes((ushort)ntlmResponse.Length).CopyTo(message, 22);
            BitConverterLE.GetBytes((ushort)(88 + lanmanResponse.Length)).CopyTo(message, 24);
            BitConverterLE.GetBytes((ushort)targetName.Length).CopyTo(message, 28);
            BitConverterLE.GetBytes((ushort)targetName.Length).CopyTo(message, 30);
            BitConverterLE.GetBytes((ushort)(88 + lanmanResponse.Length + ntlmResponse.Length)).CopyTo(message, 32);
            BitConverterLE.GetBytes((ushort)userName.Length).CopyTo(message, 36);
            BitConverterLE.GetBytes((ushort)userName.Length).CopyTo(message, 38);
            BitConverterLE.GetBytes((ushort)(88 + lanmanResponse.Length + ntlmResponse.Length + targetName.Length)).CopyTo(message, 40);
            BitConverterLE.GetBytes((ushort)workstationName.Length).CopyTo(message, 44);
            BitConverterLE.GetBytes((ushort)workstationName.Length).CopyTo(message, 46);
            BitConverterLE.GetBytes((ushort)(88 + lanmanResponse.Length + ntlmResponse.Length + targetName.Length + userName.Length)).CopyTo(message, 48);
            BitConverterLE.GetBytes((ushort)encryptedSessionKey.Length).CopyTo(message, 52);
            BitConverterLE.GetBytes((ushort)encryptedSessionKey.Length).CopyTo(message, 54);
            BitConverterLE.GetBytes((ushort)(88 + lanmanResponse.Length + ntlmResponse.Length + targetName.Length + userName.Length + workstationName.Length)).CopyTo(message, 56);
            BitConverterLE.GetBytes(version).CopyTo(message, 64);
            lanmanResponse.CopyTo(message, 88);
            ntlmResponse.CopyTo(message, 88 + lanmanResponse.Length);
            targetName.CopyTo(message, 88 + lanmanResponse.Length + ntlmResponse.Length);
            userName.CopyTo(message, 88 + lanmanResponse.Length + ntlmResponse.Length + targetName.Length);
            workstationName.CopyTo(message, 88 + lanmanResponse.Length + ntlmResponse.Length + targetName.Length + userName.Length);
            encryptedSessionKey.CopyTo(message, 88 + lanmanResponse.Length + ntlmResponse.Length + targetName.Length + userName.Length + workstationName.Length);

            MIC(sessionKey, NEGOTIATE_MESSAGE(), challengebytes, message).CopyTo(message, 72);

            return message;
        }

        internal static Tuple<bool, byte[]> AUTHENTICATE_MESSAGE(byte[] buffer, ulong serverChallenge, string serverName, AuthenticateClientDelegate auth)
        {
            ushort targetnameLength = BitConverterLE.ToUShort(buffer, 28);
            uint targetnameOffset = BitConverterLE.ToUInt(buffer, 32);
            byte[] targetName = new byte[targetnameLength];
            Array.Copy(buffer, targetnameOffset, targetName, 0, targetnameLength);
            ushort usernameLength = BitConverterLE.ToUShort(buffer, 36);
            uint usernameOffset = BitConverterLE.ToUInt(buffer, 40);
            byte[] userName = new byte[usernameLength];
            Array.Copy(buffer, usernameOffset, userName, 0, usernameLength);

            SmbClientCredentials creds = auth(Encoding.Unicode.GetString(targetName), Encoding.Unicode.GetString(userName));

            ushort ntlmResponseLength = BitConverterLE.ToUShort(buffer, 20);
            uint ntlmResponseOffset = BitConverterLE.ToUInt(buffer, 24);
            byte[] ntlmResponse = new byte[ntlmResponseLength];
            Array.Copy(buffer, ntlmResponseOffset, ntlmResponse, 0, ntlmResponseLength);

            byte[] clientNonce = new byte[8];
            Array.Copy(ntlmResponse, 32, clientNonce, 0, 8);

            byte[] proofStr = new byte[16];
            Array.Copy(ntlmResponse, 0, proofStr, 0, 16);

            ushort eskLength = BitConverterLE.ToUShort(buffer, 52);
            uint eskOffset = BitConverterLE.ToUInt(buffer, 56);
            byte[] encryptedSessionKey = new byte[eskLength];
            Array.Copy(buffer, eskOffset, encryptedSessionKey, 0, eskLength);

            if (Verify_NTLM2_Response(ntlmResponse, creds, serverChallenge))
            {
                byte[] sessionKey = NTLMv2_DecryptSessionKey(proofStr, encryptedSessionKey, creds);
                return new Tuple<bool, byte[]>(true, sessionKey);
            }
            else
            {
                return new Tuple<bool, byte[]>(false, null);
            }
        }

        internal static byte[] SigningKey(byte[] sessionKey, bool client)
        {
            if (client)
            {
                byte[] magic = Encoding.ASCII.GetBytes("session key to client-to-server signing key magic constant\0");
                byte[] concat = new byte[sessionKey.Length + magic.Length];
                sessionKey.CopyTo(concat, 0);
                magic.CopyTo(concat, sessionKey.Length);
                return MD5(concat);
            }
            else
            {
                byte[] magic = Encoding.ASCII.GetBytes("session key to server-to-client signing key magic constant\0");
                byte[] concat = new byte[sessionKey.Length + magic.Length];
                sessionKey.CopyTo(concat, 0);
                magic.CopyTo(concat, sessionKey.Length);
                return MD5(concat);
            }
        }

        internal static byte[] SealingKey(byte[] sessionKey, bool client)
        {
            if (client)
            {
                byte[] magic = Encoding.ASCII.GetBytes("session key to client-to-server sealing key magic constant\0");
                byte[] concat = new byte[sessionKey.Length + magic.Length];
                sessionKey.CopyTo(concat, 0);
                magic.CopyTo(concat, sessionKey.Length);
                return MD5(concat);
            }
            else
            {
                byte[] magic = Encoding.ASCII.GetBytes("session key to server-to-client sealing key magic constant\0");
                byte[] concat = new byte[sessionKey.Length + magic.Length];
                sessionKey.CopyTo(concat, 0);
                magic.CopyTo(concat, sessionKey.Length);
                return MD5(concat);
            }
        }

        private static byte[] TargetInfo(string serverName)
        {
            byte[] name = Encoding.Unicode.GetBytes(serverName);
            byte[] buffer = new byte[((4 + name.Length) * 4) + 16];

            byte[] identical_parts = new byte[4 + name.Length];
            BitConverterLE.GetBytes((ushort)name.Length).CopyTo(identical_parts, 2);
            name.CopyTo(identical_parts, 4);

            // NetBIOS domain name
            identical_parts[0] = 0x02;
            identical_parts[1] = 0x00;
            identical_parts.CopyTo(buffer, 0);

            // NetBIOS computer name
            identical_parts[0] = 0x01;
            identical_parts[1] = 0x00;
            identical_parts.CopyTo(buffer, identical_parts.Length);

            // DNS domain name
            identical_parts[0] = 0x04;
            identical_parts[1] = 0x00;
            identical_parts.CopyTo(buffer, identical_parts.Length * 2);

            // DNS computer name
            identical_parts[0] = 0x03;
            identical_parts[1] = 0x00;
            identical_parts.CopyTo(buffer, identical_parts.Length * 3);

            int offset = identical_parts.Length * 4;

            // Timestamp
            buffer[offset++] = 0x07;
            buffer[offset++] = 0x00;
            buffer[offset++] = 0x08;
            buffer[offset++] = 0x00;
            BitConverterLE.GetBytes(DateTime.Now.ToFileTime()).CopyTo(buffer, offset);
            offset += 8;

            // End of List
            // Array is already zeroed at the end...
            return buffer;
        }

        private static byte[] NTLMv2_Response(SmbClientCredentials creds, string targetName, byte[] targetInfo, byte[] clientNonce, ulong serverChallenge)
        {
            byte[] ntlmHash = MD4(creds.Password);
            byte[] ntlm2Hash = HMAC_MD5(ntlmHash, creds.Username.ToUpper() + creds.Domain);

            byte[] blob = new byte[32 + targetInfo.Length];
            BitConverterLE.GetBytes((uint)0x00000101).CopyTo(blob, 0);
            BitConverterLE.GetBytes(DateTime.Now.ToFileTime()).CopyTo(blob, 8);
            clientNonce.CopyTo(blob, 16);
            targetInfo.CopyTo(blob, 28);

            byte[] hmac_blob = new byte[8 + blob.Length];
            BitConverterLE.GetBytes(serverChallenge).CopyTo(hmac_blob, 0);
            blob.CopyTo(hmac_blob, 8);
            byte[] hmac_blob_done = HMAC_MD5(ntlm2Hash, hmac_blob);

            byte[] finalResponse = new byte[hmac_blob_done.Length + blob.Length];
            hmac_blob_done.CopyTo(finalResponse, 0);
            blob.CopyTo(finalResponse, hmac_blob_done.Length);
            return finalResponse;
        }

        private static bool Verify_NTLM2_Response(byte[] response, SmbClientCredentials creds, ulong serverChallenge)
        {
            byte[] ntlmHash = MD4(creds.Password);
            byte[] ntlm2Hash = HMAC_MD5(ntlmHash, creds.Username.ToUpper() + creds.Domain);

            byte[] blob = new byte[response.Length - 16];
            Array.Copy(response, 16, blob, 0, blob.Length);

            byte[] hmac_blob = new byte[8 + blob.Length];
            BitConverterLE.GetBytes(serverChallenge).CopyTo(hmac_blob, 0);
            blob.CopyTo(hmac_blob, 8);
            byte[] hmac_blob_done = HMAC_MD5(ntlm2Hash, hmac_blob);

            bool correct = true;
            for (int i = 0; i < 16; i++)
            {
                if (response[i] != hmac_blob_done[i])
                {
                    correct = false;
                    break;
                }
            }

            return correct;
        }

        private static byte[] NTLMv2_EncryptSessionKey(byte[] sessionKey, SmbClientCredentials creds, byte[] ntlmv2Response)
        {
            byte[] ntlmHash = MD4(creds.Password);
            byte[] ntlm2Hash = HMAC_MD5(ntlmHash, creds.Username.ToUpper() + creds.Domain);

            byte[] proofStr = new byte[16];
            Array.Copy(ntlmv2Response, 0, proofStr, 0, 16);

            byte[] sessionBaseKey = HMAC_MD5(ntlm2Hash, proofStr);

            RC4Engine rc4 = new RC4Engine();
            rc4.Init(true, new KeyParameter(sessionBaseKey));
            byte[] encryptedSessionKey = new byte[16];
            rc4.ProcessBytes(sessionKey, 0, 16, encryptedSessionKey, 0);

            return encryptedSessionKey;
        }

        private static byte[] NTLMv2_DecryptSessionKey(byte[] proofStr, byte[] encryptedSessionKey, SmbClientCredentials creds)
        {
            byte[] ntlmHash = MD4(creds.Password);
            byte[] ntlm2Hash = HMAC_MD5(ntlmHash, creds.Username.ToUpper() + creds.Domain);

            byte[] sessionBaseKey = HMAC_MD5(ntlm2Hash, proofStr);

            RC4Engine rc4 = new RC4Engine();
            rc4.Init(false, new KeyParameter(sessionBaseKey));
            byte[] sessionKey = new byte[16];
            rc4.ProcessBytes(encryptedSessionKey, 0, 16, sessionKey, 0);

            return sessionKey;
        }

        private static byte[] MIC(byte[] sessionKey, byte[] negotiate, byte[] challenge, byte[] authenticate)
        {
            byte[] buffer = new byte[negotiate.Length + challenge.Length + authenticate.Length];
            negotiate.CopyTo(buffer, 0);
            challenge.CopyTo(buffer, negotiate.Length);
            authenticate.CopyTo(buffer, negotiate.Length + challenge.Length);
            return HMAC_MD5(sessionKey, buffer);
        }

        private static byte[] MD4(string toHash)
        {
            Org.BouncyCastle.Crypto.Digests.MD4Digest md4 = new Org.BouncyCastle.Crypto.Digests.MD4Digest();
            byte[] data = Encoding.Unicode.GetBytes(toHash);
            md4.BlockUpdate(data, 0, data.Length);
            byte[] hash = new byte[md4.GetDigestSize()];
            md4.DoFinal(hash, 0);
            return hash;
        }

        private static byte[] MD5(byte[] data)
        {
            System.Security.Cryptography.MD5 hasher = System.Security.Cryptography.MD5.Create();
            return hasher.ComputeHash(data);
        }

        private static byte[] HMAC_MD5(byte[] key, string toHash)
        {
            return HMAC_MD5(key, Encoding.Unicode.GetBytes(toHash));
        }

        private static byte[] HMAC_MD5(byte[] key, byte[] data)
        {
            HMACMD5 hmac_md5 = new HMACMD5(key);
            return hmac_md5.ComputeHash(data);
        }
    }
}
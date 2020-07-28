using System;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KeeperSecurity.Sdk;

namespace SecurityKey
{
    public class AuthenticateRequest
    {
        public string Version { get; set; }
        public string AppId { get; set; }
        public string Challenge { get; set; }
        public string KeyHandle { get; set; }
    };

    public class AuthenticateResponse
    {
        public string ClientData { get; internal set; }
        public string Signature { get; internal set; }
        public string KeyHandle { get; internal set; }
    };

    [DataContract]
    class U2F_ClientData
    {
        [DataMember(Name = "typ")]
        public string Type { get; set; }

        [DataMember(Name = "challenge")]
        public string Challenge { get; set; }

        [DataMember(Name = "origin")]
        public string Origin { get; set; }
    }

    public class U2F : IDisposable
    {
        public enum CTAP1_INS : byte
        {
            Register = 1,
            Authenticate = 2,
            Version = 3,
        }


        private Stream _connection;
        public U2F(Stream connection)
        {
            _connection = connection;
        }

        public static async Task<string> GetVersion(Stream connection)
        {
            var rs = await Apdu.SendAdpu(connection, new ApduRequest
            {
                Cla = 0,
                Ins = (byte) CTAP1_INS.Version,
                maxResponseSize = 0xf0
            });
            if (rs.SW1 == 0x90 && rs.SW2 == 0x00)
            {
                return Encoding.ASCII.GetString(rs.data);
            }

            throw new ApduException(rs.SW1, rs.SW2);
        }

        public Task<AuthenticateResponse> Authenticate(AuthenticateRequest request, Action onTestUserPresenceRequired = null) {

            return Authenticate(request, onTestUserPresenceRequired, CancellationToken.None);
        }

        public async Task<AuthenticateResponse> Authenticate(AuthenticateRequest request, Action onTestUserPresenceRequired, CancellationToken token)
        {
            var appIdHash = SHA256.Create().ComputeHash(Encoding.ASCII.GetBytes(request.AppId));
            var u2fClientData = new U2F_ClientData
            {
                Type = U2F_Sign,
                Challenge = request.Challenge,
                Origin = request.AppId
            };
            var clientDataBytes = JsonUtils.DumpJson(u2fClientData);
            var clientDataHash = SHA256.Create().ComputeHash(clientDataBytes);

            bool userNotified = false;
            while (true)
            {
                if (token.IsCancellationRequested)
                {
                    break;
                }
                var response = await U2F_Authenticate(clientDataHash, appIdHash, request.KeyHandle.Base64UrlDecode(), false);
                if (response.SW1 == 0x90 && response.SW2 == 0x00)
                {
                    return new AuthenticateResponse
                    {
                        ClientData = clientDataBytes.Base64UrlEncode(),
                        Signature = response.data.Base64UrlEncode(),
                        KeyHandle = request.KeyHandle
                    };
                }

                if (response.SW1 == 0x69 && response.SW2 == 0x85)
                {
                    if (!userNotified)
                    {
                        userNotified = true;
                        onTestUserPresenceRequired?.Invoke();
                    }

                    try
                    {
                        await Task.Delay(200, token);
                    }
                    catch (TaskCanceledException)
                    {
                        break;
                    }
                }
                else
                {
                    throw new ApduException(response.SW1, response.SW2);
                }

            }
            throw new KeeperCanceled();
        }

        public async Task<bool> CheckOnly(AuthenticateRequest request)
        {
            var clientDataHash = SHA256.Create().ComputeHash(new byte[0]);
            var appIdHash = SHA256.Create().ComputeHash(Encoding.ASCII.GetBytes(request.AppId));
            var response = await U2F_Authenticate(clientDataHash, appIdHash, request.KeyHandle.Base64UrlDecode(), true);
            return response.SW1 == 0x90 && response.SW2 == 0x00 || response.SW1 == 0x69 && response.SW2 == 0x85;
        }

        private async Task<ApduResponse> U2F_Authenticate(byte[] clientDataHash, byte[] appIdHash, byte[] keyHandle, bool checkOnly) 
        {
            var request = new ApduRequest
            {
                Ins = (byte)CTAP1_INS.Authenticate,
                P1 = checkOnly ? (byte)0x07 : (byte)0x03,
                data = clientDataHash.Concat(appIdHash).Concat(Enumerable.Repeat((byte) keyHandle.Length, 1)).Concat(keyHandle).ToArray()
            };

            return await Apdu.SendAdpu(_connection, request);
        }

        public const string U2F_Register = "navigator.id.finishEnrollment";
        public const string U2F_Sign = "navigator.id.getAssertion";

        public void Dispose()
        {
            _connection?.Dispose();
            _connection = null;
        }
    }

    public class ApduException: Exception
    {
        public readonly byte SW1;
        public readonly byte SW2;

        public ApduException(byte sw1, byte sw2, string message = null): base(message)
        {
            SW1 = sw1;
            SW2 = sw2;
        }
    }

    public struct ApduRequest
    {
        public byte Cla;
        public byte Ins;
        public byte P1;
        public byte P2;
        public byte[] data;
        public ushort? maxResponseSize;
    }

    public struct ApduResponse
    {
        public byte[] data;
        public byte SW1;
        public byte SW2;
    }
    // https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/

    public static class Apdu
    {
        public static async Task<ApduResponse> SendAdpu(Stream connection, ApduRequest request)
        {
            var dataLen = (ushort) (request.data?.Length ?? 0);
            var maxRsBytes = 2;
            if (request.maxResponseSize.HasValue)
            {
                var rss = request.maxResponseSize.Value;
                if (rss == 0)
                {
                    maxRsBytes = 0;
                }
                else if (rss <= 0xff)
                {
                    maxRsBytes = 1;
                }
                else
                {
                    maxRsBytes = 2;
                }
            }

            var packetLength = 1 + 1 + 2 + (dataLen == 0 ? 0 : (dataLen <= 0xff ? 1 : 3)) + dataLen + maxRsBytes;
            var packet = new byte[packetLength];
            packet[0] = request.Cla;
            packet[1] = request.Ins;
            packet[2] = request.P1;
            packet[3] = request.P2;
            if (dataLen > 0)
            {
                byte dataOffset = 4;
                if (dataOffset <= 0xff)
                {
                    packet[4] = (byte) (dataOffset & 0xff);
                    dataOffset += 1;
                }
                else
                {
                    packet[4] = 0;
                    packet[5] = (byte) ((dataLen >> 8) & 0xff);
                    packet[6] = (byte) (dataLen & 0xff);
                    dataOffset += 3;
                }
                Array.Copy(request.data, 0, packet, dataOffset, request.data?.Length ?? 0);
            }

            if (request.maxResponseSize.HasValue)
            {
                if (maxRsBytes == 1)
                {
                    packet[packet.Length - 1] = (byte)(request.maxResponseSize.Value & 0xff);
                }
                else if (maxRsBytes == 2)
                {
                    packet[packet.Length - 1] = (byte) (request.maxResponseSize.Value & 0xff);
                    packet[packet.Length - 2] = (byte) ((request.maxResponseSize.Value >> 8) & 0xff);
                }
            }

            await connection.WriteAsync(packet, 0, packet.Length);
            await connection.FlushAsync();
            var readBuffer = new byte[maxRsBytes >= 2 ? ushort.MaxValue : byte.MaxValue];
            var bytesRead = await connection.ReadAsync(readBuffer, 0, readBuffer.Length);
            var rs = new ApduResponse
            {
                SW1 = 6
            };
            if (bytesRead >= 2)
            {
                rs.SW1 = readBuffer[bytesRead - 2];
                rs.SW2 = readBuffer[bytesRead - 1];
                if (bytesRead > 2)
                {
                    rs.data = new byte[bytesRead - 2];
                    Array.Copy(readBuffer, 0, rs.data, 0, rs.data.Length);
                }
            }

            return rs;
        }
    }
}

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
using Push;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    ///     Notification callback delegate.
    /// </summary>
    /// <typeparam name="T">Type of event</typeparam>
    /// <param name="evt">Notification event.</param>
    /// <returns><c>true</c> to remove callback. <c>false</c> keep receiving events.</returns>
    /// <seealso cref="IFanOut&lt;T&gt;" />
    public delegate bool NotificationCallback<in T>(T evt);

    /// <summary>
    ///     Declares fan-out event delivery interface
    /// </summary>
    /// <typeparam name="T">Type of event.</typeparam>
    public interface IFanOut<T> : IDisposable
    {
        /// <summary>
        ///     Gets completion flag.
        /// </summary>
        bool IsCompleted { get; }

        /// <summary>
        ///     Registers notification callback.
        /// </summary>
        /// <param name="callback"></param>
        void RegisterCallback(NotificationCallback<T> callback);

        /// <summary>
        ///     Removes registered callback.
        /// </summary>
        /// <param name="callback"></param>
        void RemoveCallback(NotificationCallback<T> callback);

        /// <summary>
        ///     Delivers event to subscribers.
        /// </summary>
        /// <param name="message"></param>
        void Push(T message);
    }

    /// <exclude />
    public class FanOut<T> : IFanOut<T>
    {
        private int _callbackNo;

        private readonly ConcurrentDictionary<int, NotificationCallback<T>> _callbacks = new();

        private bool TryGetCallbackId(NotificationCallback<T> callback, out int id)
        {
            using (var en = _callbacks.GetEnumerator())
            {
                while (en.MoveNext())
                {
                    if (ReferenceEquals(en.Current.Value, callback))
                    {
                        id = en.Current.Key;
                        return true;
                    }
                }
            }

            id = -1;
            return false;
        }

        public void RegisterCallback(NotificationCallback<T> callback)
        {
            if (IsCompleted) return;
            if (TryGetCallbackId(callback, out _)) return;

            var id = Interlocked.Increment(ref _callbackNo);
            _callbacks.TryAdd(id, callback);
        }

        public void RemoveCallback(NotificationCallback<T> callback)
        {
            if (IsCompleted) return;
            if (TryGetCallbackId(callback, out var id))
            {
                _callbacks.TryRemove(id, out _);
            }
        }

        public void Push(T item)
        {
            if (IsCompleted) return;
            var ids = _callbacks.Keys.ToArray();
            foreach (var id in ids)
            {
                if (!_callbacks.TryGetValue(id, out var cb)) continue;

                if (cb.Invoke(item))
                    _callbacks.TryRemove(id, out _);
            }
        }

        public bool IsCompleted { get; private set; }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool _)
        {
            IsCompleted = true;
            _callbacks.Clear();
        }
    }

    /// <exclude/>
    public class KeeperPushNotifications : FanOut<NotificationEvent>
    {
        private readonly byte[] _transmissionKey = CryptoUtils.GenerateEncryptionKey();
        private CancellationTokenSource _cancellationTokenSource;
        private readonly IWebProxy _webProxy;

        public KeeperPushNotifications(IWebProxy webProxy = null)
        {
            _webProxy = webProxy;
        }

        public void ConnectToPushServer(Func<byte[], Task<Uri>> getPushUrl, byte[] data = null)
        {
            if (_cancellationTokenSource != null)
            {
                if (!_cancellationTokenSource.IsCancellationRequested)
                {
                    _cancellationTokenSource.Cancel();
                }

                _cancellationTokenSource.Dispose();
            }
            _cancellationTokenSource = new CancellationTokenSource();
            
            _ = Task.Run(async () =>
            {
                while (true)
                {
                    var uri = await getPushUrl(_transmissionKey);
                    if (uri == null) break;

                    var ws = new ClientWebSocket();
                    ws.Options.Proxy = _webProxy;
                    var delayTask = Task.Delay(TimeSpan.FromSeconds(5), _cancellationTokenSource.Token);
                    var connectTask = ws.ConnectAsync(uri, _cancellationTokenSource.Token);
                    var t = await Task.WhenAny(delayTask, connectTask);
                    if (t == delayTask)
                    {
                        _cancellationTokenSource.Cancel();
                    }
                    if (ws.State != WebSocketState.Open)
                    {
                        ws.Dispose();
                        break;
                    }

                    if (data != null)
                    {
                        var encodedData = Encoding.UTF8.GetBytes(data.Base64UrlEncode());
                        var dataSegment = new ArraySegment<byte>(encodedData);
                        await ws.SendAsync(dataSegment, WebSocketMessageType.Text, true, _cancellationTokenSource.Token);
                    }

                    try
                    {
                        var buffer = new byte[1024];
                        var segment = new ArraySegment<byte>(buffer);
                        while (ws.State == WebSocketState.Open)
                        {
                            var rs = await ws.ReceiveAsync(segment, _cancellationTokenSource.Token);
                            if (rs.Count <= 0) continue;

                            var responseBytes = new byte[rs.Count];
                            Array.Copy(buffer, segment.Offset, responseBytes, 0, responseBytes.Length);
                            responseBytes = CryptoUtils.DecryptAesV2(responseBytes, _transmissionKey);
                            var wssRs = WssClientResponse.Parser.ParseFrom(responseBytes);
#if DEBUG
                            Debug.WriteLine($"REST push notification: {wssRs}");
#endif
                            try
                            {
                                var notification =
                                    JsonUtils.ParseJson<NotificationEvent>(Encoding.UTF8.GetBytes(wssRs.Message));
                                Push(notification);
                            }
                            catch (Exception e)
                            {
                                Debug.WriteLine(e.Message);
                            }
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                        break;
                    }
                    finally
                    {
                        ws.Dispose();
                    }
                    Debug.WriteLine("Websocket: Exited");
                }
            });
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (_cancellationTokenSource == null) return;
            
            if (!_cancellationTokenSource.IsCancellationRequested)
            {
                _cancellationTokenSource.Cancel();
            }
            _cancellationTokenSource.Dispose();
            _cancellationTokenSource = null;
        }
    }
}
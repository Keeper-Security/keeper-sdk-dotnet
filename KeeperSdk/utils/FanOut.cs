using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace KeeperSecurity.Utils
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
        private readonly ConcurrentDictionary<int, NotificationCallback<T>> _callbacks = 
            new ConcurrentDictionary<int, NotificationCallback<T>>();

        public void RegisterCallback(NotificationCallback<T> callback)
        {
            if (IsCompleted) return;
            var id = callback.GetHashCode();
            _callbacks.TryAdd(id, callback);
        }

        public void RemoveCallback(NotificationCallback<T> callback)
        {
            if (IsCompleted) return;
            _callbacks.TryRemove(callback.GetHashCode(), out _);
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

        public virtual void Shutdown()
        {
            IsCompleted = true;
            _callbacks.Clear();
        }

        protected virtual void Dispose(bool disposing)
        {
            Shutdown();
        }
    }
}

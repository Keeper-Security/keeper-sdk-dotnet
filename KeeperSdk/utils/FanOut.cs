using System;
using System.Collections.Generic;

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
        private readonly List<NotificationCallback<T>> _callbacks = new List<NotificationCallback<T>>();

        public void RegisterCallback(NotificationCallback<T> callback)
        {
            if (IsCompleted) return;
            lock (_callbacks)
            {
                foreach (var cb in _callbacks)
                    if (ReferenceEquals(cb, callback))
                        return;

                _callbacks.Add(callback);
            }
        }

        public void RemoveCallback(NotificationCallback<T> callback)
        {
            lock (_callbacks)
            {
                if (_callbacks.Count != 0) _callbacks.Remove(callback);
            }
        }

        public void Push(T item)
        {
            if (IsCompleted) return;
            lock (_callbacks)
            {
                var toRemove = new List<NotificationCallback<T>>();
                foreach (var cb in _callbacks)
                    if (cb.Invoke(item))
                        toRemove.Add(cb);

                foreach (var cb in toRemove) _callbacks.Remove(cb);
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

            lock (_callbacks)
            {
                _callbacks.Clear();
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            Shutdown();
        }
    }
}

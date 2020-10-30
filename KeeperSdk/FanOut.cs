using System;
using System.Collections.Generic;

namespace KeeperSecurity.Sdk
{

    public delegate bool NotificationCallback<in T>(T evt);

    public interface IFanOut<T>: IDisposable
    {
        void RegisterCallback(NotificationCallback<T> callback);
        void RemoveCallback(NotificationCallback<T> callback);
        void Push(T message);
        bool IsCompleted { get; }
    }

    public class FanOut<T> : IFanOut<T>
    {
        private readonly List<NotificationCallback<T>> _callbacks = new List<NotificationCallback<T>>();

        public void RegisterCallback(NotificationCallback<T> callback)
        {
            if (IsCompleted) return;
            lock (_callbacks)
            {
                foreach (var cb in _callbacks)
                {
                    if (ReferenceEquals(cb, callback)) return; 
                }

                _callbacks.Add(callback);
            }
        }

        public void RemoveCallback(NotificationCallback<T> callback)
        {
            lock (_callbacks)
            {
                if (_callbacks.Count != 0)
                {
                    _callbacks.Remove(callback);
                }
            }
        }

        public virtual void Shutdown()
        {
            IsCompleted = true;

            lock (_callbacks)
            {
                _callbacks.Clear();
            }
        }

        public void Push(T item)
        {
            if (IsCompleted) return;
            lock (_callbacks)
            {
                var toRemove = new List<NotificationCallback<T>>();
                foreach (var cb in _callbacks)
                {
                    if (cb.Invoke(item))
                    {
                        toRemove.Add(cb);
                    }
                }
                foreach (var cb in toRemove)
                {
                    _callbacks.Remove(cb);
                }
            }
        }

        public bool IsCompleted { get; private set; }

        protected virtual void Dispose(bool disposing)
        {
            Shutdown();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}

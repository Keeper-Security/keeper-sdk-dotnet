using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;

namespace Cli
{
    /// <exclude/>
    public class ReadLineParameters
    {
        public string Text { get; set; }
        public bool IsSecured { get; set; }
        public bool IsHistory { get; set; }
    }

    public class KeyboardInterrupt : Exception { }

    /// <exclude/>
    public interface IInputManager
    {
        Task<string> ReadLine(ReadLineParameters parameters = null);
        void InterruptReadTask(Task<string> task);
    }

    public class SimpleInputManager : IInputManager
    {
        private string ReadPassword()
        {
            var result = new StringBuilder();
            var done = false;
            while (!done)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                switch (key.Key)
                {
                    case ConsoleKey.Enter:
                        done = true;
                        Console.WriteLine();
                        break;
                    case ConsoleKey.Backspace:
                        if (result.Length > 0)
                        {
                            result.Length--;
                            Console.Write("\b \b");
                        }
                        break;
                    default:
                        result.Append(key.KeyChar);
                        Console.Write('*');
                        break;
                }
            }
            return result.ToString();
        }

        public void InterruptReadTask(Task<string> task)
        {
            Console.WriteLine("Press <Enter>");
        }

        public Task<string> ReadLine(ReadLineParameters parameters = null)
        {
            string input;
            if (parameters?.IsSecured == true)
            {
                input = ReadPassword();
            }
            else
            {
                input = Console.ReadLine();
            }
            return Task.FromResult(input);
        }
    }

    /// <exclude/>
    public class InputManager : IInputManager
    {
        private readonly StringBuilder _buffer = new StringBuilder();
        private bool _isSecured;
        private bool _isMaskToggled;
        private bool _isHistory;
        private int _positionInHistory;
        private string _savedBuffer;
        private TaskCompletionSource<string> _taskSource;
        private const char Mask = '*';
        private int _cursorPosition;
        private readonly Queue<string> _yankRing = new Queue<string>();
        private readonly List<string> _history = new List<string>();

        public void Run()
        {
            Console.TreatControlCAsInput = true;
            while (true)
            {
                var keyInfo = Console.ReadKey(true);
                if ((keyInfo.Modifiers & ConsoleModifiers.Control) != 0 && keyInfo.Key == ConsoleKey.C)
                {
                    TaskCompletionSource<string> ts;
                    lock (this)
                    {
                        ts = _taskSource;
                        _taskSource = null;
                    }

                    if (ts != null)
                    {
                        if (_buffer.Length > 0 && !_isSecured)
                        {
                            var left = Console.CursorLeft;
                            var top = Console.CursorTop;
                            left -= _cursorPosition;
                            _cursorPosition = 0;
                            while (left < 0)
                            {
                                left += Console.BufferWidth;
                                top--;
                            }

                            while (left >= Console.BufferWidth)
                            {
                                left -= Console.BufferWidth;
                                top++;
                            }
                            Console.SetCursorPosition(left, top);
                            var origColor = Console.ForegroundColor;
                            Console.ForegroundColor = ConsoleColor.DarkGray;
                            Console.Write(_buffer.ToString());
                            Console.ForegroundColor = origColor;
                        }

                        Console.WriteLine();
                        Task.Run(() => { ts.TrySetException(new KeyboardInterrupt()); });
                    }
                    else
                    {
                        if (CancelKeyPress != null)
                        {
                            var ev = new InputManagerCancelEventArgs();
                            try
                            {
                                CancelKeyPress(this, ev);
                            }
                            catch (Exception e)
                            {
                                Debug.WriteLine(e.Message);
                                ev.Cancel = true;
                            }

                            if (ev.Cancel)
                            {
                                break;
                            }
                        }
                    }
                }
                else if (_taskSource != null)
                {
                    if (keyInfo.Key == ConsoleKey.Enter)
                    {
                        TaskCompletionSource<string> ts;
                        lock (this)
                        {
                            ts = _taskSource;
                            _taskSource = null;
                        }

                        var line = _buffer.ToString();
                        _buffer.Length = 0;
                        _cursorPosition = 0;
                        _yankRing.Clear();
                        if (_isHistory && !string.IsNullOrEmpty(line))
                        {
                            int toDelete;
                            if (_positionInHistory > 0 && _positionInHistory <= _history.Count)
                            {
                                toDelete = _history.Count - _positionInHistory;
                            }
                            else
                            {
                                toDelete = _history.FindIndex(x => x == line);
                            }

                            if (toDelete >= 0 && toDelete < _history.Count)
                            {
                                _history.RemoveAt(toDelete);
                            }

                            _history.Add(line);
                            _positionInHistory = 0;
                        }

                        Console.WriteLine();
                        if (ts != null)
                        {
                            Task.Run(() => { ts.TrySetResult(line); });
                        }
                    }
                    else if (!char.IsControl(keyInfo.KeyChar))
                    {
                        if (_cursorPosition >= _buffer.Length)
                        {
                            _buffer.Append(keyInfo.KeyChar);
                            Console.Write(_isSecured ? Mask : keyInfo.KeyChar);
                            _cursorPosition++;
                        }
                        else
                        {
                            _buffer.Insert(_cursorPosition, keyInfo.KeyChar);
                            var tail = _buffer.ToString(_cursorPosition, _buffer.Length - _cursorPosition);
                            if (_isSecured)
                            {
                                tail = new string(Mask, tail.Length);
                            }

                            _cursorPosition++;

                            var left = Console.CursorLeft;
                            var top = Console.CursorTop;
                            if (left < Console.BufferWidth - 1)
                            {
                                left++;
                            }
                            else
                            {
                                left = 0;
                                top++;
                            }

                            Console.Write(tail);
                            Console.SetCursorPosition(left, top);
                        }

                    }
                    else if (keyInfo.Key == ConsoleKey.Backspace && _cursorPosition > 0)
                    {
                        _buffer.Remove(_cursorPosition - 1, 1);
                        _cursorPosition--;


                        var tail = _buffer.ToString(_cursorPosition, _buffer.Length - _cursorPosition);
                        if (_isSecured)
                        {
                            tail = new string(Mask, tail.Length);
                        }

                        var left = Console.CursorLeft;
                        var top = Console.CursorTop;
                        if (left > 0)
                        {
                            left--;
                        }
                        else
                        {
                            left = Console.BufferWidth - 1;
                            top--;
                        }

                        Console.SetCursorPosition(left, top);
                        Console.Write(tail + " ");
                        Console.SetCursorPosition(left, top);
                    }
                    else if (keyInfo.Key == ConsoleKey.Delete && _cursorPosition < _buffer.Length)
                    {
                        _buffer.Remove(_cursorPosition, 1);

                        var tail = _buffer.ToString(_cursorPosition, _buffer.Length - _cursorPosition);
                        if (_isSecured)
                        {
                            tail = new string(Mask, tail.Length);
                        }

                        var left = Console.CursorLeft;
                        var top = Console.CursorTop;
                        Console.Write(tail + " ");
                        Console.SetCursorPosition(left, top);
                    }
                    else if (keyInfo.Key == ConsoleKey.LeftArrow || keyInfo.Key == ConsoleKey.RightArrow)
                    {
                        var left = Console.CursorLeft;
                        var top = Console.CursorTop;

                        if (keyInfo.Key == ConsoleKey.LeftArrow)
                        {
                            if (_cursorPosition > 0)
                            {
                                _cursorPosition--;
                                if (left > 0)
                                {
                                    left--;
                                }
                                else
                                {
                                    left = Console.BufferWidth - 1;
                                    top--;
                                }
                            }
                        }
                        else
                        {
                            if (_cursorPosition < _buffer.Length)
                            {
                                _cursorPosition++;
                                if (left < Console.BufferWidth - 1)
                                {
                                    left++;
                                }
                                else
                                {
                                    left = 0;
                                    top++;
                                }
                            }
                        }

                        Console.SetCursorPosition(left, top);
                    }
                    else if (keyInfo.Key == ConsoleKey.UpArrow || keyInfo.Key == ConsoleKey.DownArrow)
                    {
                        if (!_isHistory) continue;
                        if (keyInfo.Key == ConsoleKey.UpArrow && _positionInHistory == 0)
                        {
                            _savedBuffer = _buffer.ToString();
                        }

                        if (keyInfo.Key == ConsoleKey.DownArrow)
                        {
                            if (_positionInHistory >= 0)
                            {
                                _positionInHistory--;
                            }
                            else
                            {
                                continue;
                            }
                        }

                        if (keyInfo.Key == ConsoleKey.UpArrow)
                        {
                            if (_positionInHistory < _history.Count)
                            {
                                _positionInHistory++;
                            }
                            else
                            {
                                continue;
                            }
                        }

                        string newBuffer = "";
                        if (_positionInHistory > 0)
                        {
                            if (_positionInHistory <= _history.Count)
                            {
                                newBuffer = _history[_history.Count - _positionInHistory];
                            }
                        }
                        else if (!string.IsNullOrEmpty(_savedBuffer))
                        {
                            newBuffer = _savedBuffer;
                        }

                        var left = Console.CursorLeft;
                        var top = Console.CursorTop;
                        left -= _cursorPosition;
                        while (left < 0)
                        {
                            left += Console.BufferWidth;
                            top--;
                        }

                        Console.SetCursorPosition(left, top);
                        Console.Write(new string(' ', _buffer.Length));

                        _buffer.Length = 0;
                        _buffer.Append(newBuffer);
                        Console.SetCursorPosition(left, top);
                        Console.Write(newBuffer);
                        _cursorPosition = newBuffer.Length;
                    }
                    else if (keyInfo.Key == ConsoleKey.Tab)
                    {
                        if (!_isSecured && !_isMaskToggled) continue;
                        _isMaskToggled = !_isMaskToggled;
                        _isSecured = !_isSecured;

                        var left = Console.CursorLeft;
                        var top = Console.CursorTop;
                        var origLeft = left;
                        var origTop = top;
                        left -= _cursorPosition;
                        while (left < 0)
                        {
                            left += Console.BufferWidth;
                            top--;
                        }

                        Console.SetCursorPosition(left, top);
                        Console.Write(_isMaskToggled ? _buffer.ToString() : new string(Mask, _buffer.Length));
                        Console.SetCursorPosition(origLeft, origTop);
                    }
                    else if ((keyInfo.Modifiers & ConsoleModifiers.Control) != 0)
                    {
                        var left = Console.CursorLeft;
                        var top = Console.CursorTop;
                        if (keyInfo.Key == ConsoleKey.A || keyInfo.Key == ConsoleKey.E)
                        {
                            if (keyInfo.Key == ConsoleKey.A)
                            {
                                left -= _cursorPosition;
                                _cursorPosition = 0;
                            }
                            else
                            {
                                left += _buffer.Length - _cursorPosition;
                                _cursorPosition = _buffer.Length;
                            }

                            while (left < 0)
                            {
                                left += Console.BufferWidth;
                                top--;
                            }

                            while (left >= Console.BufferWidth)
                            {
                                left -= Console.BufferWidth;
                                top++;
                            }

                            Console.SetCursorPosition(left, top);
                        }

                        if (keyInfo.Key == ConsoleKey.K || keyInfo.Key == ConsoleKey.U)
                        {
                            if (_buffer.Length > 0)
                            {
                                var start = keyInfo.Key == ConsoleKey.K ? _cursorPosition : 0;
                                var len = keyInfo.Key == ConsoleKey.K ? _buffer.Length - _cursorPosition : _cursorPosition;
                                if (len > 0)
                                {
                                    var yankText = _buffer.ToString(start, len);
                                    _yankRing.Enqueue(yankText);
                                    _buffer.Remove(start, len);
                                    if (keyInfo.Key == ConsoleKey.K)
                                    {
                                        Console.Write(new string(' ', len));
                                    }
                                    else
                                    {
                                        left -= _cursorPosition;
                                        _cursorPosition = 0;
                                        while (left < 0)
                                        {
                                            left += Console.BufferWidth;
                                            top--;
                                        }

                                        var text = (_isSecured ? new string(Mask, _buffer.Length) : _buffer.ToString()) + new string(' ', len);
                                        Console.SetCursorPosition(left, top);
                                        Console.Write(text);
                                    }

                                    Console.SetCursorPosition(left, top);
                                }
                            }
                        }
                        else if (keyInfo.Key == ConsoleKey.Y)
                        {
                            if (_yankRing.Count > 0)
                            {
                                var yankText = _yankRing.Dequeue();
                                _buffer.Insert(_cursorPosition, yankText);
                                var len = _buffer.Length - _cursorPosition;
                                var text = _isSecured ? new string(Mask, len) : _buffer.ToString(_cursorPosition, len);
                                left += yankText.Length;
                                _cursorPosition += yankText.Length;
                                while (left >= Console.BufferWidth)
                                {
                                    left -= Console.BufferWidth;
                                    top++;
                                }

                                Console.Write(text);
                                Console.SetCursorPosition(left, top);
                            }
                        }
                        else if (keyInfo.Key == ConsoleKey.L)
                        {
                            left -= _cursorPosition;
                            _cursorPosition = 0;
                            var text = new string(' ', _buffer.Length);
                            _buffer.Length = 0;
                            while (left < 0)
                            {
                                left += Console.BufferWidth;
                                top--;
                            }

                            Console.SetCursorPosition(left, top);
                            Console.Write(text);
                            Console.SetCursorPosition(left, top);
                        }
                    }
                }
            }
        }

        public void ClearHistory()
        {
            lock (this)
            {
                _history.Clear();
                _positionInHistory = 0;
            }
        }

        public void InterruptReadTask(Task<string> task)
        {
            TaskCompletionSource<string> ts;
            lock (this)
            {
                if (_taskSource == null || task == null) return;
                if (ReferenceEquals(task, _taskSource.Task))
                {
                    ts = _taskSource;
                }
                else
                {
                    return;
                }
            }

            ts.TrySetCanceled();
            if (ReferenceEquals(task, _taskSource.Task))
            {
                _taskSource = null;
            }
        }

        public Task<string> ReadLine(ReadLineParameters parameters = null)
        {
            TaskCompletionSource<string> ts;
            lock (this)
            {
                ts = _taskSource;
                _taskSource = null;
            }

            if (ts != null)
            {
                Task.Run(() => { ts.TrySetResult(""); });
            }

            lock (this)
            {
                _buffer.Length = 0;
                if (string.IsNullOrEmpty(parameters?.Text))
                {
                    _cursorPosition = 0;
                }
                else
                {
                    Console.Write(parameters.Text);
                    _buffer.Append(parameters.Text);
                    _cursorPosition = parameters.Text.Length;
                }

                _isMaskToggled = false;
                _yankRing.Clear();
                _isSecured = parameters?.IsSecured ?? false;
                _isHistory = parameters?.IsHistory ?? false;
                _taskSource = new TaskCompletionSource<string>();
                return _taskSource.Task;
            }
        }

        public sealed class InputManagerCancelEventArgs : EventArgs
        {
            public bool Cancel { get; set; }
        }

        public event EventHandler<InputManagerCancelEventArgs> CancelKeyPress;
    }
}
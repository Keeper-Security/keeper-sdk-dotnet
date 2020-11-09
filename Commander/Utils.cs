using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Commander
{
    public class ReadLineParameters {
        public string Text { get; set; }
        public bool IsSecured { get; set; }
        public bool IsHistory { get; set; }
    }

    public class InputManager
    {
        private readonly StringBuilder _buffer = new StringBuilder();
        private bool _isSecured;
        private bool _isMaskToggled;
        private bool _isHistory;
        private int _positionInHistory;
        private string _savedBuffer;
        private TaskCompletionSource<string> _taskSource;
        private const char Mask = '*';
        private int _cursorPosition = 0;
        private readonly Queue<string> _yankRing = new Queue<string>();
        private readonly List<string> _history = new List<string>();

        public void Run()
        {
            Console.TreatControlCAsInput = true;
            while (true)
            {
                var keyInfo = Console.ReadKey(true);
                lock (this)
                {
                    if (_taskSource == null)
                    {
                        if (keyInfo.Key == ConsoleKey.Enter)
                        {
                            break;
                        }

                        continue;
                    }
                }

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
                        Task.Run(() =>
                        {
                            ts.TrySetResult(line);
                        });

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
                    else
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
            lock (this)
            {
                if (_taskSource == null || task == null) return;
                if (ReferenceEquals(task, _taskSource.Task))
                {
                    _taskSource.TrySetCanceled();
                    _taskSource = null;
                }
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
                Task.Run(() =>
                {
                    ts.TrySetResult("");
                });
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
                _cursorPosition = 0;
                _yankRing.Clear();
                _isSecured = parameters?.IsSecured ?? false;
                _isHistory = parameters?.IsHistory ?? false;
                _taskSource = new TaskCompletionSource<string>();
                return _taskSource.Task;
            }
        }
    }

    public class Tabulate
    {
        private readonly int _columns;
        private readonly bool[] _rightAlignColumn;
        private readonly int[] _maxChars;
        private readonly List<string[]> _data = new List<string[]>();

        public Tabulate(int columns)
        {
            _columns = columns;
            _rightAlignColumn = Enumerable.Repeat(false, columns).ToArray();
            _maxChars = Enumerable.Repeat(0, columns).ToArray();
        }

        private string[] _header;

        public void AddHeader(params string[] header)
        {
            _header = header.Take(_columns).ToArray();
        }

        private static bool IsNumber(object value)
        {
            return value is sbyte
                   || value is byte
                   || value is short
                   || value is ushort
                   || value is int
                   || value is uint
                   || value is long
                   || value is ulong
                   || value is float
                   || value is double
                   || value is decimal;
        }

        private static bool IsDecimal(object value)
        {
            return value is float
                   || value is double
                   || value is decimal;
        }

        public void AddRow(params object[] fields)
        {
            var row = Enumerable.Repeat("", _columns).ToArray();
            var colNo = 0;
            foreach (var o in fields)
            {
                var text = "";
                if (o != null)
                {
                    text = o.ToString();
                    var isNum = IsNumber(o);
                    if (isNum)
                    {
                        if (IsDecimal(o))
                        {
                            text = $"{o:0.00}";
                        }
                    }
                }

                row[colNo] = text;
                colNo++;
                if (colNo >= _columns)
                {
                    break;
                }
            }

            _data.Add(row);
        }

        public void SetColumnRightAlign(int colNo, bool value)
        {
            if (colNo >= 0 && colNo < _columns)
            {
                _rightAlignColumn[colNo] = value;
            }
        }

        public void Sort(int colNo)
        {
            if (_data.Count <= 1) return;

            var isNum = _rightAlignColumn[colNo];
            if (colNo >= 0 && colNo < _columns)
            {
                _data.Sort((x, y) =>
                {
                    if (!isNum) return string.Compare(y[colNo], x[colNo], StringComparison.Ordinal);

                    var res = x[colNo].Length.CompareTo(y[colNo].Length);
                    return res != 0 ? res : string.Compare(y[colNo], x[colNo], StringComparison.Ordinal);
                });
            }
        }

        private const string RowSeparator = "  ";
        public bool DumpRowNo { get; set; }
        public int LeftPadding { get; set; }
        public int MaxColumnWidth { get; set; } = 40;

        public void Dump()
        {
            for (var i = 0; i < _maxChars.Length; i++)
            {
                var len = 0;
                if (DumpRowNo && _header != null)
                {
                    if (i < _header.Length)
                    {
                        len = _header[i].Length;
                    }
                }

                foreach (var row in _data.Where(row => i < row.Length))
                {
                    len = Math.Max(len, row[i].Length);
                    if (len > MaxColumnWidth)
                    {
                        len = MaxColumnWidth;
                    }
                }

                _maxChars[i] = len;
            }

            var rowNoLen = DumpRowNo ? _data.Count.ToString().Length + 1 : 0;
            if (rowNoLen > 0 && rowNoLen < 3)
            {
                rowNoLen = 3;
            }

            if (_header != null)
            {
                var r = (DumpRowNo ? (new string[] {"#".PadLeft(rowNoLen)}) : Enumerable.Empty<string>())
                    .Concat(_header.Zip(_maxChars.Zip(_rightAlignColumn, (m, b) => b ? -m : m),
                        (h, m) => m < 0 ? h.PadLeft(-m) : h.PadRight(m)));
                if (LeftPadding > 0)
                {
                    Console.Write("".PadLeft(LeftPadding));
                }

                Console.WriteLine(string.Join(RowSeparator, r));

                r = (DumpRowNo ? (new string[] {"".PadLeft(rowNoLen, '-')}) : Enumerable.Empty<string>())
                    .Concat(_maxChars.Select(m => "".PadRight(m, '-')));
                if (LeftPadding > 0)
                {
                    Console.Write("".PadLeft(LeftPadding));
                }

                Console.WriteLine(string.Join(RowSeparator, r));
            }

            var rowNo = 1;
            foreach (var row in _data)
            {
                var r = (DumpRowNo ? (new[] {rowNo.ToString().PadLeft(rowNoLen)}) : Enumerable.Empty<string>())
                    .Concat(row.Zip(_maxChars.Zip(_rightAlignColumn, (m, b) => b ? -m : m), (cell, m) =>
                    {
                        cell = cell.Replace("\n", " ");
                        if (cell.Length > MaxColumnWidth)
                        {
                            return cell.Substring(0, MaxColumnWidth - 3) + "...";
                        }

                        return m < 0 ? cell.PadLeft(-m) : cell.PadRight(m);
                    }));

                if (LeftPadding > 0)
                {
                    Console.Write("".PadLeft(LeftPadding));
                }

                Console.WriteLine(string.Join(RowSeparator, r));

                rowNo++;
            }

            Console.WriteLine();
        }
    }
}
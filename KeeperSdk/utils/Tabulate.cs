using System;
using System.Collections.Generic;
using System.Linq;

namespace KeeperSecurity.Utils
{
    /// <exclude/>
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
                    if (o is bool b)
                    {
                        text = b ? "X" : "-";
                    }
                    else
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
                    if (!isNum) return string.Compare(x[colNo], y[colNo], StringComparison.Ordinal);

                    var res = x[colNo].Length.CompareTo(y[colNo].Length);
                    return res != 0 ? res : string.Compare(x[colNo], y[colNo], StringComparison.Ordinal);
                });
            }
        }

        private const string RowSeparator = "  ";
        public bool DumpRowNo { get; set; }
        public int LeftPadding { get; set; }
        public int MaxColumnWidth { get; set; } = 60;

        public void Dump()
        {
            for (var i = 0; i < _maxChars.Length; i++)
            {
                var len = 0;
                if (_header != null)
                {
                    if (_maxChars[i] < _header.Length)
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
                var r = (DumpRowNo ? new[] {"#".PadLeft(rowNoLen)} : Enumerable.Empty<string>())
                    .Concat(_header.Zip(_maxChars.Zip(_rightAlignColumn, (m, b) => b ? -m : m),
                        (h, m) => m < 0 ? h.PadLeft(-m) : h.PadRight(m)));
                if (LeftPadding > 0)
                {
                    Console.Write("".PadLeft(LeftPadding));
                }

                Console.WriteLine(string.Join(RowSeparator, r));

                r = (DumpRowNo ? (new[] {"".PadLeft(rowNoLen, '-')}) : Enumerable.Empty<string>())
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
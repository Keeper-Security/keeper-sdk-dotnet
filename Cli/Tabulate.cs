using System;
using System.Collections.Generic;
using System.Linq;

namespace Cli
{
    /// <exclude/>
    public class Tabulate
    {
        private readonly int _columns;
        private readonly bool[] _rightAlignColumn;
        private readonly int[] _maxChars;
        private readonly List<object[]> _data = new List<object[]>();

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

        private static string ValueToString(object o) 
        {
            if (o == null) {
                return "";
            }
            else if (o is bool b)
            {
                return b ? "X" : "-";
            }
            else if (o is DateTimeOffset dt)
            {
                return dt.ToString("g");
            }
            else if (IsNumber(o)) {
                if (IsDecimal(o))
                {
                    return $"{o:0.00}";
                }
                return o.ToString();
            }
            else
            {
                return o.ToString();
            }
        }

        public void AddRow(params object[] fields)
        {
            var row = fields.Select(x => 
            {
                if (x is Array a)
                {
                    if (a.Length == 0) {
                        return "";
                    }
                    if (a.Length == 1) {
                        return ValueToString(a.GetValue(0));
                    }
                    var arr = new string[a.Length];
                    for (var i = 0; i < a.Length; i++)
                    {
                        arr[i] = ValueToString(a.GetValue(i));
                    }
                    return (object) arr;
                }
                else 
                {
                    return ValueToString(x);
                }
            }).ToArray();
            _data.Add(row);
        }

        public void SetColumnRightAlign(int colNo, bool value)
        {
            if (colNo >= 0 && colNo < _columns)
            {
                _rightAlignColumn[colNo] = value;
            }
        }

        private static string GetColumnValue(object[] row, int colNo)
        {
            if (colNo >= 0 && colNo < row.Length)
            {
                var v1 = row[colNo];
                if (v1 is string)
                {
                    return (string) v1;
                }
                else if (v1 is string[] a)
                {
                    if (a.Length > 0)
                    {
                        return (a[0] ?? "").ToString();
                    }
                }
            }
            return "";
        }

        public void Sort(int colNo)
        {
            if (_data.Count <= 1) return;

            var isNum = _rightAlignColumn[colNo];
            _data.Sort((x, y) =>
            {
                string xs = GetColumnValue(x, colNo);
                string ys = GetColumnValue(y, colNo); 

                if (!isNum) return string.Compare(xs, ys, StringComparison.InvariantCultureIgnoreCase);
                var res = xs.Length.CompareTo(ys.Length);
                return res != 0 ? res : string.Compare(xs, ys, StringComparison.Ordinal);
            });
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
                    if (i < _header.Length)
                    {
                        len = _header[i]?.Length ?? 0;
                    }
                }

                foreach (var row in _data.Where(row => i < row.Length))
                {
                    var colLen = 0;
                    if (row[i] is string[] ars)
                    {
                        colLen = ars.Where(x => !string.IsNullOrEmpty(x)).Aggregate(0, (cur, x) => Math.Max(cur, x.Length));
                    }
                    else if (row[i] is string s)
                    {
                        colLen = s.Length;
                    }
                    len = Math.Max(len, colLen);
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
                var subRows = 1;
                foreach (var col in row)
                {
                    if (col is string[] ars)
                    {
                        subRows = Math.Max(subRows, ars.Length);
                    }
                }
                for (var i = 0; i < subRows; i++) 
                {
                    var r = ((DumpRowNo) ? (new[] { (i == 0 ? rowNo.ToString() : "").PadLeft(rowNoLen) }) : Enumerable.Empty<string>())
                        .Concat(row.Zip(_maxChars.Zip(_rightAlignColumn, (m, b) => b ? -m : m), (cell, m) =>
                        {
                            string value = "";
                            if (cell is string s) {
                                if (i == 0) {
                                    value = s;
                                }
                            }
                            else if (cell is string[] ars) {
                                if (i < ars.Length) 
                                {
                                    value = ars[i];
                                }
                            }

                            value = value.Replace("\n", " ").Replace("\r", "");
                            if (value.Length > MaxColumnWidth)
                            {
                                return value.Substring(0, MaxColumnWidth - 3) + "...";
                            }

                            return m < 0 ? value.PadLeft(-m) : value.PadRight(m);
                        }));

                    if (LeftPadding > 0)
                    {
                        Console.Write("".PadLeft(LeftPadding));
                    }

                    var rowLine = string.Join(RowSeparator, r);
                    Console.WriteLine(rowLine);
                }


                rowNo++;
            }

            Console.WriteLine();
        }
    }
}
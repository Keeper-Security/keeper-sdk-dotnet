using System;

namespace Commander
{
    public static class ParseUtils
    {
        public static TimeSpan ParseTimePeriod(string period)
        {
            var pos = 0;
            while (pos < period.Length && char.IsDigit(period[pos]))
            { 
                pos++;
            }
            int num = pos == 0 ? 1 : int.Parse(period.Substring(0, pos));
            var interval = period.Substring(pos);
            switch (interval) 
            {
                case "mi":
                    return TimeSpan.FromMinutes(num);
                case "h":
                    return TimeSpan.FromHours(num);
                case "d":
                    return TimeSpan.FromDays(num);
                case "mo":
                    return TimeSpan.FromDays(num * 30);
            }
            throw new ArgumentException($"Invalid period: {period}");
        }
    }
}

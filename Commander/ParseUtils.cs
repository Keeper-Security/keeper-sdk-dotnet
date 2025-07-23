using System;

namespace Commander
{
    public static class ParseUtils
    {
        public static TimeSpan ParseTimePeriod(string period)
        {
            if (string.IsNullOrWhiteSpace(period))
                throw new ArgumentException("Period cannot be empty");

            var pos = 0;
            while (pos < period.Length && char.IsDigit(period[pos]))
            { 
                pos++;
            }
            int num = pos == 0 ? 1 : int.Parse(period.Substring(0, pos));
            var interval = period.Substring(pos).ToLowerInvariant();
            
            switch (interval) 
            {
                case "mi":
                case "minutes":
                case "minute":
                    return TimeSpan.FromMinutes(num);
                case "h":
                case "hours":
                case "hour":
                    return TimeSpan.FromHours(num);
                case "d":
                case "days":
                case "day":
                    return TimeSpan.FromDays(num);
                case "mo":
                case "months":
                case "month":
                    return TimeSpan.FromDays(num * 30);
                case "y":
                case "years":
                case "year":
                    return TimeSpan.FromDays(num * 365);
            }
            
            throw new ArgumentException($"{interval} is not allowed as a unit for the timeout value. " +
                                      "Valid units are \"years/y, months/mo, days/d, hours/h, minutes/mi\".");
        }
    }
}

using System;
using System.Globalization;

namespace Manifold.Signature
{
    public class DateChecker : IDateChecker
    {
        private double FIVE_MINUTES = TimeSpan.FromMinutes(5).TotalMilliseconds;

        public bool VerifyDate(string dateToVerify)
        {
            DateTime date = Convert.ToDateTime(dateToVerify);
            return DateTime.Now.Subtract(date).TotalMilliseconds < FIVE_MINUTES;
        }
    }
}

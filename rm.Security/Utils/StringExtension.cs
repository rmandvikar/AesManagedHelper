
namespace rm.Security.Utils
{
    public static class StringExtension
    {
        #region is null/empty/whitespace
        public static bool IsNullOrEmpty(this string s)
        {
            return string.IsNullOrEmpty(s);
        }
        public static bool IsNullOrWhiteSpace(this string s)
        {
            return string.IsNullOrWhiteSpace(s);
        }
        public static bool IsNullOrEmptyOrWhiteSpace(this string s)
        {
            return s.IsNullOrEmpty() || s.IsNullOrWhiteSpace();
        }
        #endregion
    }
}

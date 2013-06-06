using System;

namespace rm.Security.Utils
{
    public static class ObjectExtension
    {
        #region null/argument checks

        public static bool NullCheck(this object arg, string message = "",
            bool throwEx = true)
        {
            return Check<NullReferenceException>(arg == null, throwEx, message);
        }
        public static bool NullCheckArgument(this object obj, string message = "",
            bool throwEx = true)
        {
            return Check<ArgumentNullException>(obj == null, throwEx, message);
        }
        public static bool NullEmptyCheck(this string s, string message = "",
            bool throwEx = true)
        {
            return Check<NullReferenceException>(s.IsNullOrEmpty(), throwEx, message);
        }
        public static bool NullEmptyCheckArgument(this string s, string message = "",
            bool throwEx = true)
        {
            return Check<ArgumentException>(s.IsNullOrEmpty(), throwEx, message);
        }

        private static bool Check<T>(bool isNull, bool throwEx, string exceptionMessage)
            where T : Exception
        {
            if (throwEx && isNull)
            {
                throw Activator.CreateInstance(typeof(T), exceptionMessage) as Exception;
            }
            return isNull;
        }

        #endregion
    }
}

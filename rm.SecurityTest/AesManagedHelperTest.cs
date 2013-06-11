using System;
using System.Net;
using System.Text;
using NUnit.Framework;
using rm.Security;

namespace rm.SecurityTest
{
    [TestFixture]
    [Category("Unit")]
    public class AesManagedHelperTest
    {
        AesManagedHelper aes1 = null;
        AesManagedHelper aes2 = null;
        string passphrase = @"
oja60b4Ldm
LsRuY8AjtN
77xh5MpGX9
5HhlzZ3L09
LsAV66Bqrl
Vt9kQa17Wf
UXEbfBOXqc
4IwNRst1v5
ODNnHkLsi1
38rWIabl3g";

        [SetUp]
        public void setup()
        {
            aes1 = new AesManagedHelper();
            aes2 = new AesManagedHelper(passphrase);
        }
        [TearDown]
        public void teardown()
        {
            aes1 = null;
            aes2 = null;
        }

        [Test]
        [TestCase("encrypt this")]
        [TestCase("this is a test")]
        [TestCase("")]
        public void Test01a(string text)
        {
            var enc = WebUtility.UrlEncode(aes1.EncryptString(text));
            var dec = aes1.DecryptString((WebUtility.UrlDecode(enc)));
            Console.WriteLine(enc);
            Console.WriteLine(WebUtility.UrlEncode(enc));
            Console.WriteLine(dec);
            Assert.AreEqual(text, dec);
            Assert.AreNotEqual(dec, enc);
        }
        [Test]
        [TestCase(null)]
        public void Test01b(string text)
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                var enc = aes1.EncryptString(text);
            });
        }

        [Test]
        [TestCase("encrypt this")]
        [TestCase("this is a test")]
        [TestCase("")]
        public void Test02a(string text)
        {
            var enc = aes2.EncryptString(text);
            var dec = aes2.DecryptString(enc);
            Console.WriteLine(enc);
            Console.WriteLine(dec);
            Assert.AreEqual(text, dec);
            Assert.AreNotEqual(dec, enc);
        }
        [Test]
        [TestCase(null)]
        public void Test02b(string text)
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                var enc = aes2.EncryptString(text);
            });
        }

        [Test]
        public void Test03()
        {
            var sb = new StringBuilder();
            for (int i = 0; i < 100000; i++)
            {
                sb.Append("t");
            }
            var text = sb.ToString();
            var enc = aes2.EncryptString(text);
            var dec = aes2.DecryptString(enc);
            Console.WriteLine(enc);
            Console.WriteLine(dec);
            Assert.AreEqual(text, dec);
            Assert.AreNotEqual(dec, enc);
        }
    }
}

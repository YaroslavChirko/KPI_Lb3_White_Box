using IIG.PasswordHashingUtils;
using System;
using System.Linq;
using System.Security.Cryptography;
using Xunit;
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace KPI_Lb3
{

    public class Hashing_White_Box
    {
        [Fact]
        public void InitEqualCheck()
        {
            string pass = "password";
            string hashed_1 = PasswordHasher.GetHash(pass);
            PasswordHasher.Init("", 0);
            string hashed_2 = PasswordHasher.GetHash(pass);
            Assert.Equal(hashed_1, hashed_2);

        }

        [Theory]
        [InlineData("some_salt",55)]
        [InlineData("",165)]
        [InlineData("some_other_salt",0)]
        public void InitNotEqualCheck(string salt, uint adlerMod32)
        {
            string pass = "password";
            string hashed_1 = PasswordHasher.GetHash(pass);
            PasswordHasher.Init(salt,adlerMod32);
            string hashed_2 = PasswordHasher.GetHash(pass);
            Assert.NotEqual(hashed_1, hashed_2);

        }


        const uint first = 0;
        const uint second = 65521;
        [Theory]
        [InlineData(first,second)]
        [InlineData(first, null)]
        public void PasswordHasherAdlerCheck(uint? adler_1, uint? adler_2)
        {
            PasswordHasher.Init("put your soul(or salt) here", 65521);
           string pass = "password";
           string salt = "some_salt";
           string hashed_1 =  PasswordHasher.GetHash(pass, salt, adler_1);
           string hashed_2 = PasswordHasher.GetHash(pass, salt, adler_2);
           Assert.Equal(hashed_1, hashed_2);

        }

        [Fact]
        public void PasswordHasherAdlerNotEqualCheck()
        {
            PasswordHasher.Init("put your soul(or salt) here", 65521);
            string pass = "password";
            string salt = "some_salt";
            string hashed_1 = PasswordHasher.GetHash(pass, "", 0);
            string hashed_2 = PasswordHasher.GetHash(pass, salt, 1502);
            Assert.NotEqual(hashed_1, hashed_2);

        }

        [Theory]
        [InlineData(null, "put your soul(or salt) here")]
        [InlineData(null,"")]
        public void PasswordHasherSaltCheck(string salt_1,string salt_2)
        {
            PasswordHasher.Init("put your soul(or salt) here", 65521);
            string pass = "password";
            string hashed_1 = PasswordHasher.GetHash(pass,salt_1);
            string hashed_2 = PasswordHasher.GetHash(pass, salt_2);
            Assert.Equal(hashed_1, hashed_2);
        }

        [Theory]
        [InlineData(null, "some other salt insert")]
        [InlineData(null, " ")]
        public void PasswordHasherSaltNotEqualCheck(string salt_1, string salt_2)
        {
            string pass = "password";
            string hashed_1 = PasswordHasher.GetHash(pass,salt_1);
            string hashed_2 = PasswordHasher.GetHash(pass, salt_2);
            Assert.NotEqual(hashed_1, hashed_2);
        }

        [Fact]
        public void PasswordHasherAdlerNotEqualCheck2()
        {
            string pass = "password";
            string salt = "some_salt";
            string hashed_1 = PasswordHasher.GetHash(pass, "", 500000);
            string hashed_2 = PasswordHasher.GetHash(pass, salt, 1000000);
            Assert.NotEqual(hashed_1, hashed_2);

        }

         [Fact]
         public void PasswordHasherOverflowCheck()
         {
           
             string hashed_1 = PasswordHasher.GetHash("¿","a",125);
             string hashed_2 = PasswordHasher.GetHash("W\x04","a",125); //got from asserting
            Assert.Equal(hashed_2,hashed_1);

         }
        
        [Fact]
        public void PasswordHasherAdlerBufferUse()
        {
            string pass = "aaaa";
            string salt = "saltySalt";
           string hashed_1 = PasswordHasher.GetHash(pass, salt, 293);
            string sData = $"{salt}{BitConverter.ToString(BitConverter.GetBytes(195)).Replace("-", "")}{pass}";
            string expected = BitConverter.ToString(SHA256.Create().ComputeHash(sData.Select(Convert.ToByte).ToArray()))
                .Replace("-", "");

            Assert.Equal(expected, hashed_1); // will be true if buffer was used instead of res


        }

        [Fact]
        public void PasswordHasherAdlerResUse()
        {
            string pass = "0000";
            string salt = "saltySalt";
            string hashed = PasswordHasher.GetHash(pass, salt, 97);
            string sData = $"{salt}{BitConverter.ToString(BitConverter.GetBytes((49<<16))).Replace("-", "")}{pass}";
            string expected = BitConverter.ToString(SHA256.Create().ComputeHash(sData.Select(Convert.ToByte).ToArray()))
                .Replace("-", "");

            Assert.Equal(expected, hashed); // will be true if res was used (means if buf was 0 due to short circuit or) 
        }

        [Fact]
        public void PasswordHasherAdlerResAndBufFalse()
        {
            string pass = "00";
            string salt = "saltySalt";
            string hashed = PasswordHasher.GetHash(pass, salt, 49);
            string sData = $"{salt}{BitConverter.ToString(BitConverter.GetBytes((0))).Replace("-", "")}{pass}"; // either res or buf will be used since both are equal to 0 and no default value check provided
            string expected = BitConverter.ToString(SHA256.Create().ComputeHash(sData.Select(Convert.ToByte).ToArray()))
                .Replace("-", "");

            Assert.Equal(expected, hashed);
        }
    }
}

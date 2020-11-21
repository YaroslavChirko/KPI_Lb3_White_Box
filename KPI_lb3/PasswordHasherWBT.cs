using System;
using IIG.PasswordHashingUtils;
using Xunit;

namespace KPI_lb3
{
    public class PasswordHasherWBT
    {
        private const UInt32 param = 1;
        [Theory]
        [InlineData("some_pass","")]
        [InlineData("","")]
        [InlineData("1","")]
        [InlineData("", "",param)]
        public void LegalArgTest(string pass, string salt = null , uint? adlerMod32 = null)
        {
            string hashed = PasswordHasher.GetHash(pass, salt, adlerMod32);
        
            Assert.Equal(PasswordHasher.GetHash(pass, salt, adlerMod32), hashed);
        }

        [Fact]
        public void OverflowTest()
        {
            UInt32 adl = uint.MaxValue;
            string hashed = PasswordHasher.GetHash("pass", "salt", (uint)(adl+1));

            Assert.Equal(PasswordHasher.GetHash("pass", "salt", (uint)(adl+1)), hashed);
        }

        [Theory]
        [InlineData("some_pass","")]
        public void InitEqualTest(string pass, string salt = null, uint adlerMod32 = 0)
        {
            string hashed = PasswordHasher.GetHash(pass);
            PasswordHasher.Init(salt,adlerMod32);
            Assert.Equal(PasswordHasher.GetHash(pass), hashed);
        }

        [Theory]
        [InlineData("some_pass", "ffff")]
        [InlineData("some_pass", null, (UInt32)586)]
        public void InitNotEqualTest(string pass, string salt = null, uint adlerMod32 = 0)
        {
            string hashed = PasswordHasher.GetHash(pass);
            PasswordHasher.Init(salt, adlerMod32);
            Assert.NotEqual(PasswordHasher.GetHash(pass), hashed);
        }

        [Theory]
        [InlineData("some_pass")]
        [InlineData("")]
        [InlineData("1")]
        public void AvalancheEffectTest(string salt)
        {
            
            string pass1 = "pass1";
            string pass2 = "pass2";
            string hashed = PasswordHasher.GetHash(pass1,salt,(UInt32)1);

            Assert.NotEqual(PasswordHasher.GetHash(pass2,salt, (UInt32)1).Substring(0,2), hashed.Substring(0,2));
        }
    }
}

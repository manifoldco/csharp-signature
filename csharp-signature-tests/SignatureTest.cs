using System;
using Manifold.Signature;
using Xunit;

namespace csharp_signature_tests
{
    public class SignatureTest
    {
        private const string dummyKey = "PY7wu3q3-adYr9-0ES6CMRixup9OjO5iL7EFDFpolhk";

        private string signature;
        private string canonizedBody;

        public SignatureTest()
        {
            this.signature = "Nb9iJZVDFrcf8-dw7AsuSCPtdoxoAr61YVWQe-5b9z_YiuQW73wR7RRsDBPnrBMtXIg_h8yKWsr-ZNRgYbM7CA FzNbTkRjAGjkpwHUbAhjvLsIlAlL_M6EUh5E9OVEwXs qGR6iozBfLUCHbRywz1mHDdGYeqZ0JEcseV4KcwjEVeZtQN54odcJ1_QyZkmHacbQeHEai2-Aw9EF8-Ceh09Cg";
            this.canonizedBody = "put /v1/resources/2686c96868emyj61cgt2ma7vdntg4\n" +
                                 "host: 127.0.0.1:4567\n" +
                                 "date: 2017-03-05T23:53:08Z\n" +
                                 "content-type: application/json\n" +
                                 "content-length: 143\n" +
                                 "x-signed-headers: host date content-type content-length\n" +
                                 "{\"id\":\"2686c96868emyj61cgt2ma7vdntg4\",\"plan\":\"low\",\"product\":\"generators\",\"region\":\"aws::us-east-1\",\"user_id\":\"200e7aeg2kf2d6nud8jran3zxnz5j\"}\n";

        }

        [Fact]
        public void TestValidate()
        {
            Signature instance = new Signature(this.signature);
            Assert.True(instance.Validate(dummyKey, this.canonizedBody), "The Validate method should return true if given valid data");
        }

        [Fact]
        public void TestValidateNotEndorsed()
        {
            // Changed so that the public key starts with zz
            this.signature = "Nb9iJZVDFrcf8-dw7AsuSCPtdoxoAr61YVWQe-5b9z_YiuQW73wR7RRsDBPnrBMtXIg_h8yKWsr-ZNRgYbM7CA zzNbTkRjAGjkpwHUbAhjvLsIlAlL_M6EUh5E9OVEwXs qGR6iozBfLUCHbRywz1mHDdGYeqZ0JEcseV4KcwjEVeZtQN54odcJ1_QyZkmHacbQeHEai2-Aw9EF8-Ceh09Cg";
            Signature instance = new Signature(this.signature);
            Assert.Throws<InvalidSignatureException>(() => instance.Validate(dummyKey, this.canonizedBody));
        }

        [Fact]
        public void TestValidateWrongBody()
        {
            // Changed to start with bb eather than Nb
            this.signature = "bb9iJZVDFrcf8-dw7AsuSCPtdoxoAr61YVWQe-5b9z_YiuQW73wR7RRsDBPnrBMtXIg_h8yKWsr-ZNRgYbM7CA FzNbTkRjAGjkpwHUbAhjvLsIlAlL_M6EUh5E9OVEwXs qGR6iozBfLUCHbRywz1mHDdGYeqZ0JEcseV4KcwjEVeZtQN54odcJ1_QyZkmHacbQeHEai2-Aw9EF8-Ceh09Cg";
            Signature instance = new Signature(this.signature);
            Assert.Throws<InvalidSignatureException>(() => instance.Validate(dummyKey, this.canonizedBody));
        }
    }
}

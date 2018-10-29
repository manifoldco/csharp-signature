using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Manifold.Signature;
using Moq;
using Xunit;

namespace csharp_signature_tests
{
    public class VerifierTest
    {
        private HttpRequestMessage request;
        private const string dummyKey = "PY7wu3q3-adYr9-0ES6CMRixup9OjO5iL7EFDFpolhk";
    
        private Mock<IDateChecker> checker = null;

        public VerifierTest()
        {
            this.request = new HttpRequestMessage(HttpMethod.Put, "https://127.0.0.1:4567/v1/resources/2686c96868emyj61cgt2ma7vdntg4") {
                Content = new StringContent(
                    "{\"id\":\"2686c96868emyj61cgt2ma7vdntg4\",\"plan\":\"low\",\"product\":\"generators\",\"region\":\"aws::us-east-1\",\"user_id\":\"200e7aeg2kf2d6nud8jran3zxnz5j\"}\n"
                )
            };
            this.request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            this.request.Content.Headers.ContentLength = 143;
            this.request.Headers.Add("Date", new DateTime(2017, 03, 05, 23, 53, 08).ToString("ddd, dd MMM yyyy HH:mm:ss zzzz"));
            this.request.Headers.Add("X-Signed-Headers", "host date content-type content-length");
            this.request.Headers.Add("X-Signature", "Nb9iJZVDFrcf8-dw7AsuSCPtdoxoAr61YVWQe-5b9z_YiuQW73wR7RRsDBPnrBMtXIg_h8yKWsr-ZNRgYbM7CA FzNbTkRjAGjkpwHUbAhjvLsIlAlL_M6EUh5E9OVEwXs qGR6iozBfLUCHbRywz1mHDdGYeqZ0JEcseV4KcwjEVeZtQN54odcJ1_QyZkmHacbQeHEai2-Aw9EF8-Ceh09Cg");

            this.checker = new Mock<IDateChecker>();
            checker.Setup(checker => checker.VerifyDate(It.IsAny<string>())).Returns(true);
        }

        [Fact]
        public void TestVerify()
        {
            Verifier instance = new Verifier(VerifierTest.dummyKey, this.checker.Object);
            Task.Run(async () =>
            {
                Assert.True(await instance.VerifyAsync(this.request), "The VerifyAsync method should return true if given valid data");
            }).GetAwaiter().GetResult();
        }

        [Fact]
        public void TestVerifyInvalidSignature()
        {
            // Removed the signature
            this.request.Headers.Remove("X-Signature");
            Verifier instance = new Verifier(VerifierTest.dummyKey, this.checker.Object);
            Task.Run(async () =>
            {
                await Assert.ThrowsAsync<InvalidHeadersException>(() => instance.VerifyAsync(this.request));
            }).GetAwaiter().GetResult();
        }

        [Fact]
        public void TestVerifyInvalidSigned()
        {
            // Removed the signed headers
            this.request.Headers.Remove("X-Signed-Headers");
            Verifier instance = new Verifier(VerifierTest.dummyKey, this.checker.Object);
            Task.Run(async () =>
            {
                await Assert.ThrowsAsync<InvalidHeadersException>(() => instance.VerifyAsync(this.request));
            }).GetAwaiter().GetResult();
        }

        [Fact]
        public void TestVerifyInvalidDate()
        {
            // Change the date
            this.request.Headers.Remove("Date");
            this.request.Headers.Add("Date", new DateTime(2017, 03, 05, 23, 40, 08).ToString("ddd, dd MMM yyyy HH:mm:ss zzzz"));
            Verifier instance = new Verifier(VerifierTest.dummyKey);
            Task.Run(async () =>
            {
                await Assert.ThrowsAsync<InvalidHeadersException>(() => instance.VerifyAsync(this.request));
            }).GetAwaiter().GetResult();
        }
    }
}

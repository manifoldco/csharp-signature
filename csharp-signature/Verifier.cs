using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace Manifold.Signature
{
    /// <summary>
    /// Verifier class that will make sure the data received by an HTTP request 
    /// is signed by manifold using the ED25519 algorithm.
    /// </summary>
    public class Verifier
    {
        /// <summary>
        /// Main manifold master key that can be used to verify signatures coming
        /// from manifold.
        /// </summary>
        public const string MANIFOLD_MASTERKEY = "PtISNzqQmQPBxNlUw3CdxsWczXbIwyExxlkRqZ7E690";

        /// <summary>
        /// Time format definition for the accepted RFC3339 format accepted by manifold.
        /// </summary>
        public const string TIME_RFC3339 = "yyyy-MM-dd'T'HH:mm:ss'Z'";
        
        private const string METHOD_GET = "GET";
        
        private const string SIGNATURE_HEADER = "X-Signature";
        private const string SIGNED_HEADERS = "X-Signed-Headers";
        private const string DATE_HEADER = "Date";

        /// <summary>
        /// The public key currently stored inside the verifier.
        /// </summary>
        /// <value>The public key.</value>
        public string publicKey
        {
            get;
        }

        private IDateChecker checker;

        /// <summary>
        /// Initialize the class with the given public key. The constructor is
        /// lenient of the various Base64 formats of publickeys and will clean
        /// it up if needed.
        /// </summary>
        /// <param name="publicKey">The public key encoded in base64Url</param>
        public Verifier(string publicKey)
        {
            // Be lenient of different base64 formats
            publicKey = publicKey.Replace("+", "-");
            publicKey = publicKey.Replace("/", "_");
            publicKey = publicKey.Replace("=+$", "");

            this.publicKey = publicKey;
            this.checker = new DateChecker();
        }

        /// <summary>
        /// Constructor for testing purposes, allows to redefine the date header
        /// verification logic.
        /// </summary>
        /// <param name="publicKey">The public key encoded in base64Url</param>
        /// <param name="checker">The date checker instance, available for mocking.</param>
        public Verifier(string publicKey, IDateChecker checker)
        {
            // Be lenient of different base64 formats
            publicKey = publicKey.Replace("+", "-");
            publicKey = publicKey.Replace("/", "_");
            publicKey = publicKey.Replace("=+$", "");

            this.publicKey = publicKey;
            this.checker = checker;
        }

        /// <summary>
        /// Verifies the given request parts with the Signature class.
        /// </summary>
        /// <example>
        /// 
        /// </example>
        /// <returns>Whether or not the </returns>
        /// <param name="request">An Http request that contins the various parts of the signed request.</param>
        public async Task<bool> VerifyAsync(HttpRequestMessage request)
        {
            HttpRequestHeaders headers = request.Headers;
            if (!headers.Contains(SIGNATURE_HEADER))
            {
                throw new InvalidHeadersException($"The header {SIGNATURE_HEADER} is missing");
            }
            string signatureHeader = headers.GetValues(SIGNATURE_HEADER).First();

            Signature signature = new Signature(signatureHeader);

            if (!headers.Contains(SIGNED_HEADERS))
            {
                throw new InvalidHeadersException($"The header {SIGNED_HEADERS} is missing");
            }
            if (!headers.Contains(DATE_HEADER))
            {
                throw new InvalidHeadersException($"The header {DATE_HEADER} is missing");
            }
            if (!this.checker.VerifyDate(headers.GetValues(DATE_HEADER).First()))
            {
                throw new InvalidHeadersException($"The header {DATE_HEADER} is not within five minutes of the request");
            }

            return signature.Validate(this.publicKey, await this.CanonizeAsync(request));
        }

        private async Task<string> CanonizeAsync(HttpRequestMessage request)
        {
            string method = request.Method.Method;
            HttpRequestHeaders headers = request.Headers;
            if (String.IsNullOrEmpty(method))
            {
                method = METHOD_GET;
            }
            StringBuilder bodyBuilder = new StringBuilder();

            Uri path = request.RequestUri;
            // Begin writing the target of the signature.
            // start with the request target:
            //     lower(METHOD) <space > PATH <'?'> canonical(QUERY) <newline>
            // where canonical(QUERY) is the query params, lexicographically sorted
            // in ascending order (including param name, = sign, and value),
            // and delimited by an '&'.
            // If no query params are set, the '?' is omitted.
            bodyBuilder.Append(method.ToLower()).Append(" ").Append(path.AbsolutePath);
            string query = path.Query;
            if (!string.IsNullOrEmpty(query))
            {
                string[] queryParts = query.Split('&');
                Array.Sort(queryParts);
                bodyBuilder.Append(String.Join("&", queryParts));
            }
            bodyBuilder.Append("\n");

            // Next, add all headers. These are the headers listed in the
            // X-Signed-Headers  header, in the order they are listed, followed by
            // the X-Signed-Headers header itself.
            //
            // Headers are written in the form:
            //     lower(NAME) <colon> <space> VALUES <newline>
            // Values have all optional whitespace removed.
            // If the header occurs multiple times on the request, the values are
            // included delimited by `, `, in the order they appear on the request.
            //
            // The X-Signed-Headers header includes the list of all signed headers,
            // lowercased, and delimited by a space. Only one occurrence of
            // X-Signed-Headers should exist on a request. If more than one exists,
            // The first is used.

            List<string> signerHeaders = headers.GetValues(SIGNED_HEADERS).FirstOrDefault().Split(' ').ToList<string>();
            signerHeaders.Add(SIGNED_HEADERS);
            signerHeaders.ForEach(header => {
                string headerName = this.CanonizeHeaderName(header);

                string signedHeader = "";
                IEnumerable<string> extractedHeaders;
                if (headerName.Equals("Host"))
                {
                    signedHeader = path.Authority;
                }
                else if (headerName.Equals("Date"))
                {
                    signedHeader = Convert.ToDateTime(
                        headers.GetValues(headerName).First()
                    ).ToString(TIME_RFC3339);
                }
                else if (headers.TryGetValues(headerName, out extractedHeaders))
                {
                    signedHeader = extractedHeaders.First();
                }
                else if (request.Content.Headers.TryGetValues(headerName, out extractedHeaders))
                {
                    signedHeader = extractedHeaders.First();
                }

                bodyBuilder.Append(header.ToLower()).Append(": ").Append(signedHeader).Append("\n");
            });

            string body = await request.Content.ReadAsStringAsync();

            return bodyBuilder.Append(body).ToString();
        }

        private string CanonizeHeaderName(string name)
        {
            string output = name;
            int lastIndex = 0;
            output = output.Substring(0, 1).ToUpper() + output.Substring(1);
            while (output.IndexOf("-", lastIndex, StringComparison.InvariantCulture) > 0)
            {
                lastIndex = output.IndexOf("-", lastIndex, StringComparison.InvariantCulture) + 1;
                output = output.Substring(0, lastIndex) +
                               output.Substring(lastIndex, 1).ToUpper() +
                               output.Substring(lastIndex + 1);
            }
            return output;
        }
    }
}

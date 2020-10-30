//----------------------------------------------------------------------------------------------
// <copyright file="CertContextHandle.cs" company="Microsoft">
// Copyright (c) Microsoft.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
using System;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace SSLHelper
{
    public static class SSLHelper
    {
        public static bool OnRemoteCertificateReceived(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine("Remote Certificate Received!");
            SslStream stream = (SslStream)sender;

            bool ok = true;
            if (sslPolicyErrors != 0)
            {
                Console.WriteLine($"SSL Policy ERRORS!! {sslPolicyErrors.ToString()}");
                ok = false;
            }

            string indent = "";
            foreach (var el in chain.ChainElements)
            {
                var c = (X509Certificate2)el.Certificate;

                Console.WriteLine($"{indent}Subject={c.Subject}, Expires: {c.GetExpirationDateString()}, KeyAlgorithm={c.GetKeyAlgorithmParametersString()} Issuer={c.Issuer}");

                // if(false) //TODO add export option
                //     SaveCertificatesToDisk(c, indent);

                var s = el.ChainElementStatus;
                foreach (var status in s.Where(x => x.Status != 0))
                {
                    Console.WriteLine($"{indent}Cert Status: {status.Status}, {status.StatusInformation}");
                    ok = false;
                }

                Console.WriteLine();
                indent += "  ";
            }

            bool buildsOk = chain.Build((X509Certificate2)certificate);
            if (!buildsOk)
            {
                Console.WriteLine("Building Certificate chain failed!");
                ok = false;
            }
            foreach (var status in chain.ChainStatus)
            {
                Console.WriteLine($"Chain Status: {status.Status}, {status.StatusInformation}");
            }

            if (ok) Console.WriteLine("No errors - certificate validation passed!");
            return ok;
        }

        private static void SaveCertificatesToDisk(X509Certificate2 c, string indent){
            string filename = c.Subject.Replace("CN=", "").Replace("*", "") + ".cer";
            Console.WriteLine($"{indent}Saving Certificate public key data: {filename}");
            var certBytes = c.Export(X509ContentType.Cert);
            File.WriteAllBytes(filename, certBytes);
        }

        public static X509Certificate OnClientCertificateRequested(
            object sender, 
            string targetHost, 
            X509CertificateCollection localCertificates, 
            X509Certificate remoteCertificate, 
            string[] acceptableIssuers)
        {
            Console.WriteLine("Not using a client certificate");
            return null;
        }

    }
}

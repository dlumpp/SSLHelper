using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;

namespace SSLHelper
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: SSLHelper [hostname] [port]");
                Console.WriteLine("port defaults to 443 if not specified");
                return;
            }

            string hostname = args[0];
            int port = args.Length == 1 ? 443 : int.Parse(args[1]);

            var addr = Dns.GetHostAddresses(hostname).First();
            Console.WriteLine($"DNS resolved {hostname} to address {addr}");
            IPEndPoint remoteEP = new IPEndPoint(addr, port);

            Console.WriteLine($"Creating TCP Socket and NetworkStream");
            Socket s;
            Stream tcpStream;
            try
            {
                s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                s.Connect(remoteEP);
                tcpStream = new NetworkStream(s, ownsSocket: true);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Network Stream creation failed with {e.GetType()}: {e.ToString()}");
                return;
            }

            using (SslStream sslStream = new SslStream(tcpStream, false, SSLHelper.OnRemoteCertificateReceived, SSLHelper.OnClientCertificateRequested, EncryptionPolicy.RequireEncryption))
            {
                try
                {
                    sslStream.AuthenticateAsClient(hostname);

                    Console.WriteLine($"TransportContext: {sslStream.TransportContext}");
                    Console.WriteLine($"Protocol: {sslStream.SslProtocol}");

                    Console.WriteLine($"KeyExchangeAlgorithm: {sslStream.KeyExchangeAlgorithm}");
                    Console.WriteLine($"KeyExchangeStrength: {sslStream.KeyExchangeStrength}");

                    Console.WriteLine($"CipherAlgorithm: {sslStream.CipherAlgorithm}");
                    Console.WriteLine($"CipherStrength: {sslStream.CipherStrength}");

                    Console.WriteLine($"HashAlgorithm: {sslStream.HashAlgorithm}");
                    Console.WriteLine($"HashStrength: {sslStream.HashStrength}");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"SSL Stream creation failed with {e.GetType()}: {e.ToString()}");
                    return;
                }
            }

            Console.WriteLine("All checks passed!");
        }
    }
}

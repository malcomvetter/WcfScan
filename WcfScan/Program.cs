using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace WcfScan
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("\nWCF NET.TCP Scan\n.......");
            if (args.Count() < 1)
            {
                Console.WriteLine("ERROR: Missing endpoint URL");
                DisplayUsage();
                return;
            }
            var uri = new Uri(args[0]);
            Console.WriteLine(uri);
            if (!IsValidEndpoint(uri))
            {
                DisplayUsage();
                return;
            }
            Console.WriteLine(" - Testing binding configurations with generic contract:");
            foreach (var mode in Enum.GetValues(typeof(SecurityMode)).Cast<SecurityMode>())
            {
                try
                {
                    var address = new EndpointAddress(uri);
                    var binding = new NetTcpBinding(mode);
                    var service = new ChannelFactory<IDataAccess>(binding, address).CreateChannel();
                    var result = service.SomeOperation("blah");
                }
                catch (ActionNotSupportedException)
                {
                    //Contract mismatch, i.e. the binding config is ok, but wrong contract is specified, which is what we expect...
                    Console.WriteLine(" + Server accepted \"{0}\" security mode", mode);
                    if (mode == SecurityMode.None)
                    {
                        Console.WriteLine("***WARNING*** No authentication or transport encryption enabled on binding!");
                    }
                }
                catch (ProtocolException)
                {
                    Console.WriteLine(" - Server rejected \"{0}\" mode", mode);
                }
                catch (SecurityNegotiationException sne)
                {
                    if (sne.InnerException.InnerException.Message.ToLower().Contains("target principal"))
                    {
                        Console.WriteLine(" + Server accepted \"{0}\" security mode, but authentication failed:\n   - {1}", mode, sne.InnerException.InnerException.Message);
                    }
                    else
                    {
                        Console.WriteLine(" - Server failed to negotiate \"{0}\" mode", mode);
                    }
                }
                catch (CommunicationException)
                {
                    Console.WriteLine(" - Connection forcibly dropped in \"{0}\" mode", mode);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                }
            }
        }

        static bool IsValidEndpoint(Uri uri)
        {
            if (uri == null)
            {
                Console.WriteLine("Invalid URI");
                return false;
            }
            if (uri.Scheme != "net.tcp")// && uri.Scheme != "http" && uri.Scheme != "https")
            {
                Console.WriteLine("***ERROR*** URI scheme {0} is invalid", uri.Scheme);
                return false;
            }
            Console.WriteLine(" - URI appears valid");
            try
            {
                var ip = Dns.GetHostAddresses(uri.Host)[0];
            }
            catch (SocketException)
            {
                Console.WriteLine("***ERROR*** Host \"{0}\" not resolvable in DNS", uri.Host);
                return false;
            }
            Console.WriteLine(" - host resolves in DNS");
            try
            {
                var tcpClient = new TcpClient(uri.Host, uri.Port);
            }
            catch (Exception)
            {
                Console.WriteLine("***ERROR*** TCP port {0} on host {1} is not available", uri.Port, uri.Host);
                return false;
            }
            Console.WriteLine(" - successfully opened TCP connection to port");
            return true;
        }

        static void DisplayUsage()
        {
            Console.WriteLine("\n\nUsage: WCFScan.exe net.tcp://[host]:[port]/[path]");
            Console.WriteLine("As is, no warranty, use at own risk");
        }
    }

    [ServiceContract]
    public interface IDataAccess
    {
        [OperationContract]
        string SomeOperation(string s);
    }
}
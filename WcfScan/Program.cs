using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.ServiceModel;
using System.ServiceModel.Security;
 
namespace WcfScan
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(".......\nWCF NET.TCP Scan\n");
            if (args.Count() < 1)
            {
                Console.WriteLine("ERROR: Missing endpoint URL");
                DisplayUsage();
                return;
            }
            var uri = new Uri(args[0]);
            Console.WriteLine(uri);
            string userid = "";
            string password = "";
            try
            {
                userid = args[1];
                password = args[2];
            }
            catch { }
            string currentUser = "";
            try
            {
                currentUser = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            }
            catch
            {
                currentUser = "unknown";
            }
            if (!IsValidEndpoint(uri))
            {
                DisplayUsage();
                return;
            }
            Console.WriteLine(" + Testing with generic contract as {0}", currentUser);
 
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
                    if (mode == SecurityMode.Transport)
                    {
                        try
                        {
                            //resend without creds to verify server is authenticating:
                            var address = new EndpointAddress(uri);
                            var binding = new NetTcpBinding(mode);
                            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.None;
                            var factory = new ChannelFactory<IDataAccess>(binding, address);
                            var service = factory.CreateChannel();
                            var result = service.SomeOperation("blah");
                        }
                        catch (ActionNotSupportedException anse)
                        {
                            Console.WriteLine("***WARNING**** Server does not require authentication!", mode);
                            Console.WriteLine(anse.InnerException.Message);
                        }
                        catch (Exception)
                        {
                            Console.WriteLine("   * Server required credentials: {0}", currentUser);
                        }
                    }
                }
                catch (ProtocolException)
                {
                    Console.WriteLine(" - Server rejected \"{0}\" mode", mode);
                }
                catch (SecurityNegotiationException sne)
                {
                    if (sne.InnerException.InnerException != null &&
                        sne.InnerException.InnerException.Message.ToLower().Contains("target principal"))
                    {
                        Console.WriteLine(" + \"{0}\" security mode accepted, but rejected {1}: {2}", mode, currentUser, sne.InnerException.InnerException.Message);
                        try
                        {
                            if (mode == SecurityMode.Transport
                                && !string.IsNullOrWhiteSpace(userid)
                                && !string.IsNullOrWhiteSpace(password))
                            {
                                //try it again with specified creds
                                var address = new EndpointAddress(uri);
                                var binding = new NetTcpBinding(mode);
                                binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
                                var factory = new ChannelFactory<IDataAccess>(binding, address);
                                Console.WriteLine("   * Retrying specified credentials {0}:{1}", userid, password);
                                factory.Credentials.UserName.UserName = userid;
                                factory.Credentials.UserName.UserName = password;
                                var service = factory.CreateChannel();
                                var result = service.SomeOperation("blah");
                            }
                        }
                        catch (ActionNotSupportedException anse)
                        {
                            Console.WriteLine("   * Credentials accepted in \"{0}\" security mode.", mode);
                            Console.WriteLine(anse.InnerException.Message);
                        }
                        catch (Exception)
                        {
                            Console.WriteLine("   * Credentials rejected in \"{0}\" security mode.", mode);
                        }
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
            Console.WriteLine("\n\nUsage: WCFScan.exe net.tcp://[host]:[port]/[path] {options}");
            Console.WriteLine(" Optionally include user/password, for example: ");
            Console.WriteLine(" WCFScan.exe net.tcp://127.0.0.1:4444/service userid password");
            Console.WriteLine(" * As is, no warranty, use at own risk");
        }
    }
 
    [ServiceContract]
    public interface IDataAccess
    {
        [OperationContract]
        string SomeOperation(string s);
    }
}
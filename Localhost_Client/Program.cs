using Org.BouncyCastle.Crypto;
using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Net;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

class Client
{
    static void Main()
    {
        RunClient();
    }

    static void RunClient()
    {
        Console.WriteLine("Клієнт підключається до сервера...");

        // Завантаження клієнтського сертифіката
        var clientCertificate = new X509Certificate2("Certificates/ClientCertificate.pfx", "BestPassword", X509KeyStorageFlags.MachineKeySet);

        using var client = new TcpClient("127.0.0.1", 5000);
        using var sslStream = new SslStream(client.GetStream(), false, ValidateServerCertificate);

        sslStream.AuthenticateAsClient("ELK", new X509CertificateCollection { clientCertificate }, System.Security.Authentication.SslProtocols.Tls13, false);

        Console.WriteLine("Підключення встановлено. Відправляємо повідомлення...");

        // Відправка повідомлення
        string message = "Привіт";
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        sslStream.Write(messageBytes);
        sslStream.Flush();

        Console.WriteLine("Повідомлення відправлено.");
    }
    //Перевірка сертифіката
    static bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        if (certificate == null)
        {
            Console.WriteLine("Сертифікат сервера відсутній.");
            return false;
        }

        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            Console.WriteLine("Серверний сертифікат дійсний.");
            return true;
        }

        Console.WriteLine($"Помилки сертифіката: {sslPolicyErrors}");
        return false;
    }
}
using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

class Client
{
    static void Main()
    {
        RunClient();
    }

    static void RunClient()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("Клієнт підключається до сервера...");

        try
        {
            // Завантаження клієнтського сертифіката
            var clientCertificate = new X509Certificate2("Certificates/ClientCertificate.pfx", "BestPassword", X509KeyStorageFlags.MachineKeySet);

            using var client = new TcpClient("127.0.0.1", 5000);
            using var sslStream = new SslStream(client.GetStream(), false, ValidateServerCertificate);
            if (!File.Exists("Certificates/ClientCertificate.pfx"))
            {
                Console.WriteLine("Файл клієнтського сертифіката не знайдено.");
            }
            sslStream.AuthenticateAsClient("ELK", new X509CertificateCollection { clientCertificate }, System.Security.Authentication.SslProtocols.Tls12, false);

            Console.WriteLine("Підключення до сервера встановлено.");

            // Відправка повідомлення
            string message = "Привіт";
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            sslStream.Write(messageBytes);
            sslStream.Flush();

            Console.WriteLine("Повідомлення відправлено.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Помилка автентифікації: {ex.Message}");
            if (ex.InnerException != null)
            {
                Console.WriteLine($"Деталі: {ex.InnerException.Message}");
            }
        }
    }

    static bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        Console.WriteLine("Перевірка серверного сертифіката...");

        if (certificate == null)
        {
            Console.WriteLine("Сертифікат сервера відсутній.");
            return false;
        }

        Console.WriteLine($"Сертифікат сервера: {certificate.Subject}");

        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            Console.WriteLine("Серверний сертифікат дійсний.");
            return true;
        }

        Console.WriteLine($"Помилки сертифіката: {sslPolicyErrors}");
        if (chain != null)
        {
            foreach (var status in chain.ChainStatus)
            {
                Console.WriteLine($"Статус: {status.StatusInformation}");
            }
        }

        return false;
    }
}


using io.github.ba32107.Chrome.NativeMessaging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DownloadBlockerNativeMessagingHost
{
    internal static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            var host = new NativeMessagingHost();

            host.StartListening(jsonMessage =>
            {
                var message = JsonDocument.Parse(jsonMessage);

                var filePath = message.RootElement.GetProperty("FilePath").GetString();

                var fileMetadata = FileMetadata.CalculateFileMetadata(filePath);

                return fileMetadata;
               
            }, () =>
            {
                Environment.Exit(0);
            });

            //Application.EnableVisualStyles();
            //Application.SetCompatibleTextRenderingDefault(false);
            Application.Run();
            
        }
    }
}

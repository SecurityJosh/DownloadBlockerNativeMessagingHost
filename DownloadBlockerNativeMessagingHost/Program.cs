using io.github.ba32107.Chrome.NativeMessaging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
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

        // https://stackoverflow.com/a/58347430
        public static IEnumerable<int> IndexesOf(this byte[] haystack, byte[] needle, int startIndex = 0, bool includeOverlapping = false)
        {
            int matchIndex = haystack.AsSpan(startIndex).IndexOf(needle);
            while (matchIndex >= 0)
            {
                yield return startIndex + matchIndex;
                startIndex += matchIndex + (includeOverlapping ? 1 : needle.Length);
                matchIndex = haystack.AsSpan(startIndex).IndexOf(needle);
            }
        }
    }


}

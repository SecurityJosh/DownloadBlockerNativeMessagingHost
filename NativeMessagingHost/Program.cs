using System.Text.Json;

namespace DownloadBlockerNativeMessagingHost
{
    internal static class Program
    {

        static string? ParseFilePath(string jsonMessage)
        {
            try
            {
                var message = JsonDocument.Parse(jsonMessage);

                return message.RootElement.GetProperty("FilePath").GetString();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            var host = new io.github.ba32107.Chrome.NativeMessaging.NativeMessagingHost();

            host.StartListening(jsonMessage =>
            {
                var filePath = ParseFilePath(jsonMessage);

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

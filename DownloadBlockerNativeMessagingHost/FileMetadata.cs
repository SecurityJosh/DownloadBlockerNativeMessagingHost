using System;
using System.Text.Json.Nodes;
using System.IO;
using System.Security.Cryptography;
using System.Linq;
using System.Windows.Forms;
using System.Collections;
using System.IO.Compression;

namespace DownloadBlockerNativeMessagingHost
{
    internal class FileMetadata
    {
        static JsonObject GetDefaultJson()
        {
            return new JsonObject
                {
                    { "sha256", "Unknown"},
                    {"fileInspectionData" , new JsonObject
                        {
                            { "macros", false },
                            { "zipFileNames",  JsonValue.Create(new string[0] { })}
                        }
                    }
                };
        }
        internal static string CalculateFileMetadata(string filePath)
        {
            if (!File.Exists(filePath))
            {
                return GetDefaultJson().ToString();
            }

            try
            {
                using (FileStream fileStream = File.OpenRead(filePath))
                {
                    var macros = doesFileHaveMacros(fileStream);
                    var zipFileNames = GetZipFileNames(fileStream);

                    var jsonObject = new JsonObject {
                        { "sha256", SHA256CheckSum(fileStream)},
                        {"fileInspectionData" , new JsonObject
                            {
                                { "macros", macros },
                                { "zipFileNames",  JsonValue.Create(zipFileNames)}
                            }
                        }
                };
                    return jsonObject.ToString();
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return GetDefaultJson().ToString();
            }
        }

        private static string SHA256CheckSum(FileStream fileStream)
        {
            try
            {
                fileStream.Seek(0, SeekOrigin.Begin);
                using (SHA256 SHA256 = System.Security.Cryptography.SHA256.Create())
                {
                    return BitConverter.ToString(SHA256.ComputeHash(fileStream)).Replace("-", "").ToLowerInvariant();
                }
            }
            catch
            {
                return "Unknown";
            }
        }

        private static bool doesFileHaveExcel4Macros(FileStream fileStream) {
            /*
                // https://blog.reversinglabs.com/blog/excel-4.0-macros
                rule Excel_Macros40_String
                {
                    strings:
                        $a = { 20 45 78 63 65 6C 20 34 2E 30 00 } 
                        $b = { 00 45 78 63 65 6C 20 34 2E 30 20 }
                        $c = { 00 45 78 63 65 6C 20 34 2E 30 2D }
                        $fp = { 31 39 39 32 20 45 78 63 65 6C 20 34 2E 30 00 }
                    condition:
                        uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1 and any of ($a,$b,$c) and not $fp
                }
            */
            var compoundFileHeader = new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };

            var pattern1 = new byte[] { 0x20, 0x45, 0x78, 0x63, 0x65, 0x6C, 0x20, 0x34, 0x2E, 0x30, 0x00 }; // " Excel 4.0[NUL]"
            var pattern2 = new byte[] { 0x00, 0x45, 0x78, 0x63, 0x65, 0x6C, 0x20, 0x34, 0x2E, 0x30, 0x00 }; // "[NUL]Excel 4.0[NUL]"
            var pattern3 = new byte[] {0x00, 0x45, 0x78, 0x63, 0x65, 0x6C, 0x20, 0x34, 0x2E, 0x30, 0x2D}; // "[NUL]Excel 4.0-"
            var falsePositive = new byte[] { 0x31, 0x39, 0x39, 0x32, 0x20, 0x45, 0x78, 0x63, 0x65, 0x6C, 0x20, 0x34, 0x2E, 0x30, 0x00 }; // "1992 Excel 4.0"

            return (
                    byteSearch(fileStream, compoundFileHeader, pattern1) ||
                    byteSearch(fileStream, compoundFileHeader, pattern2) ||
                    byteSearch(fileStream, compoundFileHeader, pattern3)
                    ) && !byteSearch(fileStream, compoundFileHeader, falsePositive);
    }

    private static bool doesFileHaveOfficeMacros(FileStream fileStream)
        { 
            // https://blog.rootshell.be/2015/01/08/searching-for-microsoft-office-files-containing-macro/
            // https://isc.sans.edu/forums/diary/Malicious+Excel+Sheet+with+a+NULL+VT+Score+More+Info/26516/
            // https://www.dshield.org/forums/diary/YARA+and+CyberChef/27180/
            /*
                rule office_macro
                {
                    strings:
                        $a = {d0 cf 11 e0}
                        $b = {00 41 74 74 72 69 62 75 74 00}
                    condition:
                        $a at 0 and $b
                }
            */

            var officeHeaderBytes = new byte[] { 0xd0, 0xcf, 0x11, 0xe0 };
            var macroBytes = new byte[] {0x00, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x00}; // [NUL]Attribut[NUL]

            try
            {   
                return byteSearch(fileStream, officeHeaderBytes, macroBytes);
            }
            catch(Exception e)
            {
                MessageBox.Show(e.ToString());
                return false;
            }
        }

        private static bool doesFileHaveMacros(FileStream fileStream)
        {
            try
            {
                return doesFileHaveOfficeMacros(fileStream) || doesFileHaveExcel4Macros(fileStream);
            }
            catch
            {
                return false;
            }
            
        }

        static string[] GetZipFileNames(FileStream stream)
        {
            try
            {
                var ZIP_HEADER = new byte[] { 0x50, 0x4b };

                if(!byteSearch(stream, ZIP_HEADER, new byte[] {}, zipFileNames))
                {
                    return new string[0] { };
                }

                using (var zipArchive = new ZipArchive(stream, ZipArchiveMode.Read, true))
                {
                    return zipArchive.Entries.Select(x => x.FullName).ToArray();
                }
            }
            catch
            {
                return new string[0] { };
            }
        }

        private static dynamic byteSearch(FileStream fileStream, byte[] fileHeader, byte[] searchBytes, Func<long, byte[], Object> callback = null) {

            var results = new ArrayList();

            fileStream.Seek(0, SeekOrigin.Begin);
            
            if (fileStream.Length < fileHeader.Length + searchBytes.Length) {
                return false;
            }

            var buffer = new byte[fileHeader.Length];

            var bytesRead = fileStream.Read(buffer, 0, fileHeader.Length);

            if (!buffer.SequenceEqual(fileHeader))
            {
                return false;
            }

            if(searchBytes.Length == 0)
            {
                // We're just checking the file header, not any content bytes
                return true;
            }

            buffer = new byte[fileStream.Length - fileHeader.Length];
            fileStream.Read(buffer, 0, (int)(fileStream.Length - fileHeader.Length));

            var indexes = buffer.IndexesOf(searchBytes, 0, true);

            if(callback == null)
            {
                return true;
            }

            foreach(int index in indexes)
            {
                var result = callback(index, buffer);

                if (result != null)
                {
                    results.Add(result);
                }
            }

            return results;
        }
        
        private static string[] extractZipFileNames(FileStream fileStream) {
            var ZIP_HEADER = new byte[] { 0x50, 0x4b };
            var START_OF_CENTRAL_DIRECTORY = new byte[] { 0x50, 0x4b, 0x01, 0x02 };

            try
            {
                var fileNames = (ArrayList)byteSearch(fileStream, ZIP_HEADER, START_OF_CENTRAL_DIRECTORY, zipFileNames);

                if (fileNames?.Count == 0)
                {
                    return new string[] { };
                }
                return fileNames.Cast<string>().ToArray();
            }
            catch
            {
                return new string[] { };
            }
        }

        private static dynamic zipFileNames(long fileOffset, byte[] fileBytes) {
            var startOfRecordIndex = fileOffset;
            const int FILE_NAME_LENGTH_OFFSET = 28;
            const int FILE_NAME_OFFSET = 46;
            if (fileBytes.Length <= startOfRecordIndex + FILE_NAME_LENGTH_OFFSET + 1) {
                return false;
            }

            var fileNameLengthStartByte = startOfRecordIndex + FILE_NAME_LENGTH_OFFSET;

            long fileNameLength = fileBytes[fileNameLengthStartByte] + (256 * fileBytes[fileNameLengthStartByte + 1]);

            var fileNameStartByte = startOfRecordIndex + FILE_NAME_OFFSET;

            var fileNameBuffer = new byte[fileNameLength];

            Array.Copy(fileBytes, fileNameStartByte, fileNameBuffer, 0, fileNameLength);

            var fileName = System.Text.Encoding.UTF8.GetString(fileNameBuffer, 0, fileNameBuffer.Length);
            return fileName;
        }
    }
}

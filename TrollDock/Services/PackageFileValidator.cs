using System.IO;
using System.IO.Compression;
using System.Text.RegularExpressions;

namespace TrollDock.Services;

public static class PackageFileValidator
{
    public static void Validate(string path, bool deb)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length == 0) throw new IOException("Выбран пустой файл.");
        if (deb)
        {
            if (stream.Length < 8) throw new IOException("Файл не похож на DEB-пакет.");
            Span<byte> magic = stackalloc byte[8];
            stream.ReadExactly(magic);
            if (!magic.SequenceEqual("!<arch>\n"u8)) throw new IOException("Файл не похож на DEB-пакет.");
        }
        else
        {
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
            if (!zip.Entries.Any(e => Regex.IsMatch(e.FullName, @"^Payload/[^/]+\.app/Info\.plist$")))
                throw new IOException("В IPA не найдено приложение Payload/*.app. Выберите корректный IPA-файл.");
        }
    }
}

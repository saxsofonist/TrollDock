using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace TrollDock.Services;

public sealed record IpaMetadata(string BundleIdentifier, string Version, string Name, long UnpackedBytes, IReadOnlyList<string> ExtensionIdentifiers);

public static class IpaInspection
{
    public static IpaMetadata Read(string path)
    {
        using var archive = ZipFile.OpenRead(path);
        if (archive.Entries.Count > 300000) throw new IOException("В IPA слишком много файлов.");
        long unpacked = 0;
        var entries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var directories = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in archive.Entries)
        {
            var name = entry.FullName;
            if (name.StartsWith('/') || name.Contains('\\') || name.Contains(':') || name.Split('/').Any(s => s is ".." or ".")
                || ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000)
                throw new IOException("IPA содержит небезопасный путь или символическую ссылку. Выберите обычный IPA-архив.");
            var normalized = name.TrimEnd('/'); var segments = normalized.Split('/');
            if (segments.Any(s => s.Length == 0 || s.EndsWith(' ') || s.EndsWith('.') || s.Any(c => char.IsControl(c) || "<>\"|?*".Contains(c))
                || Regex.IsMatch(s, @"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)))
                throw new IOException("IPA содержит имя файла, небезопасное для распаковки в Windows.");
            if (!entries.Add(normalized)) throw new IOException("В IPA есть повторяющиеся пути файлов, включая различия только в регистре букв.");
            var isDirectory = name.EndsWith('/');
            if (!isDirectory && directories.ContainsKey(normalized)) throw new IOException("В IPA конфликтуют пути файла и папки.");
            if (!isDirectory) files.Add(normalized);
            for (int length = 1; length <= segments.Length - (isDirectory ? 0 : 1); length++)
            {
                var parent = string.Join('/', segments.Take(length));
                if (files.Contains(parent)) throw new IOException("В IPA конфликтуют пути файла и папки.");
                if (directories.TryGetValue(parent, out var spelling) && spelling != parent) throw new IOException("В IPA есть неоднозначные имена папок для Windows.");
                directories[parent] = parent;
            }
            unpacked = checked(unpacked + entry.Length);
        }
        var infoFiles = archive.Entries.Where(e => Regex.IsMatch(e.FullName, @"^Payload/[^/]+\.app/Info\.plist$")).ToArray();
        if (infoFiles.Length != 1) throw new IOException("В IPA должно быть одно основное приложение Payload/*.app.");
        var info = ReadInfo(infoFiles[0]);
        var id = GetString(info, "CFBundleIdentifier");
        if (!Regex.IsMatch(id, @"^[A-Za-z0-9][A-Za-z0-9.\-]{0,254}$")) throw new IOException("Некорректный идентификатор приложения в IPA.");
        var mainDirectory = infoFiles[0].FullName[..^"Info.plist".Length];
        var extensionIds = archive.Entries.Where(e => e.FullName.StartsWith(mainDirectory, StringComparison.Ordinal)
                && Regex.IsMatch(e.FullName[mainDirectory.Length..], @"^(?:[^/]+/)*[^/]+\.(?:app|appex)/Info\.plist$"))
            .Select(e => GetString(ReadInfo(e), "CFBundleIdentifier")).ToArray();
        if (extensionIds.Any(value => !Regex.IsMatch(value, @"^[A-Za-z0-9][A-Za-z0-9.\-]{0,254}$")))
            throw new IOException("Некорректный идентификатор вложенного приложения в IPA.");
        return new(id, GetString(info, "CFBundleVersion"), GetString(info, "CFBundleDisplayName", GetString(info, "CFBundleName", id)), unpacked, extensionIds);
    }
    private static string GetString(Dictionary<string, object?> info, string key, string fallback = "") => info.TryGetValue(key, out var value) ? value as string ?? fallback : fallback;
    private static Dictionary<string, object?> ReadInfo(ZipArchiveEntry entry)
    {
        if (entry.Length is < 1 or > 8 * 1024 * 1024) throw new IOException("Слишком большой или пустой Info.plist.");
        using var input = entry.Open(); using var buffer = new MemoryStream(); input.CopyTo(buffer);
        var bytes = buffer.ToArray();
        if (bytes.AsSpan().StartsWith("bplist00"u8)) return BinaryPlist.Read(bytes);
        using var reader = XmlReader.Create(new MemoryStream(bytes), new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, MaxCharactersInDocument = 8 * 1024 * 1024 });
        var dict = XDocument.Load(reader).Root?.Element("dict") ?? throw new IOException("Повреждён Info.plist.");
        var elements = dict.Elements().ToArray(); var result = new Dictionary<string, object?>();
        for (int i = 0; i + 1 < elements.Length; i += 2) if (elements[i].Name.LocalName == "key") result[elements[i].Value] = elements[i + 1].Value;
        return result;
    }

    private sealed class BinaryPlist(byte[] bytes)
    {
        private int offsetSize, referenceSize;
        private ulong count, offsetTable;
        private readonly HashSet<ulong> active = [];
        public static Dictionary<string, object?> Read(byte[] bytes)
        {
            try
            {
                if (bytes.Length < 40) throw new IOException("Invalid binary plist.");
                var parser = new BinaryPlist(bytes); var trailer = bytes.AsSpan(bytes.Length - 32);
                parser.offsetSize = trailer[6]; parser.referenceSize = trailer[7];
                parser.count = BinaryPrimitives.ReadUInt64BigEndian(trailer[8..]);
                var top = BinaryPrimitives.ReadUInt64BigEndian(trailer[16..]); parser.offsetTable = BinaryPrimitives.ReadUInt64BigEndian(trailer[24..]);
                if (parser.offsetSize is < 1 or > 8 || parser.referenceSize is < 1 or > 8 || parser.count > 100000) throw new IOException("Invalid binary plist trailer.");
                return parser.Object(top, 0) as Dictionary<string, object?> ?? throw new IOException("Expected plist dictionary.");
            }
            catch (Exception ex) when (ex is ArgumentException or OverflowException or IndexOutOfRangeException) { throw new IOException("Повреждён бинарный Info.plist.", ex); }
        }
        private ulong Number(ulong at, int size)
        {
            if (size is < 1 or > 8 || at > (ulong)bytes.Length || (ulong)size > (ulong)bytes.Length - at) throw new IOException("Invalid binary plist offset.");
            ulong n = 0; for (int i = 0; i < size; i++) n = (n << 8) | bytes[(int)at + i]; return n;
        }
        private object? Object(ulong reference, int depth)
        {
            if (reference >= count || depth > 30 || !active.Add(reference)) throw new IOException("Invalid binary plist references.");
            try
            {
                var p = Number(checked(offsetTable + reference * (ulong)offsetSize), offsetSize);
                var marker = (byte)Number(p++, 1); int kind = marker >> 4; ulong length = (uint)(marker & 15);
                if (kind is 4 or 5 or 6 or 10 or 13)
                {
                    if (length == 15) { var sizeMarker = (byte)Number(p++, 1); if ((sizeMarker >> 4) != 1 || (sizeMarker & 15) > 3) throw new IOException("Invalid plist length."); var size = 1 << (sizeMarker & 15); length = Number(p, size); p += (ulong)size; }
                    if (length > 8 * 1024 * 1024) throw new IOException("Invalid plist length.");
                }
                switch (kind)
                {
                    case 5: return Encoding.ASCII.GetString(bytes, checked((int)p), checked((int)length));
                    case 6: return Encoding.BigEndianUnicode.GetString(bytes, checked((int)p), checked((int)length * 2));
                    case 13:
                        if (length > 100000) throw new IOException("Invalid plist dictionary.");
                        var result = new Dictionary<string, object?>();
                        for (ulong i = 0; i < length; i++)
                        {
                            var key = Object(Number(checked(p + i * (ulong)referenceSize), referenceSize), depth + 1) as string ?? throw new IOException("Invalid plist key.");
                            result[key] = Object(Number(checked(p + (length + i) * (ulong)referenceSize), referenceSize), depth + 1);
                        }
                        return result;
                    // Values outside the fields we need can be skipped without decoding their payload.
                    default: return null;
                }
            }
            finally { active.Remove(reference); }
        }
    }
}

using System;
using System.Security.Cryptography;
using System.Text;

// SRun bx1 wire-format codec, implemented for the SZU public-area portal.
// Inputs use JavaScript UTF-16 code units, matching the portal's JSON.stringify
// and word-packing routine, rather than silently converting the info to UTF-8.
public static class SzuSrunCodec
{
    private const string Standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private const string Srun = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

    private static string Quote(string text)
    {
        StringBuilder value = new StringBuilder("\"");
        for (int i = 0; i < text.Length; i++)
        {
            char ch = text[i];
            switch (ch)
            {
                case '\"': value.Append("\\\""); break;
                case '\\': value.Append("\\\\"); break;
                case '\b': value.Append("\\b"); break;
                case '\f': value.Append("\\f"); break;
                case '\n': value.Append("\\n"); break;
                case '\r': value.Append("\\r"); break;
                case '\t': value.Append("\\t"); break;
                default:
                    if (ch < 32 || (char.IsSurrogate(ch) &&
                        !(char.IsHighSurrogate(ch) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))))
                        value.Append("\\u").Append(((int)ch).ToString("x4"));
                    else
                    {
                        value.Append(ch);
                        if (char.IsHighSurrogate(ch)) value.Append(text[++i]);
                    }
                    break;
            }
        }
        return value.Append('"').ToString();
    }

    public static string BuildInfo(string username, string password, string ip, string acid)
    {
        // Windows PowerShell 5.1's ConvertTo-Json HTML-escapes '&'. Match the
        // browser's exact JSON.stringify representation before bx1 encoding.
        return "{\"username\":" + Quote(username) + ",\"password\":" + Quote(password) +
            ",\"ip\":" + Quote(ip) + ",\"acid\":" + Quote(acid) + ",\"enc_ver\":\"srun_bx1\"}";
    }

    private static uint[] Pack(string text, bool includeLength)
    {
        int count = (text.Length + 3) / 4;
        uint[] words = new uint[count + (includeLength ? 1 : 0)];
        for (int i = 0; i < text.Length; i++)
            words[i / 4] |= (uint)text[i] << ((i % 4) * 8);
        if (includeLength) words[count] = (uint)text.Length;
        return words;
    }

    public static string EncodeInfo(string json, string token)
    {
        if (json == null || token == null) throw new ArgumentNullException();
        if (json.Length == 0) return "{SRBX1}";
        uint[] words = Pack(json, true);
        uint[] key = Pack(token, false);
        if (key.Length < 4) Array.Resize(ref key, 4);
        int last = words.Length - 1;
        uint z = words[last], y, sum = 0;
        int rounds = 6 + 52 / words.Length;
        unchecked
        {
            for (int round = 0; round < rounds; round++)
            {
                sum += 0x9E3779B9;
                uint selector = (sum >> 2) & 3;
                for (int index = 0; index < words.Length; index++)
                {
                    y = words[index == last ? 0 : index + 1];
                    uint mix = (z >> 5) ^ (y << 2);
                    mix += (y >> 3) ^ (z << 4) ^ (sum ^ y);
                    mix += key[((uint)index & 3) ^ selector] ^ z;
                    z = words[index] += mix;
                }
            }
        }
        byte[] data = new byte[words.Length * 4];
        for (int i = 0; i < words.Length; i++)
            for (int shift = 0; shift < 4; shift++)
                data[i * 4 + shift] = (byte)(words[i] >> (shift * 8));
        char[] encoded = Convert.ToBase64String(data).ToCharArray();
        for (int i = 0; i < encoded.Length; i++)
        {
            int index = Standard.IndexOf(encoded[i]);
            if (index >= 0) encoded[i] = Srun[index];
        }
        return "{SRBX1}" + new string(encoded);
    }

    private static string Hex(byte[] bytes)
    {
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }

    public static string PasswordDigest(string password, string token)
    {
        using (HMACMD5 hash = new HMACMD5(Encoding.UTF8.GetBytes(token)))
            return Hex(hash.ComputeHash(Encoding.UTF8.GetBytes(password)));
    }

    public static string Checksum(string value)
    {
        using (SHA1 hash = SHA1.Create())
            return Hex(hash.ComputeHash(Encoding.UTF8.GetBytes(value)));
    }
}

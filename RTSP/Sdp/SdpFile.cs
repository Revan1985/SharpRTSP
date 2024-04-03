using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace Rtsp.Sdp
{
    public class SdpFile
    {
        private static KeyValuePair<char, string> GetKeyValue(TextReader sdpStream)
        {
            string? line = sdpStream.ReadLine();

            // end of file ?
            if (string.IsNullOrEmpty(line))
                return new('\0', string.Empty);

            string[] parts = line.Split('=', 2);
            if (parts.Length != 2)
                throw new InvalidDataException();
            if (parts[0].Length != 1)
                throw new InvalidDataException();

            return new(parts[0][0], parts[1]);
        }

        /// <summary>
        /// Reads the specified SDP stream.
        /// As define in RFC 4566
        /// </summary>
        /// <param name="sdpStream">The SDP stream.</param>
        /// <param name="strictParsing">if set to <c>false</c> accept some error seen with camera.</param>
        /// <returns>Parsed SDP file</returns>
// Hard to make shorter
#pragma warning disable MA0051 // Method is too long
        public static SdpFile Read(TextReader sdpStream, bool strictParsing = false)
#pragma warning restore MA0051 // Method is too long
        {
            SdpFile returnValue = new();
            KeyValuePair<char, string> value;   //= GetKeyValue(sdpStream);

            while ((value = GetKeyValue(sdpStream)).Key != '\0')
            {

                switch (value.Key)
                {
                    case 'v':
                        {
                            returnValue.Version = int.Parse(value.Value, CultureInfo.InvariantCulture);
                        }
                        break;
                    case 'o':
                        {
                            returnValue.Origin = Origin.Parse(value.Value);
                        }
                        break;
                    case 's':
                        {
                            returnValue.Session = value.Value;
                        }
                        break;
                    case 'i':
                        {
                            returnValue.SessionInformation = value.Value;
                        }
                        break;
                    case 'u':
                        {
                            try
                            {
                                returnValue.Url = new Uri(value.Value);
                            }
                            catch (UriFormatException err)
                            {
                                /* skip if cannot parse, some cams returns empty or invalid values for optional ones */
                                if (strictParsing)
                                    throw new InvalidDataException($"uri value invalid {value.Value}", err);
                            }
                        }
                        break;
                    case 'e':
                        {
                            returnValue.Email = value.Value;
                        }
                        break;
                    case 'p':
                        {
                            returnValue.Phone = value.Value;
                        }
                        break;
                    case 'c':
                        {
                            returnValue.Connection = Connection.Parse(value.Value);
                        }
                        break;
                    case 'b':
                        {
                            returnValue.Bandwidth = Bandwidth.Parse(value.Value);
                        }
                        break;
                    case 't':
                        {
                            string timing = value.Value;
                            returnValue.Timings.Add(Timing.Parse(timing));
                        }
                        break;
                    case 'r':
                        {
                            // todo...
                        }
                        break;
                    case 'z':
                        {
                            returnValue.TimeZone = SdpTimeZone.ParseInvariant(value.Value);
                        }
                        break;
                    case 'a':
                        {
                            returnValue.Attributs.Add(Attribut.ParseInvariant(value.Value));
                        }
                        break;
                    case 'm':
                        {
                            while (value.Key == 'm')
                            {
                                Media newMedia = ReadMedia(sdpStream, ref value);
                                returnValue.Medias.Add(newMedia);
                            }
                        }
                        break;
                }
            }

            if (returnValue.Version == -1) { throw new InvalidDataException("version missing"); }
            if (returnValue.Origin is null) { throw new InvalidDataException("origin missing"); }
            if (string.IsNullOrEmpty(returnValue.Session) && strictParsing) { throw new InvalidDataException("session missing"); }
            if (returnValue.Medias.Count == 0) { throw new InvalidDataException("media information(s) missing"); }

            return returnValue;
        }

        private static Media ReadMedia(TextReader sdpStream, ref KeyValuePair<char, string> value)
        {
            Media returnValue = new(value.Value);
            value = GetKeyValue(sdpStream);

            // Media title
            if (value.Key == 'i')
            {
                value = GetKeyValue(sdpStream);
            }

            // Connexion optional and multiple in media
            while (value.Key == 'c')
            {
                returnValue.Connections.Add(Connection.Parse(value.Value));
                value = GetKeyValue(sdpStream);
            }

            // bandwidth optional multiple value possible
            while (value.Key == 'b')
            {
                returnValue.Bandwidths.Add(Bandwidth.Parse(value.Value));
                value = GetKeyValue(sdpStream);
            }

            // encryption key optional
            if (value.Key == 'k')
            {
                // Obsolete in RFC 8866 ignored
                value = GetKeyValue(sdpStream);
            }

            //Attribut optional multiple
            while (value.Key == 'a')
            {
                returnValue.Attributs.Add(Attribut.ParseInvariant(value.Value));
                value = GetKeyValue(sdpStream);
            }

            return returnValue;
        }

        public int Version { get; set; } = -1;

        public Origin? Origin { get; set; }

        public string? Session { get; set; }

        public string? SessionInformation { get; set; }

        public Uri? Url { get; set; }

        public string? Email { get; set; }

        public string? Phone { get; set; }

        public Connection? Connection { get; set; }

        public Bandwidth? Bandwidth { get; set; }

        public IList<Timing> Timings { get; } = [];

        public SdpTimeZone? TimeZone { get; set; }

        public IList<Attribut> Attributs { get; } = [];

        public IList<Media> Medias { get; } = [];
    }
}

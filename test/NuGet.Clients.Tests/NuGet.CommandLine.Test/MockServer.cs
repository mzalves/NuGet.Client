﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace NuGet.CommandLine.Test
{
    /// <summary>
    /// A Mock Server that is used to mimic a NuGet Server.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1001:TypesThatOwnDisposableFieldsShouldBeDisposable")]
    public class MockServer : IDisposable
    {
        public HttpListener Listener { get; }
        private PortReserver PortReserver { get; }

        private Task _listenerTask;
        private bool _disposed = false;

        /// <summary>
        /// Initializes an instance of MockServer.
        /// </summary>
        public MockServer()
        {
            PortReserver = new PortReserver();

            // tests that cancel downloads and exit will cause the mock server to throw, this should be ignored.
            Listener = new HttpListener()
            {
                IgnoreWriteExceptions = true
            };

            Listener.Prefixes.Add(PortReserver.BaseUri);
        }

        public RouteTable Get { get; } = new RouteTable();

        public RouteTable Put { get; } = new RouteTable();

        public RouteTable Delete { get; } = new RouteTable();

        public string Uri { get { return PortReserver.BaseUri; } }

        /// <summary>
        /// Starts the mock server.
        /// </summary>
        public void Start()
        {
            Listener.Start();
            _listenerTask = Task.Factory.StartNew(() => HandleRequest());
        }

        /// <summary>
        /// Stops the mock server.
        /// </summary>
        public void Stop()
        {
            try
            {
                Listener.Abort();

                var task = _listenerTask;
                _listenerTask = null;

                if (task != null)
                {
                    task.Wait();
                }
            }
            catch (Exception ex)
            {
                Debug.Fail(ex.ToString());
            }
        }

        /// <summary>
        /// Gets the pushed package from a nuget push request.
        /// </summary>
        /// <param name="r">The request generated by nuget push command.</param>
        /// <returns>The content of the package that is pushed.</returns>
        public static byte[] GetPushedPackage(HttpListenerRequest r)
        {
            byte[] buffer;
            using (var memoryStream = new MemoryStream())
            {
                r.InputStream.CopyTo(memoryStream);
                buffer = memoryStream.ToArray();
            }

            byte[] result = new byte[] { };
            var multipartContentType = "multipart/form-data; boundary=";
            if (!r.ContentType.StartsWith(multipartContentType, StringComparison.Ordinal))
            {
                return result;
            }
            var boundary = r.ContentType.Substring(multipartContentType.Length);
            byte[] delimiter = Encoding.UTF8.GetBytes("\r\n--" + boundary);
            int bodyStartIndex = Find(buffer, 0, new byte[] { 0x0d, 0x0a, 0x0d, 0x0a });
            if (bodyStartIndex == -1)
            {
                return result;
            }
            else
            {
                bodyStartIndex += 4;
            }

            int bodyEndIndex = Find(buffer, 0, delimiter);
            if (bodyEndIndex == -1)
            {
                //Patch, to deal with new binary format coming with the HttpClient
                //from dnxcore50. The right way should use existing libraries with
                //multi-part parsers
                byte[] delimiter2 = Encoding.UTF8.GetBytes("\r\n--");
                bodyEndIndex = Find(buffer, 0, delimiter2);
                if (bodyEndIndex == -1)
                {
                    return result;
                }
            }

            result = buffer.Skip(bodyStartIndex).Take(bodyEndIndex - bodyStartIndex).ToArray();
            return result;
        }

        /// <summary>
        /// Returns the index of the first occurrence of <paramref name="pattern"/> in
        /// <paramref name="buffer"/>. The search starts at a specified position.
        /// </summary>
        /// <param name="buffer">The buffer to search.</param>
        /// <param name="startIndex">The search start position.</param>
        /// <param name="pattern">The pattern to search.</param>
        /// <returns>The index position of <paramref name="pattern"/> if it is found in buffer, or -1
        /// if not.</returns>
        private static int Find(byte[] buffer, int startIndex, byte[] pattern)
        {
            for (int s = startIndex; s + pattern.Length <= buffer.Length; ++s)
            {
                if (StartsWith(buffer, s, pattern))
                {
                    return s;
                }
            }

            return -1;
        }

        /// <summary>
        /// Determines if the subset of <paramref name="buffer"/> starting at
        /// <paramref name="startIndex"/> starts with <paramref name="pattern"/>.
        /// </summary>
        /// <param name="buffer">The buffer to check.</param>
        /// <param name="startIndex">The start index of the subset to check.</param>
        /// <param name="pattern">The pattern to search.</param>
        /// <returns>True if the subset starts with the pattern; otherwise, false.</returns>
        private static bool StartsWith(byte[] buffer, int startIndex, byte[] pattern)
        {
            if (startIndex + pattern.Length > buffer.Length)
            {
                return false;
            }

            for (int i = 0; i < pattern.Length; ++i)
            {
                if (buffer[startIndex + i] != pattern[i])
                {
                    return false;
                }
            }

            return true;
        }

        public static void SetResponseContent(HttpListenerResponse response, byte[] content)
        {
            // The client should not cache data between mock server calls
            response.AddHeader("Cache-Control", "no-cache, no-store");

            response.ContentLength64 = content.Length;

            try
            {
                response.OutputStream.Write(content, 0, content.Length);
            }
            catch (HttpListenerException)
            {
                // Listener exceptions may occur if the client drops the connection
            }
        }

        public static void SetResponseContent(HttpListenerResponse response, string text)
        {
            SetResponseContent(response, System.Text.Encoding.UTF8.GetBytes(text));
        }

        void SetResponseNotFound(HttpListenerResponse response)
        {
            response.StatusCode = (int)HttpStatusCode.NotFound;
            SetResponseContent(response, "404 not found");
        }

        void GenerateResponse(HttpListenerContext context)
        {
            var request = context.Request;
            HttpListenerResponse response = context.Response;
            try
            {
                RouteTable m = null;
                if (request.HttpMethod == "GET")
                {
                    m = Get;
                }
                else if (request.HttpMethod == "PUT")
                {
                    m = Put;
                }
                else if (request.HttpMethod == "DELETE")
                {
                    m = Delete;
                }

                if (m == null)
                {
                    SetResponseNotFound(response);
                }
                else
                {
                    var f = m.Match(request);
                    if (f != null)
                    {
                        var r = f(request);
                        if (r is string)
                        {
                            SetResponseContent(response, (string)r);
                        }
                        else if (r is Action<HttpListenerResponse>)
                        {
                            var action = (Action<HttpListenerResponse>)r;
                            action(response);
                        }
                        else if (r is Action<HttpListenerResponse, IPrincipal>)
                        {
                            var action = (Action<HttpListenerResponse, IPrincipal>)r;
                            action(response, context.User);
                        }
                        else if (r is int || r is HttpStatusCode)
                        {
                            response.StatusCode = (int)r;
                        }
                    }
                    else
                    {
                        SetResponseNotFound(response);
                    }
                }
            }
            finally
            {
                response.OutputStream.Close();
            }
        }

        void HandleRequest()
        {
            const int ERROR_OPERATION_ABORTED = 995;
            const int ERROR_INVALID_HANDLE = 6;
            const int ERROR_INVALID_FUNCTION = 1;

            while (true)
            {
                try
                {
                    var context = Listener.GetContext();
                    GenerateResponse(context);
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                catch (HttpListenerException ex)
                {
                    if (ex.ErrorCode == ERROR_OPERATION_ABORTED ||
                        ex.ErrorCode == ERROR_INVALID_HANDLE ||
                        ex.ErrorCode == ERROR_INVALID_FUNCTION)
                    {
                        return;
                    }
                    else
                    {
                        Console.WriteLine("Unexpected error code: {0}. Ex: {1}", ex.ErrorCode, ex);
                        throw;
                    }
                }
            }
        }

        /// <summary>
        /// Creates OData feed from the list of packages.
        /// </summary>
        /// <param name="packages">The list of packages.</param>
        /// <param name="title">The title of the feed.</param>
        /// <returns>The string representation of the created OData feed.</returns>
        public string ToODataFeed(IEnumerable<IPackage> packages, string title)
        {
            string nsAtom = "http://www.w3.org/2005/Atom";
            var id = string.Format(CultureInfo.InvariantCulture, "{0}{1}", Uri, title);
            XDocument doc = new XDocument(
                new XElement(XName.Get("feed", nsAtom),
                    new XElement(XName.Get("id", nsAtom), id),
                    new XElement(XName.Get("title", nsAtom), title)));

            foreach (var p in packages)
            {
                doc.Root.Add(ToODataEntryXElement(p));
            }

            return doc.ToString();
        }

        /// <summary>
        /// Creates an OData entry XElement representation of the package.
        /// </summary>
        /// <param name="package">The package.</param>
        /// <returns>The OData entry XElement.</returns>
        private XElement ToODataEntryXElement(IPackage package)
        {
            string nsAtom = "http://www.w3.org/2005/Atom";
            XNamespace nsDataService = "http://schemas.microsoft.com/ado/2007/08/dataservices";
            string nsMetadata = "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata";
            string downloadUrl = string.Format(
                CultureInfo.InvariantCulture,
                "{0}package/{1}/{2}", Uri, package.Id, package.Version);
            string entryId = string.Format(
                CultureInfo.InvariantCulture,
                "{0}Packages(Id='{1}',Version='{2}')",
                Uri, package.Id, package.Version);

            var entry = new XElement(XName.Get("entry", nsAtom),
                new XAttribute(XNamespace.Xmlns + "d", nsDataService.ToString()),
                new XAttribute(XNamespace.Xmlns + "m", nsMetadata.ToString()),
                new XElement(XName.Get("id", nsAtom), entryId),
                new XElement(XName.Get("title", nsAtom), package.Id),
                new XElement(XName.Get("content", nsAtom),
                    new XAttribute("type", "application/zip"),
                    new XAttribute("src", downloadUrl)),
                new XElement(XName.Get("properties", nsMetadata),
                    new XElement(nsDataService + "Version", package.Version),
                    new XElement(nsDataService + "PackageHash", package.GetHash("SHA512")),
                    new XElement(nsDataService + "PackageHashAlgorithm", "SHA512"),
                    new XElement(nsDataService + "Description", package.Description),
                    new XElement(nsDataService + "Listed", package.Listed)));
            return entry;
        }

        public string ToOData(IPackage package)
        {
            XDocument doc = new XDocument(ToODataEntryXElement(package));
            return doc.ToString();
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                // Closing the http listener
                Stop();

                // Disposing the PortReserver
                PortReserver.Dispose();

                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Represents the route table of the mock server.
    /// </summary>
    /// <remarks>
    /// The return type of a request handler could be:
    /// - string: the string will be sent back as the response content, and the response
    ///           status code is OK.
    /// - HttpStatusCode: the value is returned as the response status code.
    /// - Action&lt;HttpListenerResponse&gt;: The action will be called to construct the response.
    /// </remarks>
    public class RouteTable
    {
        List<Tuple<string, Func<HttpListenerRequest, object>>> _mappings;

        public RouteTable()
        {
            _mappings = new List<Tuple<string, Func<HttpListenerRequest, object>>>();
        }

        public void Add(string pattern, Func<HttpListenerRequest, object> f)
        {
            _mappings.Add(new Tuple<string, Func<HttpListenerRequest, object>>(pattern, f));
        }

        public Func<HttpListenerRequest, object> Match(HttpListenerRequest r)
        {
            foreach (var m in _mappings)
            {
                if (r.Url.AbsolutePath.StartsWith(m.Item1, StringComparison.Ordinal))
                {
                    return m.Item2;
                }
            }

            return null;
        }
    }
}

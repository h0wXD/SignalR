//------------------------------------------------------------------------------
// <copyright file="ClientWebSocket.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

namespace System.Net.WebSockets
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Diagnostics.Contracts;
    using System.Globalization;
    using System.Net;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    public sealed class HeaderClientWebSocket : WebSocket
    {
        private readonly HeaderClientWebSocketOptions options;
        private WebSocket innerWebSocket;
        private readonly CancellationTokenSource cts;

        // Stages of this class. Interlocked doesn't support enums.
        private int state;
        private const int created = 0;
        private const int connecting = 1;
        private const int connected = 2;
        private const int disposed = 3;

        static HeaderClientWebSocket()
        {
            // Register ws: and wss: with WebRequest.Register so that WebRequest.Create returns a
            // WebSocket capable HttpWebRequest instance.
            WebSocket.RegisterPrefixes();
        }

        public HeaderClientWebSocket()
        {
            state = created;
            options = new HeaderClientWebSocketOptions();
            cts = new CancellationTokenSource();
        }

        #region Properties

        public HeaderClientWebSocketOptions Options { get { return options; } }

        public override WebSocketCloseStatus? CloseStatus
        {
            get
            {
                if (innerWebSocket != null)
                {
                    return innerWebSocket.CloseStatus;
                }
                return null;
            }
        }

        public override string CloseStatusDescription
        {
            get
            {
                if (innerWebSocket != null)
                {
                    return innerWebSocket.CloseStatusDescription;
                }
                return null;
            }
        }

        public override string SubProtocol
        {
            get
            {
                if (innerWebSocket != null)
                {
                    return innerWebSocket.SubProtocol;
                }
                return null;
            }
        }

        public override WebSocketState State
        {
            get
            {
                // state == Connected or Disposed
                if (innerWebSocket != null)
                {
                    return innerWebSocket.State;
                }
                switch (state)
                {
                    case created:
                        return WebSocketState.None;
                    case connecting:
                        return WebSocketState.Connecting;
                    case disposed: // We only get here if disposed before connecting
                        return WebSocketState.Closed;
                    default:
                        Contract.Assert(false, "NotImplemented: " + state);
                        return WebSocketState.Closed;
                }
            }
        }

        #endregion Properties

        public Task ConnectAsync(Uri uri, CancellationToken cancellationToken)
        {
            if (uri == null)
            {
                throw new ArgumentNullException("uri");
            }
            if (!uri.IsAbsoluteUri)
            {
                throw new ArgumentException("net_uri_NotAbsolute");
            }
            if (String.IsNullOrWhiteSpace(uri.Scheme) || (!uri.Scheme.Equals("ws", StringComparison.OrdinalIgnoreCase) && !uri.Scheme.Equals("wss", StringComparison.OrdinalIgnoreCase)))
            {
                throw new ArgumentException("net_WebSockets_Scheme");
            }

            // Check that we have not started already
            int priorState = Interlocked.CompareExchange(ref state, connecting, created);
            if (priorState == disposed)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }
            else if (priorState != created)
            {
                throw new InvalidOperationException("net_WebSockets_AlreadyStarted");
            }
            options.SetToReadOnly();

            return ConnectAsyncCore(uri, cancellationToken);
        }

        private async Task ConnectAsyncCore(Uri uri, CancellationToken cancellationToken)
        {
            HttpWebResponse response = null;
            CancellationTokenRegistration connectCancellation = new CancellationTokenRegistration();
            // Any errors from here on out are fatal and this instance will be disposed.
            try
            {
                HttpWebRequest request = CreateAndConfigureRequest(uri);

                connectCancellation = cancellationToken.Register(AbortRequest, request, false);

                response = await request.GetResponseAsync().ConfigureAwait(false) as HttpWebResponse;
                Contract.Assert(response != null, "Not an HttpWebResponse");

                string subprotocol = ValidateResponse(request, response);

                innerWebSocket = WebSocket.CreateClientWebSocket(response.GetResponseStream(), subprotocol,
                    options.ReceiveBufferSize, options.SendBufferSize, options.KeepAliveInterval, false,
                    options.GetOrCreateBuffer());

                // Change internal state to 'connected' to enable the other methods
                if (Interlocked.CompareExchange(ref state, connected, connecting) != connecting)
                {
                    // Aborted/Disposed during connect.
                    throw new ObjectDisposedException(GetType().FullName);
                }
            }
            catch (WebException ex)
            {
                ConnectExceptionCleanup(response);
                WebSocketException wex = new WebSocketException("net_webstatus_ConnectFailure", ex);
                throw wex;
            }
            catch (Exception)
            {
                ConnectExceptionCleanup(response);
                throw;
            }
            finally
            {
                // We successfully connected (or failed trying), disengage from this token.
                // Otherwise any timeout/cancellation would apply to the full session.
                // In the failure case we need to release the reference to HWR.
                connectCancellation.Dispose();
            }
        }

        private void ConnectExceptionCleanup(HttpWebResponse response)
        {
            Dispose();
            if (response != null)
            {
                response.Dispose();
            }
        }

        private HttpWebRequest CreateAndConfigureRequest(Uri uri)
        {
            HttpWebRequest request = WebRequest.Create(uri) as HttpWebRequest;
            if (request == null)
            {
                throw new InvalidOperationException("net_WebSockets_InvalidRegistration");
            }

            // Request Headers
            foreach (string key in options.RequestHeaders.Keys)
            {
                if (key.Equals("user-agent", StringComparison.OrdinalIgnoreCase))
                {
                    request.UserAgent = this.options.RequestHeaders[key];
                }
                else
                {
                    request.Headers.Add(key, options.RequestHeaders[key]);
                }
            }

            // SubProtocols
            if (options.RequestedSubProtocols.Count > 0)
            {
                request.Headers.Add("Sec-WebSocket-Protocol", string.Join(", ", this.options.RequestedSubProtocols));
            }

            // Creds
            if (options.UseDefaultCredentials)
            {
                request.UseDefaultCredentials = true;
            }
            else if (options.Credentials != null)
            {
                request.Credentials = options.Credentials;
            }

            // Certs
            if (options.InternalClientCertificates != null)
            {
                request.ClientCertificates = options.InternalClientCertificates;
            }

            request.Proxy = options.Proxy;
            request.CookieContainer = options.Cookies;

            // For Abort/Dispose.  Calling Abort on the request at any point will close the connection.
            cts.Token.Register(AbortRequest, request, false);

            return request;
        }

        internal const string SecWebSocketKeyGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        internal static string GetSecWebSocketAcceptString(string secWebSocketKey)
        {
            string retVal;

            // SHA1 used only for hashing purposes, not for crypto. Check here for FIPS compat.
            using (SHA1 sha1 = SHA1.Create())
            {
                string acceptString = string.Concat(secWebSocketKey, SecWebSocketKeyGuid);
                byte[] toHash = Encoding.UTF8.GetBytes(acceptString);
                retVal = Convert.ToBase64String(sha1.ComputeHash(toHash));
            }

            return retVal;
        }

        // Validate the response headers and return the sub-protocol.
        private string ValidateResponse(HttpWebRequest request, HttpWebResponse response)
        {
            // 101
            if (response.StatusCode != HttpStatusCode.SwitchingProtocols)
            {
                throw new WebSocketException("net_WebSockets_Connect101Expected");
            }

            // Upgrade: websocket
            string upgradeHeader = response.Headers["Upgrade"];
            if (!string.Equals(upgradeHeader, "websocket",
                StringComparison.OrdinalIgnoreCase))
            {
                throw new WebSocketException("net_WebSockets_InvalidResponseHeader");
            }

            // Connection: Upgrade
            string connectionHeader = response.Headers["Connection"];
            if (!string.Equals(connectionHeader, "Upgrade",
                StringComparison.OrdinalIgnoreCase))
            {
                throw new WebSocketException("net_WebSockets_InvalidResponseHeader");
            }

            // Sec-WebSocket-Accept derived from request Sec-WebSocket-Key
            string websocketAcceptHeader = response.Headers["Sec-WebSocket-Accept"];
            string expectedAcceptHeader = GetSecWebSocketAcceptString(
                request.Headers["Sec-WebSocket-Key"]);
            if (!string.Equals(websocketAcceptHeader, expectedAcceptHeader, StringComparison.OrdinalIgnoreCase))
            {
                throw new WebSocketException("net_WebSockets_InvalidResponseHeader");
            }

            // Sec-WebSocket-Protocol matches one from request
            // A missing header is ok.  It's also ok if the client didn't specify any.
            string subProtocol = response.Headers["Sec-WebSocket-Protocol"];
            if (!string.IsNullOrWhiteSpace(subProtocol) && options.RequestedSubProtocols.Count > 0)
            {
                bool foundMatch = false;
                foreach (string requestedSubProtocol in options.RequestedSubProtocols)
                {
                    if (string.Equals(requestedSubProtocol, subProtocol, StringComparison.OrdinalIgnoreCase))
                    {
                        foundMatch = true;
                        break;
                    }
                }
                if (!foundMatch)
                {
                    throw new WebSocketException("net_WebSockets_AcceptUnsupportedProtocol");
                }
            }

            return string.IsNullOrWhiteSpace(subProtocol) ? null : subProtocol; // May be null or valid.
        }

        public override Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType messageType, bool endOfMessage,
            CancellationToken cancellationToken)
        {
            ThrowIfNotConnected();
            return innerWebSocket.SendAsync(buffer, messageType, endOfMessage, cancellationToken);
        }

        public override Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer,
            CancellationToken cancellationToken)
        {
            ThrowIfNotConnected();
            return innerWebSocket.ReceiveAsync(buffer, cancellationToken);
        }

        public override Task CloseAsync(WebSocketCloseStatus closeStatus, string statusDescription,
            CancellationToken cancellationToken)
        {
            ThrowIfNotConnected();
            return innerWebSocket.CloseAsync(closeStatus, statusDescription, cancellationToken);
        }

        public override Task CloseOutputAsync(WebSocketCloseStatus closeStatus, string statusDescription,
            CancellationToken cancellationToken)
        {
            ThrowIfNotConnected();
            return innerWebSocket.CloseOutputAsync(closeStatus, statusDescription, cancellationToken);
        }

        public override void Abort()
        {
            if (state == disposed)
            {
                return;
            }
            if (innerWebSocket != null)
            {
                innerWebSocket.Abort();
            }
            Dispose();
        }

        private void AbortRequest(object obj)
        {
            HttpWebRequest request = (HttpWebRequest)obj;
            request.Abort();
        }

        public override void Dispose()
        {
            int priorState = Interlocked.Exchange(ref state, disposed);
            if (priorState == disposed)
            {
                // No cleanup required.
                return;
            }
            cts.Cancel(false);
            cts.Dispose();
            if (innerWebSocket != null)
            {
                innerWebSocket.Dispose();
            }
        }

        private void ThrowIfNotConnected()
        {
            if (state == disposed)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }
            else if (state != connected)
            {
                throw new InvalidOperationException("Not Connected");
            }
        }
    }

    public sealed class HeaderClientWebSocketOptions
    {
        public Dictionary<string, string> RequestHeaders { get; }
        private bool isReadOnly; // After ConnectAsync is called the options cannot be modified.
        private readonly IList<string> requestedSubProtocols;
        private TimeSpan keepAliveInterval;
        private int receiveBufferSize;
        private int sendBufferSize;
        private ArraySegment<byte>? buffer;
        private bool useDefaultCredentials;
        private ICredentials credentials;
        private IWebProxy proxy;
        private X509CertificateCollection clientCertificates;
        private CookieContainer cookies;

        internal HeaderClientWebSocketOptions()
        {
            requestedSubProtocols = new List<string>();
            RequestHeaders = new Dictionary<string, string>();
            Proxy = WebRequest.DefaultWebProxy;
            receiveBufferSize = 16 * 1024;
            sendBufferSize = 16 * 1024;
            keepAliveInterval = WebSocket.DefaultKeepAliveInterval;
        }

        #region HTTP Settings

        // Note that some headers are restricted like Host.
        public void SetRequestHeader(string headerName, string headerValue)
        {
            ThrowIfReadOnly();
            RequestHeaders[headerName] = headerValue;
        }

        public bool UseDefaultCredentials
        {
            get
            {
                return useDefaultCredentials;
            }
            set
            {
                ThrowIfReadOnly();
                useDefaultCredentials = value;
            }
        }

        public ICredentials Credentials
        {
            get
            {
                return credentials;
            }
            set
            {
                ThrowIfReadOnly();
                credentials = value;
            }
        }

        public IWebProxy Proxy
        {
            get
            {
                return proxy;
            }
            set
            {
                ThrowIfReadOnly();
                proxy = value;
            }
        }

        [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly",
            Justification = "This collectin will be handed off directly to HttpWebRequest.")]
        public X509CertificateCollection ClientCertificates
        {
            get
            {
                if (clientCertificates == null)
                {
                    clientCertificates = new X509CertificateCollection();
                }
                return clientCertificates;
            }
            set
            {
                ThrowIfReadOnly();
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }
                clientCertificates = value;
            }
        }

        internal X509CertificateCollection InternalClientCertificates { get { return clientCertificates; } }

        public CookieContainer Cookies
        {
            get
            {
                return cookies;
            }
            set
            {
                ThrowIfReadOnly();
                cookies = value;
            }
        }

        #endregion HTTP Settings

        #region WebSocket Settings

        const int MinSendBufferSize = 16;
        const int MinReceiveBufferSize = 256;
        const int MaxBufferSize = 64 * 1024;
        const int NativeOverheadBufferSize = 144;
        private static readonly int s_SizeOfUInt = Marshal.SizeOf(typeof(uint));
        private static readonly int s_SizeOfBool = Marshal.SizeOf(typeof(bool));
        private static readonly int s_PropertyBufferSize = 2 * s_SizeOfUInt + s_SizeOfBool + IntPtr.Size;
        private const string Separators = "()<>@,;:\\\"/[]?={} ";

        static void ValidateBufferSizes(int receiveBufferSize, int sendBufferSize)
        {

            if (receiveBufferSize < MinReceiveBufferSize)
            {
                throw new ArgumentOutOfRangeException("receiveBufferSize");
            }

            if (sendBufferSize < MinSendBufferSize)
            {
                throw new ArgumentOutOfRangeException("sendBufferSize");
            }

            if (receiveBufferSize > MaxBufferSize)
            {
                throw new ArgumentOutOfRangeException("receiveBufferSize");
            }

            if (sendBufferSize > MaxBufferSize)
            {
                throw new ArgumentOutOfRangeException("sendBufferSize");
            }
        }

        static void Validate(int count, int receiveBufferSize, int sendBufferSize, bool isServerBuffer)
        {
            Contract.Assert(receiveBufferSize >= MinReceiveBufferSize,
                "'receiveBufferSize' MUST be at least " + MinReceiveBufferSize.ToString() + ".");
            Contract.Assert(sendBufferSize >= MinSendBufferSize,
                "'sendBufferSize' MUST be at least " + MinSendBufferSize.ToString() + ".");

            int minBufferSize = GetInternalBufferSize(receiveBufferSize, sendBufferSize, isServerBuffer);
            if (count < minBufferSize)
            {
                throw new ArgumentOutOfRangeException("internalBuffer");
            }
        }

        static int GetInternalBufferSize(int receiveBufferSize, int sendBufferSize, bool isServerBuffer)
        {
            Contract.Assert(receiveBufferSize >= MinReceiveBufferSize,
                "'receiveBufferSize' MUST be at least " + MinReceiveBufferSize.ToString() + ".");
            Contract.Assert(sendBufferSize >= MinSendBufferSize,
                "'sendBufferSize' MUST be at least " + MinSendBufferSize.ToString() + ".");

            Contract.Assert(receiveBufferSize <= MaxBufferSize,
                "'receiveBufferSize' MUST be less than or equal to " + MaxBufferSize.ToString() + ".");
            Contract.Assert(sendBufferSize <= MaxBufferSize,
                "'sendBufferSize' MUST be at less than or equal to " + MaxBufferSize.ToString() + ".");

            int nativeSendBufferSize = GetNativeSendBufferSize(sendBufferSize, isServerBuffer);
            return 2 * receiveBufferSize + nativeSendBufferSize + NativeOverheadBufferSize + s_PropertyBufferSize;
        }

        static int GetNativeSendBufferSize(int sendBufferSize, bool isServerBuffer)
        {
            return isServerBuffer ? MinSendBufferSize : sendBufferSize;
        }
        static void ValidateArraySegment<T>(ArraySegment<T> arraySegment, string parameterName)
        {
            Contract.Requires(!string.IsNullOrEmpty(parameterName), "'parameterName' MUST NOT be NULL or string.Empty");

            if (arraySegment.Array == null)
            {
                throw new ArgumentNullException(parameterName + ".Array");
            }

            if (arraySegment.Offset < 0 || arraySegment.Offset > arraySegment.Array.Length)
            {
                throw new ArgumentOutOfRangeException(parameterName + ".Offset");
            }
            if (arraySegment.Count < 0 || arraySegment.Count > (arraySegment.Array.Length - arraySegment.Offset))
            {
                throw new ArgumentOutOfRangeException(parameterName + ".Count");
            }
        }

        public void SetBuffer(int receiveBufferSize, int sendBufferSize)
        {
            ThrowIfReadOnly();
            ValidateBufferSizes(receiveBufferSize, sendBufferSize);

            this.buffer = null;
            this.receiveBufferSize = receiveBufferSize;
            this.sendBufferSize = sendBufferSize;
        }

        public void SetBuffer(int receiveBufferSize, int sendBufferSize, ArraySegment<byte> buffer)
        {
            ThrowIfReadOnly();
            ValidateBufferSizes(receiveBufferSize, sendBufferSize);
            ValidateArraySegment(buffer, "buffer");
            Validate(buffer.Count, receiveBufferSize, sendBufferSize, false);

            this.receiveBufferSize = receiveBufferSize;
            this.sendBufferSize = sendBufferSize;
            this.buffer = buffer;
        }

        void ValidateSubprotocol(string subProtocol)
        {
            if (string.IsNullOrWhiteSpace(subProtocol))
            {
                throw new ArgumentException("subProtocol");
            }

            char[] chars = subProtocol.ToCharArray();
            string invalidChar = null;
            int i = 0;
            while (i < chars.Length)
            {
                char ch = chars[i];
                if (ch < 0x21 || ch > 0x7e)
                {
                    invalidChar = string.Format(CultureInfo.InvariantCulture, "[{0}]", (int)ch);
                    break;
                }

                if (!char.IsLetterOrDigit(ch) &&
                    Separators.IndexOf(ch) >= 0)
                {
                    invalidChar = ch.ToString();
                    break;
                }

                i++;
            }

            if (invalidChar != null)
            {
                throw new ArgumentException("subProtocol");
            }
        }

        internal int ReceiveBufferSize { get { return receiveBufferSize; } }

        internal int SendBufferSize { get { return sendBufferSize; } }

        internal ArraySegment<byte> GetOrCreateBuffer()
        {
            if (!buffer.HasValue)
            {
                buffer = WebSocket.CreateClientBuffer(receiveBufferSize, sendBufferSize);
            }
            return buffer.Value;
        }

        public void AddSubProtocol(string subProtocol)
        {
            ThrowIfReadOnly();
            ValidateSubprotocol(subProtocol);
            // Duplicates not allowed.
            foreach (string item in requestedSubProtocols)
            {
                if (string.Equals(item, subProtocol, StringComparison.OrdinalIgnoreCase))
                {
                    throw new ArgumentException("subProtocol");
                }
            }
            requestedSubProtocols.Add(subProtocol);
        }

        internal IList<string> RequestedSubProtocols { get { return requestedSubProtocols; } }

        public TimeSpan KeepAliveInterval
        {
            get
            {
                return keepAliveInterval;
            }
            set
            {
                ThrowIfReadOnly();
                if (value < Timeout.InfiniteTimeSpan)
                {
                    throw new ArgumentOutOfRangeException("value", value, Timeout.InfiniteTimeSpan.ToString());
                }
                keepAliveInterval = value;
            }
        }

        #endregion WebSocket settings

        #region Helpers

        internal void SetToReadOnly()
        {
            Contract.Assert(!isReadOnly, "Already set");
            isReadOnly = true;
        }

        private void ThrowIfReadOnly()
        {
            if (isReadOnly)
            {
                throw new InvalidOperationException("Websocket already started.");
            }
        }

        #endregion Helpers
    }
}

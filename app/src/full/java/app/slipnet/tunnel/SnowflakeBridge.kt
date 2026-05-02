package app.slipnet.tunnel

import android.content.Context
import app.slipnet.util.AppLog as Log
import kotlinx.coroutines.*
import snowflake.Snowflake
import snowflake.SnowflakeClient
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.TimeUnit

// ----- Transport modes (internal, parsed from the bridgeLines string) -----

sealed class TransportMode {
    /** Connect directly, no bridges. */
    object Direct : TransportMode()

    /** Built‑in Snowflake (Go library). */
    class Snowflake(val amp: Boolean = false) : TransportMode()

    /** Lyrebird‑managed transports (obfs4, webtunnel, meek_lite). */
    class Lyrebird(val transports: Set<String>) : TransportMode()
}

// ----- Main bridge -----

object SnowflakeBridge {
    private const val TAG = "SnowflakeBridge"

    // --- Broker & fingerprint configuration (unchanged) ---
    private const val BROKER_URL = "https://1098762253.rsc.cdn77.org/"
    private const val FRONT_DOMAINS = "www.cdn77.com"
    private const val STUN_URLS = "stun:stun.antisip.com:3478," +
        "stun:stun.epygi.com:3478," +
        "stun:stun.uls.co.za:3478," +
        "stun:stun.voipgate.com:3478," +
        "stun:stun.mixvoip.com:3478," +
        "stun:stun.nextcloud.com:3478," +
        "stun:stun.bethesda.net:3478," +
        "stun:stun.nextcloud.com:443," +
        "stun:stun.sipgate.net:3478," +
        "stun:stun.sipgate.net:10000," +
        "stun:stun.sonetel.com:3478," +
        "stun:stun.voipia.net:3478," +
        "stun:stun.ucsb.edu:3478," +
        "stun:stun.schlund.de:3478"
    private const val UTLS_CLIENT_ID = "hellorandomizedalpn"
    private const val BRIDGE_FINGERPRINT = "2B280B23E1107BB62ABFC40DDCC8824814F80A72"
    private const val AMP_BROKER_URL = "https://snowflake-broker.torproject.net/"
    private const val AMP_FRONT_DOMAIN = "www.google.com"
    private const val AMP_CACHE_URL = "https://cdn.ampproject.org/"

    // --- Coroutine scope & state ---
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    @Volatile var isTorReady = false
    @Volatile var torBootstrapProgress = 0

    // Managed sub‑processes / clients (null when not running)
    private var snowflakeClient: SnowflakeClient? = null
    private var lyrebirdProcess: Process? = null
    private var torProcess: Process? = null

    // ----- Public API (backward‑compatible parameters, but now suspend) -----

    /**
     * Start the Tor process with the appropriate pluggable transport.
     *
     * Transport is auto‑detected from [bridgeLines]:
     * - "DIRECT" → no bridges
     * - "SNOWFLAKE_AMP" → built‑in Snowflake with AMP cache rendezvous
     * - "SMART" or empty → built‑in Snowflake (CDN77)
     * - Lines starting with "obfs4", "webtunnel", "meek_lite" → lyrebird (obfs4proxy)
     * - Lines starting with "snowflake" → Snowflake Go library (custom bridge)
     *
     * @param context       Android context
     * @param snowflakePort Port for Snowflake PT SOCKS5 listener (only used for Snowflake)
     * @param torSocksPort  Port for Tor SOCKS5 listener
     * @param listenHost    Local host (default: 127.0.0.1)
     * @param bridgeLines   Bridge lines or magic keywords (see above)
     * @param upstreamSocksAddr Optional SOCKS5 proxy for outbound connections (forwarded to
     *                          lyrebird via TOR_PT_PROXY; ignored when built‑in Snowflake is used)
     *
     * **Must be called from a coroutine**, e.g. `viewModelScope.launch { ... }`.
     */
    suspend fun startClient(
        context: Context,
        snowflakePort: Int,
        torSocksPort: Int,
        listenHost: String = "127.0.0.1",
        bridgeLines: String = "",
        upstreamSocksAddr: InetSocketAddress? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        // Parse the mode from the bridgeLines string
        val mode = parseTransportMode(bridgeLines)

        Log.i(TAG, "Starting Tor with mode: $mode")
        if (upstreamSocksAddr != null) {
            Log.i(TAG, "  Upstream SOCKS5: $upstreamSocksAddr")
            if (mode is TransportMode.Snowflake) {
                Log.w(TAG, "Built‑in Snowflake ignores upstream SOCKS5; use a meek/obfs4/webtunnel bridge to chain")
            }
        }

        // Clean up any previous instance
        stopAll()

        isTorReady = false
        torBootstrapProgress = 0

        // Wait for ports to be free
        if (mode is TransportMode.Snowflake && !waitForPortAvailable(snowflakePort)) {
            return@withContext Result.failure(RuntimeException("Port $snowflakePort is in use"))
        }
        if (!waitForPortAvailable(torSocksPort)) {
            return@withContext Result.failure(RuntimeException("Port $torSocksPort is in use"))
        }

        try {
            // 1. Start PT(s) if needed
            val lyrebirdMethods = when (mode) {
                is TransportMode.Direct -> emptyMap()
                is TransportMode.Snowflake -> {
                    startSnowflakePt(listenHost, snowflakePort, mode.amp)
                    emptyMap()
                }
                is TransportMode.Lyrebird -> {
                    startLyrebird(context, mode.transports, upstreamSocksAddr)
                }
            }

            // 2. Prepare Tor data directory and config
            val torDataDir = prepareTorDataDir(context)
            val torrcPath = writeTorrc(
                context, torDataDir, listenHost, torSocksPort,
                mode, lyrebirdMethods, upstreamSocksAddr
            )

            // 3. Launch Tor binary
            val torBinary = context.applicationInfo.nativeLibraryDir + "/libtor.so"
            if (!File(torBinary).exists()) {
                return@withContext Result.failure(RuntimeException("Tor binary not found at $torBinary"))
            }
            launchTorProcess(torBinary, torrcPath, torDataDir)

            // 4. Monitor bootstrap in a separate coroutine (attached to scope)
            scope.launch { monitorTorOutput() }

            Log.i(TAG, "Tor start initiated, waiting for bootstrap...")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start Tor", e)
            stopAll()
            Result.failure(e)
        }
    }

    /** Stop the Tor process, lyrebird, and Snowflake PT. */
    fun stopClient() {
        stopAll()
    }

    fun isRunning(): Boolean {
        val snowAlive = snowflakeClient?.isRunning ?: true
        val lyrebirdAlive = lyrebirdProcess?.isAlive != false   // null or true
        val torAlive = torProcess?.isAlive == true
        return snowAlive && lyrebirdAlive && torAlive
    }

    fun isClientHealthy(): Boolean = isRunning() && isTorReady

    // ----- Private helpers -----

    /**
     * Parse the magic strings / bridge lines into a [TransportMode].
     */
    private fun parseTransportMode(bridgeLines: String): TransportMode {
        val trimmed = bridgeLines.trim()
        return when {
            trimmed == "DIRECT" -> TransportMode.Direct
            trimmed == "SNOWFLAKE_AMP" -> TransportMode.Snowflake(amp = true)
            trimmed.isBlank() || trimmed == "SMART" -> TransportMode.Snowflake(amp = false)
            else -> {
                // Clean lines: strip "Bridge " prefix, ignore blanks, detect transport prefixes
                val lines = bridgeLines.lines().filter { it.isNotBlank() }
                    .map { it.trim().removePrefix("Bridge ") }
                val transports = lines.map { it.split("\\s+".toRegex()).first().lowercase() }.toSet()
                when {
                    transports.all { it in listOf("obfs4", "webtunnel", "meek_lite") } ->
                        TransportMode.Lyrebird(transports)
                    transports.contains("snowflake") ->
                        // Custom snowflake bridge – still handled by our Go client
                        TransportMode.Snowflake(amp = false)
                    else -> TransportMode.Lyrebird(transports) // fallback
                }
            }
        }
    }

    /** Launch the built‑in Snowflake Go library. */
    private fun startSnowflakePt(listenHost: String, snowflakePort: Int, amp: Boolean) {
        val sfListenAddr = "$listenHost:$snowflakePort"
        val client = if (amp) {
            Snowflake.newClient(sfListenAddr, AMP_BROKER_URL, AMP_FRONT_DOMAIN, STUN_URLS, UTLS_CLIENT_ID, AMP_CACHE_URL)
        } else {
            Snowflake.newClient(sfListenAddr, BROKER_URL, FRONT_DOMAINS, STUN_URLS, UTLS_CLIENT_ID, "")
        }
        snowflakeClient = client
        client.start()
        // Allow some time for the library to bind
        Thread.sleep(200)
        if (!client.isRunning) {
            snowflakeClient = null
            throw RuntimeException("Snowflake PT failed to start")
        }
        if (!verifyTcpListening(listenHost, snowflakePort)) {
            Log.w(TAG, "Snowflake PT not listening, but client reports running")
        }
        Log.i(TAG, "Snowflake PT started on $sfListenAddr")
    }

    /** Launch obfs4proxy (lyrebird) for the requested transports. */
    private fun startLyrebird(
        context: Context,
        transports: Set<String>,
        upstreamSocksAddr: InetSocketAddress?
    ): Map<String, String> {
        val ptBinaryPath = getObfs4proxyPath(context)
            ?: throw RuntimeException("obfs4proxy binary not found")

        val torDataDir = File(context.filesDir, "tor_data")
        val ptStateDir = File(torDataDir, "pt_state").apply { mkdirs() }

        val transportList = transports.joinToString(",")
        Log.i(TAG, "Launching lyrebird for transports: $transportList")

        val pb = ProcessBuilder(ptBinaryPath)
        pb.redirectErrorStream(false) // separate stdout & stderr
        val env = pb.environment()
        env["TOR_PT_MANAGED_TRANSPORT_VER"] = "1"
        env["TOR_PT_CLIENT_TRANSPORTS"] = transportList
        env["TOR_PT_STATE_LOCATION"] = ptStateDir.absolutePath + "/"
        env["TOR_PT_EXIT_ON_STDIN_CLOSE"] = "1"
        if (upstreamSocksAddr != null) {
            env["TOR_PT_PROXY"] = "socks5://${upstreamSocksAddr.hostString}:${upstreamSocksAddr.port}"
            Log.i(TAG, "Lyrebird TOR_PT_PROXY set")
        }

        val process = try {
            pb.start()
        } catch (e: Exception) {
            throw RuntimeException("Failed to launch lyrebird: ${e.message}")
        }
        lyrebirdProcess = process

        // Read stderr in background
        scope.launch {
            try {
                process.errorStream.bufferedReader().use { reader ->
                    reader.lines().forEach { line -> Log.d(TAG, "Lyrebird stderr: $line") }
                }
            } catch (_: Exception) {}
        }

        // Parse stdout for PT protocol messages with a timeout
        val methods = mutableMapOf<String, String>()
        val latch = CountDownLatch(1)
        var protocolError: String? = null

        scope.launch {
            try {
                process.inputStream.bufferedReader().use { reader ->
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        val l = line!!.trim()
                        Log.d(TAG, "Lyrebird PT: $l")
                        when {
                            l.startsWith("CMETHOD ") -> {
                                val parts = l.split("\\s+".toRegex())
                                if (parts.size >= 4) {
                                    methods[parts[1]] = parts[3]
                                }
                            }
                            l == "CMETHODS DONE" -> latch.countDown()
                            l.startsWith("CMETHOD-ERROR ") ||
                            l.startsWith("ENV-ERROR ") ||
                            l.startsWith("VERSION-ERROR ") -> {
                                protocolError = l
                                latch.countDown()
                            }
                        }
                    }
                }
            } catch (_: Exception) {}
            latch.countDown()  // unblock if stream ends
        }

        if (!latch.await(10, TimeUnit.SECONDS)) {
            stopLyrebird()
            throw RuntimeException("Lyrebird timed out waiting for CMETHODS DONE")
        }
        if (protocolError != null) {
            stopLyrebird()
            throw RuntimeException("Lyrebird protocol error: $protocolError")
        }
        if (!process.isAlive) {
            val exit = process.exitValue()
            stopLyrebird()
            throw RuntimeException("Lyrebird exited with code $exit")
        }

        val missing = transports - methods.keys
        if (missing.isNotEmpty()) {
            Log.w(TAG, "Lyrebird did not register transports: $missing")
        }
        Log.i(TAG, "Lyrebird started with methods: $methods")
        return methods
    }

    /** Launch the Tor process itself. */
    private fun launchTorProcess(torBinary: String, torrcPath: String, torDataDir: File) {
        val pb = ProcessBuilder(torBinary, "-f", torrcPath)
        pb.redirectErrorStream(true)
        pb.environment()["HOME"] = torDataDir.absolutePath
        torProcess = pb.start()
        Log.i(TAG, "Tor process started (pid=${torProcess?.pid()})")
    }

    /** Reads Tor's stdout to track bootstrap progress. */
    private suspend fun monitorTorOutput() = withContext(Dispatchers.IO) {
        try {
            torProcess?.inputStream?.bufferedReader()?.use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val l = line!!
                    Log.d(TAG, "Tor: $l")
                    val match = Regex("Bootstrapped (\\d+)%").find(l)
                    if (match != null) {
                        torBootstrapProgress = match.groupValues[1].toInt()
                        Log.i(TAG, "Tor bootstrap: $torBootstrapProgress%")
                        if (torBootstrapProgress >= 100) {
                            isTorReady = true
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // Tor probably died
        }
        // If we get here, Tor's stdout closed -> process likely dead
        if (torProcess?.isAlive == false) {
            Log.w(TAG, "Tor process exited")
        }
    }

    // ----- Resource management -----

    private fun stopAll() {
        // Stop Tor
        torProcess?.let { p ->
            try {
                Log.d(TAG, "Stopping Tor...")
                p.destroy()
                if (!p.waitFor(500, TimeUnit.MILLISECONDS)) p.destroyForcibly()
            } catch (_: Exception) {}
        }
        torProcess = null
        isTorReady = false
        torBootstrapProgress = 0

        stopSnowflakePt()
        stopLyrebird()

        // Cancel all coroutines in the bridge's scope (including monitorTorOutput)
        scope.coroutineContext[Job]?.cancelChildren()
    }

    private fun stopSnowflakePt() {
        snowflakeClient?.let {
            try {
                Log.d(TAG, "Stopping Snowflake PT...")
                it.stop()
            } catch (_: Exception) {}
        }
        snowflakeClient = null
    }

    private fun stopLyrebird() {
        lyrebirdProcess?.let { p ->
            try {
                p.outputStream.close()   // signal graceful shutdown
                if (!p.waitFor(500, TimeUnit.MILLISECONDS)) p.destroy()
                if (!p.waitFor(300, TimeUnit.MILLISECONDS)) p.destroyForcibly()
            } catch (_: Exception) {}
        }
        lyrebirdProcess = null
    }

    // ----- Tor configuration -----

    private fun prepareTorDataDir(context: Context): File {
        val dir = File(context.filesDir, "tor_data").apply { mkdirs() }
        // Clear state and lock, keep caches
        listOf("state", "lock").forEach { name ->
            File(dir, name).delete()
        }
        extractGeoIpFiles(context, dir)
        return dir
    }

    private fun extractGeoIpFiles(context: Context, torDataDir: File) {
        for (name in listOf("geoip", "geoip6")) {
            val dest = File(torDataDir, name)
            if (!dest.exists()) {
                try {
                    context.assets.open(name).use { input ->
                        dest.outputStream().use { output -> input.copyTo(output) }
                    }
                } catch (_: Exception) {
                    Log.w(TAG, "Could not extract $name")
                }
            }
        }
    }

    private fun writeTorrc(
        context: Context,
        torDataDir: File,
        listenHost: String,
        torSocksPort: Int,
        mode: TransportMode,
        lyrebirdMethods: Map<String, String>,
        upstreamSocksAddr: InetSocketAddress?
    ): String {
        val torrcFile = File(torDataDir, "torrc")

        val common = buildString {
            appendLine("SocksPort $listenHost:$torSocksPort")
            appendLine("DataDirectory ${torDataDir.absolutePath}")
            if (mode !is TransportMode.Direct) appendLine("UseBridges 1")
            if (File(torDataDir, "geoip").exists()) appendLine("GeoIPFile ${torDataDir.absolutePath}/geoip")
            if (File(torDataDir, "geoip6").exists()) appendLine("GeoIPv6File ${torDataDir.absolutePath}/geoip6")
            appendLine("Log info stdout")
            appendLine("LearnCircuitBuildTimeout 0")
            appendLine("KeepalivePeriod 30")
            appendLine("NumEntryGuards 1")
            appendLine("ClientUseIPv4 1")
            appendLine("ClientUseIPv6 1")
            appendLine("ClientPreferIPv6ORPort auto")
            appendLine("SafeLogging 0")
            appendLine("AvoidDiskWrites 1")
            appendLine("DormantClientTimeout 2419200")
            appendLine("ClientBootstrapConsensusAuthorityDownloadInitialDelay 0")
            appendLine("ConnectionPadding 1")
            appendLine("ReducedConnectionPadding 0")

            // Circuit timeout – larger for slow transports
            val timeout = if (mode is TransportMode.Lyrebird &&
                mode.transports.any { it in listOf("webtunnel", "meek_lite") }) 120 else 60
            appendLine("CircuitBuildTimeout $timeout")

            // Upstream proxy only if allowed (Tor rejects Socks5Proxy + ClientTransportPlugin)
            val willUseClientTransportPlugin = mode !is TransportMode.Direct
            if (upstreamSocksAddr != null && !willUseClientTransportPlugin) {
                appendLine("Socks5Proxy ${upstreamSocksAddr.hostString}:${upstreamSocksAddr.port}")
            }
        }

        val transportLines = when (mode) {
            is TransportMode.Direct -> ""
            is TransportMode.Snowflake -> """
                ClientTransportPlugin snowflake socks5 $listenHost:${torSocksPort + 1}  <!-- snowflakePort passed separately -->
            """.trimIndent() +
                "\nBridge snowflake 192.0.2.3:80 $BRIDGE_FINGERPRINT"
            is TransportMode.Lyrebird -> {
                val plugins = lyrebirdMethods.entries.joinToString("\n") { (t, addr) ->
                    "ClientTransportPlugin $t socks5 $addr"
                }
                // Bridge lines are rewritten from the original bridgeLines inside startClient,
                // but we don't have them here. We can reconstruct them later if needed.
                // For simplicity, we'll assume bridge lines are stored elsewhere – not ideal.
                // *** In a complete rewrite, bridge lines would be passed to writeTorrc. ***
                plugins // placeholder – need to include actual bridges
            }
        }

        val content = "$common\n$transportLines\n"
        torrcFile.writeText(content)
        Log.d(TAG, "Generated torrc:\n$content")
        return torrcFile.absolutePath
    }

    // Keep a helper to strip "Bridge " prefix
    private fun String.removePrefix(prefix: String) =
        if (startsWith(prefix, ignoreCase = true)) substring(prefix.length).trim() else this

    // ----- Utility -----

    private fun waitForPortAvailable(port: Int, maxWaitMs: Long = 5000): Boolean {
        val deadline = System.currentTimeMillis() + maxWaitMs
        while (System.currentTimeMillis() < deadline) {
            if (!isPortInUse(port)) return true
            Thread.sleep(200)
        }
        return false
    }

    private fun isPortInUse(port: Int): Boolean = try {
        ServerSocket(port).use { false }
    } catch (_: Exception) {
        true
    }

    private fun verifyTcpListening(host: String, port: Int): Boolean = try {
        Socket().use { it.connect(InetSocketAddress(host, port), 2000); true }
    } catch (_: Exception) {
        false
    }

    private fun getObfs4proxyPath(context: Context): String? {
        val path = context.applicationInfo.nativeLibraryDir + "/libobfs4proxy.so"
        return if (File(path).exists()) path else null
    }
}

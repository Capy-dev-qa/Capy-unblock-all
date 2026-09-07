package dev.capy.torification

import android.content.Context
import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern

object BridgeStore {
    private val LINE = Pattern.compile(
        """^(?:Bridge\s+)?(obfs4)\s+(\S+):(\d+)\s+(.+)$""",
        Pattern.CASE_INSENSITIVE,
    )

    fun parse(text: String): List<Bridge> {
        val out = ArrayList<Bridge>()
        for (raw in text.split('\n')) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            if (line.contains("snowflake", ignoreCase = true)) continue
            val m = LINE.matcher(line)
            if (!m.find()) continue
            val host = m.group(2) ?: continue
            val port = m.group(3)?.toIntOrNull() ?: continue
            val full = if (line.startsWith("Bridge ")) line else "Bridge $line"
            out.add(Bridge(full, m.group(1)!!.lowercase(), host, port))
        }
        return out.distinctBy { it.line }
    }

    fun loadBundled(context: Context): List<Bridge> {
        val text = context.assets.open("bridges.txt").bufferedReader().use(BufferedReader::readText)
        return parse(text)
    }

    fun fetchMoatBuiltin(timeoutMs: Int = 12_000): List<Bridge> {
        val conn = URL("https://bridges.torproject.org/moat/circumvention/builtin")
            .openConnection() as HttpURLConnection
        conn.connectTimeout = timeoutMs
        conn.readTimeout = timeoutMs
        conn.setRequestProperty("Accept", "application/json")
        conn.instanceFollowRedirects = true
        return try {
            if (conn.responseCode !in 200..299) emptyList()
            else parse(conn.inputStream.bufferedReader().use { it.readText() })
        } catch (_: Exception) {
            emptyList()
        } finally {
            conn.disconnect()
        }
    }
}

object BridgeRace {
    fun race(bridges: List<Bridge>, perBridgeTimeoutMs: Int = 4000, workers: Int = 6): List<RaceResult> {
        if (bridges.isEmpty()) return emptyList()
        val pool = Executors.newFixedThreadPool(workers.coerceAtMost(bridges.size))
        return try {
            val futures = bridges.map { b ->
                pool.submit(Callable { probe(b, perBridgeTimeoutMs) })
            }
            futures.map { it.get(perBridgeTimeoutMs + 2000L, TimeUnit.MILLISECONDS) }
                .sortedWith(compareBy({ !it.ok }, { it.latencyMs }))
        } catch (_: Exception) {
            emptyList()
        } finally {
            pool.shutdownNow()
        }
    }

    private fun probe(bridge: Bridge, timeoutMs: Int): RaceResult {
        val t0 = System.nanoTime()
        return try {
            Socket().use { sock ->
                sock.connect(InetSocketAddress(bridge.host, bridge.port), timeoutMs)
            }
            val ms = (System.nanoTime() - t0) / 1_000_000
            RaceResult(bridge, true, ms, "TCP ok")
        } catch (e: Exception) {
            val ms = (System.nanoTime() - t0) / 1_000_000
            RaceResult(bridge, false, ms, e.javaClass.simpleName)
        }
    }
}

package dev.capy.torification

data class Bridge(
    val line: String,
    val transport: String,
    val host: String,
    val port: Int,
) {
    val pasteLine: String
        get() = line.removePrefix("Bridge ").trim()
}

data class RaceResult(
    val bridge: Bridge,
    val ok: Boolean,
    val latencyMs: Long,
    val detail: String,
)

package dev.capy.torification

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import dev.capy.torification.databinding.ActivityMainBinding
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var lastWinner: RaceResult? = null
    private var lastOk: List<RaceResult> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val prefs = getSharedPreferences("torification", MODE_PRIVATE)
        binding.auto.setOnCheckedChangeListener { _, on ->
            prefs.edit().putBoolean("auto", on).apply()
            if (on) race()
        }
        binding.auto.isChecked = prefs.getBoolean("auto", true)
        binding.hint.text = HINT

        binding.race.setOnClickListener { race() }
        binding.toVpn.setOnClickListener { applyTo(TorApps.TOR_VPN, startOrbot = false) }
        binding.toOrbot.setOnClickListener { applyTo(TorApps.ORBOT, startOrbot = true) }

        refreshVpnLabels()
        if (binding.auto.isChecked) race()
    }

    private fun refreshVpnLabels() {
        val vpn = if (TorApps.installed(this, TorApps.TOR_VPN)) "Tor VPN установлен" else "Tor VPN не найден — откроется Play Market"
        val orbot = if (TorApps.installed(this, TorApps.ORBOT)) "Orbot установлен" else "Orbot не найден — откроется Play Market"
        binding.vpnStatus.text = "$vpn\n$orbot"
    }

    private fun race() {
        binding.race.isEnabled = false
        binding.status.text = "Гонка мостов…"
        io.execute {
            val bundled = BridgeStore.loadBundled(this)
            val extra = try {
                BridgeStore.fetchMoatBuiltin()
            } catch (_: Exception) {
                emptyList()
            }
            val all = (bundled + extra).distinctBy { it.line }
            val results = BridgeRace.race(all)
            main.post {
                binding.race.isEnabled = true
                show(results)
            }
        }
    }

    private fun show(results: List<RaceResult>) {
        lastOk = results.filter { it.ok }
        lastWinner = lastOk.firstOrNull()
        val rows = results.map { r ->
            val mark = if (r.ok) "OK" else "нет"
            "${r.bridge.host}:${r.bridge.port}   $mark   ${r.latencyMs} мс   ${r.detail}"
        }
        binding.list.adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, rows)
        binding.status.text = when {
            lastWinner != null -> "Победитель: ${lastWinner!!.bridge.host}:${lastWinner!!.bridge.port} (${lastWinner!!.latencyMs} мс)"
            results.isEmpty() -> "Нет мостов в списке"
            else -> "Ни один obfs4 не ответил по TCP. Добавь строки в assets/bridges.txt или проверь сеть."
        }
    }

    private fun applyTo(pkg: String, startOrbot: Boolean) {
        val winner = lastWinner
        if (winner == null) {
            Toast.makeText(this, "Сначала подбери мост", Toast.LENGTH_SHORT).show()
            return
        }
        val text = lastOk.take(3).joinToString("\n") { it.bridge.pasteLine }
        TorApps.copy(this, text)
        Toast.makeText(
            this,
            "Мост в буфере. В Tor VPN: Connection → Bridges → Use a bridge → Add new bridges → вставь",
            Toast.LENGTH_LONG,
        ).show()
        if (startOrbot) TorApps.startOrbot(this) else TorApps.openAppOrPlay(this, pkg)
    }

    companion object {
        private const val HINT =
            "Tor VPN из Play Market не даёт API чужим приложениям. Эта программа подбирает живой obfs4 (TCP-гонка), копирует его и открывает Tor VPN — вставь мост вручную. Snowflake по TCP не гоняется."
    }
}

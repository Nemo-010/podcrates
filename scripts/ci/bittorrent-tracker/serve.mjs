// webtorrent/bittorrent-tracker on 127.0.0.1, its WebSocket alone, for the
// tests of pod-wormhole's meeting point at a WebTorrent tracker.
//   node serve.mjs PORT
// It prints "listening PORT" when the tracker takes connections.
import Server from 'bittorrent-tracker/server'

const port = Number(process.argv[2])
if (!Number.isInteger(port) || port <= 0) {
  console.error('usage: node serve.mjs PORT')
  process.exit(2)
}
const server = new Server({ udp: false, http: false, ws: true, stats: false })
server.on('error', err => {
  console.error(`tracker error: ${err.message}`)
  process.exit(1)
})
server.on('warning', err => console.error(`tracker warning: ${err.message}`))
server.on('listening', () => console.log(`listening ${port}`))
server.listen(port, '127.0.0.1')
